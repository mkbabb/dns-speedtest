import time
from datetime import datetime
from typing import override

import ipinfo
import ipinfo.details
from dnslib import NS, QTYPE, RR, SOA, TXT, A, DNSHeader, DNSRecord
from dnslib.server import BaseResolver
from loguru import logger
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from src.constants import (
    DEFAULT_ADDRESS,
    DEFAULT_PORT,
    DOMAIN_NAME,
    EXPIRE_TIME,
    MAX_TXT_CHUNK_SIZE,
    MINIMUM_TIME,
    RECORD_SIZE,
    REFRESH_TIME,
    RETRY_TIME,
    SERIAL_NUMBER,
    TTL,
)
from src.models import DNSUrlsTable, IPInfoTable, RequestsTable, SpeedtestResultsTable
from src.server.dns import BaseResolver, DNSHandler, DNSServer
from src.utils import ChunkCache, DNSUrl, calc_speed


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

    def __getitem__(self, item):
        return DomainName(item + '.' + self)


D = DomainName(DOMAIN_NAME)
IP = DEFAULT_ADDRESS

soa_record = SOA(
    mname=D["ns-1"],  # primary name server
    rname=D.admin,  # email of the domain administrator
    times=(
        SERIAL_NUMBER,
        REFRESH_TIME,
        RETRY_TIME,
        EXPIRE_TIME,
        MINIMUM_TIME,
    ),
)

ns_records = [NS(D["ns-1"])]

records = {
    D: [A(IP), soa_record] + ns_records,
    D["ns-1"]: [A(IP)],
    D.admin: [A(IP)],
}


class SpeedtestDNSHandler(DNSHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.dns_record: DNSRecord = None

        self.dns_record_id: int = None

        self.dns_url: DNSUrl = None

        self.start_time: datetime = None

    @override
    def handle(self):
        logger.info(f"Handling DNS request from {self.client_address}")

        self.start_time = datetime.now()

        return super().handle()

    @override
    def get_reply(self, data: bytes):
        logger.info(f"Received DNS request from {self.client_address}")

        self.dns_record = DNSRecord.parse(data)

        qname = self.dns_record.q.qname
        qtype = QTYPE[self.dns_record.q.qtype]

        url = str(qname).rstrip('.')
        ip = self.client_address[0]

        self.dns_url = DNSUrl.from_url(url)

        # TODO! hack to get the engine
        with Session(self.server.engine) as session:
            dns_url_table_obj = DNSUrlsTable(
                byte_len=self.dns_url.byte_len,
                uid=self.dns_url.uid,
                domain=self.dns_url.domain,
            )

            request_table_obj = RequestsTable(
                protocol=self.protocol,
                qtype=qtype,
                start_time=self.start_time,
                ip=ip,
                dns_url=dns_url_table_obj,
            )

            session.add(request_table_obj)

            session.commit()

            self.request_id = request_table_obj.id

            logger.info(
                f"Logged DNS request: {qtype} from {ip} for {self.dns_url.domain}"
            )

            try:
                details: ipinfo.details.Details = self.server.ipinfo_handler.getDetails(
                    ip
                )
                details = details.all

                if details.get("bogon"):
                    raise Exception("Bogon IP address")

                ipinfo_table_obj = IPInfoTable(
                    ip_address=details["ip"],
                    location=details["loc"],
                    org=details["org"],
                    postal=details["postal"],
                    city=details["city"],
                    region=details["region"],
                    country=details["country"],
                )
                request_table_obj.ipinfo = ipinfo_table_obj

                session.commit()
            except Exception as e:
                logger.error(f"Error getting IP info: {e}")

        return super().get_reply(data)

    @override
    def on_send(self, data: bytes, delta: float):
        qtype = QTYPE[self.dns_record.q.qtype]

        end_time = datetime.now()

        with Session(self.server.engine) as session:
            request_table_obj = session.get(RequestsTable, self.request_id)
            request_table_obj.end_time = end_time

            session.commit()

        if qtype == 'TXT' or qtype == 'A':
            self.log_txt_or_a_query(
                data=data,
                delta=delta,
            )

    def log_txt_or_a_query(
        self,
        data: bytes,
        delta: float,
    ):
        with Session(self.server.engine) as session:
            dl_speed = calc_speed(
                delta=delta,
                byte_len=len(data),
            )
            speedtest_result = SpeedtestResultsTable(
                request_id=self.request_id,
                delta=delta,
                dl_speed=dl_speed,
            )

            session.add(speedtest_result)
            session.commit()

        logger.info(f"Logged Speed Test result for request {self.request_id}")


class SpeedTestResolver(BaseResolver):
    def __init__(self, chunk_cache: ChunkCache):
        self.chunk_cache = chunk_cache

    @override
    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord:
        qname = request.q.qname
        qtype = request.q.qtype
        qt = QTYPE[qtype]

        logger.info(f"Resolving query for {qname} with type {qt}")

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if qt in ['NS', 'SOA', 'A', 'TXT']:
            logger.info(f"***Resolving query for {qname} with type {qt}")

            reply = self.handle_standard_query(reply, qname, qt)
            if qt == 'TXT' or qt == 'A':
                reply = self.handle_txt_query(reply, qname, handler)

            return reply
        else:
            return self.handle_unsupported_query(reply, qt)

    def handle_standard_query(self, reply: DNSRecord, qname, qt):
        qn = str(qname)

        if qn == D or qn.endswith('.' + D):
            for name, rrs in records.items():
                if name == qn:
                    for rdata in rrs:
                        rqt = rdata.__class__.__name__
                        if qt in ['*', rqt]:
                            reply.add_answer(
                                RR(
                                    rname=qname,
                                    rtype=getattr(QTYPE, rqt),
                                    rclass=1,
                                    ttl=TTL,
                                    rdata=rdata,
                                )
                            )

            for rdata in ns_records:
                reply.add_ar(
                    RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata)
                )

            reply.add_auth(
                RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record)
            )

        logger.info(f"Resolved standard query for {qname} with type {qt}")
        return reply

    def handle_txt_query(self, reply: DNSRecord, qname, handler: DNSHandler):
        dns_url = handler.dns_url
        byte_len = dns_url.byte_len

        num_chunks = byte_len // MAX_TXT_CHUNK_SIZE
        chunks = self.chunk_cache.get_random_chunks(num_chunks)

        remaining_bytes = byte_len

        for chunk in chunks:
            if remaining_bytes < MAX_TXT_CHUNK_SIZE:
                chunk = chunk[:remaining_bytes]

            remaining_bytes -= len(chunk)

            reply.add_answer(
                RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=0, rdata=TXT(chunk))
            )

        logger.info(f"Resolved TXT query for {qname} with {byte_len} bytes")

        return reply

    def handle_unsupported_query(self, reply: DNSRecord, qt):
        reply.header.rcode = 3

        logger.warning(f"Unsupported query type: {qt}")

        return reply


class SpeedtestDNSServer(DNSServer):
    def __init__(
        self,
        engine: Engine,
        ipinfo_handler: ipinfo.handler.Handler,
        cache_size: int,
        address: str = "",
        port: int = DEFAULT_PORT,
        tcp: bool = False,
    ):
        chunk_cache = ChunkCache(
            cache_size=cache_size,
            chunk_size=MAX_TXT_CHUNK_SIZE,
        )

        resolver = SpeedTestResolver(
            chunk_cache=chunk_cache,
        )

        super().__init__(
            resolver=resolver,
            address=address,
            port=port,
            tcp=tcp,
            handler=SpeedtestDNSHandler,
        )

        self.engine = engine
        self.server.engine = engine
        self.server.ipinfo_handler = ipinfo_handler


def run_server(
    port: int,
    cache_size: int,
    engine: Engine,
    ipinfo_handler: ipinfo.handler.Handler,
) -> None:
    udp_server = SpeedtestDNSServer(
        engine=engine,
        ipinfo_handler=ipinfo_handler,
        cache_size=cache_size,
        port=port,
        tcp=False,
    )

    tcp_server = SpeedtestDNSServer(
        engine=engine,
        ipinfo_handler=ipinfo_handler,
        cache_size=cache_size,
        port=port,
        tcp=True,
    )

    logger.info(f"Starting DNS Speed Test Server on port {port} using TCP and UDP...")

    tcp_server.start_thread()
    udp_server.start_thread()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server stopping due to keyboard interrupt...")
    finally:
        tcp_server.stop()
        udp_server.stop()

        logger.info("Server stopped.")
