import time
from datetime import datetime
from typing import override

from dnslib import A, NS, QTYPE, RR, TXT, DNSRecord
from dnslib.server import BaseResolver
import ipinfo.details
from loguru import logger
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
import ipinfo

from src.constants import (
    DEFAULT_ADDRESS,
    DEFAULT_PORT,
    MAX_TXT_CHUNK_SIZE,
    NS_RECORD_NAME,
)
from src.models import DNSUrlsTable, IPInfoTable, RequestsTable, SpeedtestResultsTable
from src.server.dns import BaseResolver, DNSHandler, DNSServer
from src.utils import ChunkCache, DNSUrl, calc_speed


class SpeedtestDNSHandler(DNSHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.request = None

        self.request_id: int = None

        self.dns_url: DNSUrl = None

        self.start_time: datetime = None

    @override
    def handle(self):
        self.start_time = datetime.now()

        return super().handle()

    @override
    def get_reply(self, data: bytes):
        self.request = DNSRecord.parse(data)

        qname = self.request.q.qname
        qtype = QTYPE[self.request.q.qtype]

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
        qtype = QTYPE[self.request.q.qtype]

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

    def resolve(self, request: DNSRecord, handler: SpeedtestDNSHandler) -> DNSRecord:
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        if qtype == 'NS':
            return self.handle_ns_query(
                request=request,
                qname=qname,
            )
        elif qtype == 'TXT' or qtype == 'A':
            return self.handle_txt_or_a_query(
                request=request,
                qname=qname,
                qtype=qtype,
                byte_len=handler.dns_url.byte_len,
            )
        else:
            return self.handle_unsupported_query(request=request, qtype=qtype)

    def handle_ns_query(self, request: DNSRecord, qname):
        reply = request.reply()

        reply.add_answer(
            RR(
                rname=qname,
                rtype=QTYPE.NS,
                rclass=1,
                ttl=300,
                rdata=NS(NS_RECORD_NAME),
            )
        )

        logger.info(f"Resolved NS query for {qname} with NS record {NS_RECORD_NAME}")

        return reply

    def handle_txt_or_a_query(self, request: DNSRecord, qname: str, qtype: str, byte_len: int):
        reply = request.reply()

        RecordClass = TXT
        rtype = QTYPE.TXT

        if qtype == "A":
            RecordClass = A
            rtype = QTYPE.A

        num_chunks = byte_len // MAX_TXT_CHUNK_SIZE
        chunks = self.chunk_cache.get_random_chunks(num_chunks)

        for chunk in chunks:
            reply.add_answer(
                RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=0, rdata=TXT(chunk))
            )

        logger.info(f"Resolved {qname} query with {byte_len} bytes")

        return reply

    def handle_unsupported_query(self, request: DNSRecord, qtype: str) -> None:
        reply = request.reply()

        reply.header.rcode = 3

        logger.warning(f"Unsupported query type: {qtype}")

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
        address=DEFAULT_ADDRESS,
        tcp=False,
    )

    tcp_server = SpeedtestDNSServer(
        engine=engine,
        ipinfo_handler=ipinfo_handler,
        cache_size=cache_size,
        port=port,
        address=DEFAULT_ADDRESS,
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
