import time
import uuid
from datetime import datetime
from typing import Optional, override

import ipinfo
import ipinfo.details
from dnslib import AAAA, CNAME, MX, NS, QTYPE, RR, SOA, TXT, A, DNSHeader, DNSRecord
from dnslib.server import BaseResolver
from loguru import logger
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from src.constants import (
    CACHE_SIZE,
    DEFAULT_ADDRESS,
    DEFAULT_INTERFACE,
    DEFAULT_PORT,
    DNS_TTL,
    DOMAIN_NAME,
    EXPIRE_TIME,
    MAX_TXT_CHUNK_SIZE,
    MINIMUM_TIME,
    NS_1_IP,
    RECORD_SIZE,
    REFRESH_TIME,
    RETRY_TIME,
)
from src.models import DNSUrlsTable, IPInfoTable, RequestsTable, SpeedtestResultsTable
from src.server.dns import BaseResolver, DNSHandler, DNSServer
from src.server.pcap import DNSPacketCapture
from src.utils import ChunkCache, DNSUrl, calc_throughput


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

    def __getitem__(self, item):
        return DomainName(item + '.' + self)


D = DomainName(DOMAIN_NAME)

SERIAL_NUMBER = int(time.time())

SOA_RECORD = SOA(
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

NS_RECORDS = [NS(D["ns-1"])]

RECORDS = {
    D: [A(NS_1_IP), AAAA((0,) * 16), MX(D.mail), SOA_RECORD] + NS_RECORDS,
    D["ns-1"]: [A(NS_1_IP)],
    D.admin: [A(NS_1_IP)],
    D.mail: [A(NS_1_IP)],
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
    def get_reply(self, data: bytes, transaction_uuid: Optional[uuid.UUID] = None):
        logger.info(
            f"Received DNS request from {self.client_address} : {transaction_uuid}"
        )

        self.dns_record = DNSRecord.parse(data)

        qname = self.dns_record.q.qname
        qtype = QTYPE[self.dns_record.q.qtype]

        url = str(qname).rstrip('.')
        ip = self.client_address[0]

        self.dns_url = DNSUrl.from_url(url)

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
                transaction_uuid=(
                    str(transaction_uuid) if transaction_uuid is not None else None
                ),
                dns_url=dns_url_table_obj,
            )

            session.add(request_table_obj)
            session.commit()

            self.request_id = request_table_obj.id

            logger.info(
                f"Logged DNS request: {qtype} from {ip} for {self.dns_url.domain}"
            )

            # self.call_ipinfo(
            #     ip=ip,
            #     request_table_obj=request_table_obj,
            # )
            # session.commit()

        return super().get_reply(data=data)

    @override
    def on_send(self, data: bytes, latency: float):
        qtype = QTYPE[self.dns_record.q.qtype]

        end_time = datetime.now()

        with Session(self.server.engine) as session:
            request_table_obj = session.get(RequestsTable, self.request_id)
            request_table_obj.end_time = end_time

            session.commit()

    def call_ipinfo(self, ip: str, request_table_obj: RequestsTable):
        try:
            details: ipinfo.details.Details = self.server.ipinfo_handler.getDetails(ip)
            details = details.all

            if details.get("bogon"):
                raise Exception("Bogon DEFAULT_ADDRESS address")

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

            return request_table_obj
        except Exception as e:
            logger.error(f"Error getting IP info: {e}")


class SpeedTestResolver(BaseResolver):
    def __init__(self, chunk_cache: ChunkCache):
        self.chunk_cache = chunk_cache

    def resolve(self, request: DNSRecord, handler: SpeedtestDNSHandler) -> DNSRecord:
        """
        Main resolver method.
        Handles different types of DNS queries and constructs appropriate responses.
        Routes TXT, A, and AAAA queries to a common handler for consistent
        data delivery and TCP forcing.
        """
        qname = request.q.qname
        qtype = request.q.qtype
        qt = QTYPE[qtype]

        logger.info(f"Resolving query for {qname} with type {qt}")

        reply = DNSRecord(
            DNSHeader(
                id=request.header.id,
                qr=1,  # QR: 1 (response),
                aa=1,  # AA: 1 (authoritative),
                ra=0,  # RA: 0 (recursion not available),
                tc=1,  # TC: 1 (truncated)
            ),
            q=request.q,
        )

        self.add_soa_to_reply(reply)

        if not self.is_valid_domain(qname):
            reply.header.rcode = 3
            return reply

        if qt == 'SOA':
            self.handle_soa_query(reply=reply, qname=qname)
        elif qt == 'NS':
            self.handle_ns_query(reply=reply, qname=qname)
        elif qt in ['TXT', 'A', 'AAAA']:
            self.handle_data_query(
                reply=reply,
                qname=qname,
                qtype=qtype,
                byte_len=handler.dns_url.byte_len,
            )
        else:
            self.handle_unsupported_query(reply=reply, qt=qt)

        self.add_edns0_if_requested(request=request, reply=reply)

        return reply

    def handle_data_query(
        self, reply: DNSRecord, qname: str, qtype: int, byte_len: int
    ):
        """
        Handles TXT, A, and AAAA queries with data responses.
        For A and AAAA queries, uses a special response to force TCP.
        For TXT queries, splits the data into chunks and adds them to the reply.
        """
        if qtype == QTYPE.TXT:
            self.handle_txt_response(reply, qname, byte_len)
        elif qtype in [QTYPE.A, QTYPE.AAAA]:
            self.handle_a_aaaa_response(reply, qname, qtype, byte_len)

    def handle_txt_response(self, reply: DNSRecord, qname: str, byte_len: int):
        """
        Handles TXT responses by splitting the data into chunks and adding them to the reply.
        """
        num_chunks = byte_len // MAX_TXT_CHUNK_SIZE
        chunks = self.chunk_cache.get_random_chunks(num_chunks)
        remaining_bytes = byte_len

        for chunk in chunks:
            if remaining_bytes < MAX_TXT_CHUNK_SIZE:
                chunk = chunk[:remaining_bytes]
            remaining_bytes -= len(chunk)
            reply.add_answer(
                RR(
                    rname=qname,
                    rtype=QTYPE.TXT,
                    rclass=1,
                    ttl=DNS_TTL,
                    rdata=TXT(chunk),
                )
            )

        logger.info(f"Resolved TXT query for {qname} with {byte_len} bytes")

    def handle_a_aaaa_response(
        self, reply: DNSRecord, qname: str, qtype: int, byte_len: int
    ):
        """
        Handles A and AAAA responses.
        Adds one valid A or AAAA record, then uses handle_txt_response for the rest of the data.
        """
        # Add one valid A or AAAA record
        if qtype == QTYPE.A:
            reply.add_answer(
                RR(
                    rname=qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=DNS_TTL,
                    rdata=A(NS_1_IP),
                )
            )
            address_record_len = 4  # IPv4 address is 4 bytes
        else:  # AAAA
            reply.add_answer(
                RR(
                    rname=qname,
                    rtype=QTYPE.AAAA,
                    rclass=1,
                    ttl=DNS_TTL,
                    rdata=AAAA(NS_1_IP),
                )
            )
            address_record_len = 16  # IPv6 address is 16 bytes

        # Adjust byte_len to account for the address record
        adjusted_byte_len = max(0, byte_len - address_record_len)

        # Use handle_txt_response for the rest of the data
        self.handle_txt_response(reply, qname, adjusted_byte_len)

        logger.info(
            f"Resolved A/AAAA query for {qname} with 1 address record and {adjusted_byte_len} bytes of TXT data"
        )

    def handle_soa_query(self, reply: DNSRecord, qname: str):
        """
        Handles SOA (Start of Authority) queries by adding the SOA record to the reply.
        """
        reply.add_answer(
            RR(rname=qname, rtype=QTYPE.SOA, rclass=1, ttl=DNS_TTL, rdata=SOA_RECORD)
        )
        logger.info(f"Resolved SOA query for {qname}")

    def handle_ns_query(self, reply: DNSRecord, qname: str):
        """
        Handles NS (Name Server) queries by adding NS records to the reply.
        """
        for rdata in NS_RECORDS:
            reply.add_answer(
                RR(rname=qname, rtype=QTYPE.NS, rclass=1, ttl=DNS_TTL, rdata=rdata)
            )
        logger.info(f"Resolved NS query for {qname}")

    def handle_unsupported_query(self, reply: DNSRecord, qt):
        """
        Handles unsupported query types by setting the response code to NOTIMPL (4).
        """
        reply.header.rcode = 4  # Not Implemented
        logger.warning(f"Unsupported query type: {qt}")

    def is_valid_domain(self, qname: str) -> bool:
        """
        Checks if the queried domain is valid for this zone.
        """
        qn = str(qname)
        return qn == D or qn.endswith('.' + D)

    def add_soa_to_reply(self, reply: DNSRecord):
        """
        Adds SOA record to the authority section of the reply.
        """
        reply.add_auth(
            RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=DNS_TTL, rdata=SOA_RECORD)
        )

    def add_edns0_if_requested(self, request: DNSRecord, reply: DNSRecord):
        """
        Adds EDNS0 OPT record to the reply if it was present in the request.
        """
        if request.ar and request.ar[0].rtype == QTYPE.OPT:
            reply.add_ar(request.ar[0])


class SpeedtestDNSServer(DNSServer):
    def __init__(
        self,
        engine: Engine,
        packet_capture: DNSPacketCapture,
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
            packet_capture=packet_capture,
            resolver=resolver,
            address=address,
            port=port,
            tcp=tcp,
            handler=SpeedtestDNSHandler,
        )

        self.server.engine = engine
        self.server.ipinfo_handler = ipinfo_handler
        self.server.packet_capture = packet_capture


def run_server(
    engine: Engine,
    ipinfo_handler: ipinfo.handler.Handler,
    interface: str = DEFAULT_INTERFACE,
    port: int = DEFAULT_PORT,
    cache_size: int = CACHE_SIZE,
) -> None:
    packet_capture = DNSPacketCapture(
        engine=engine,
        interface=interface,
        port=port,
    )

    packet_capture.start()

    udp_server = SpeedtestDNSServer(
        engine=engine,
        packet_capture=packet_capture,
        ipinfo_handler=ipinfo_handler,
        cache_size=cache_size,
        port=port,
        address="",
        tcp=False,
    )

    tcp_server = SpeedtestDNSServer(
        engine=engine,
        packet_capture=packet_capture,
        ipinfo_handler=ipinfo_handler,
        cache_size=cache_size,
        port=port,
        address="",
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

        packet_capture.stop()

        logger.info("Server stopped.")
