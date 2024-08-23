import socket
import socketserver
import struct
import threading
import time
from datetime import datetime
from typing import override

from dnslib import NS, QTYPE, RCODE, RR, TXT, DNSRecord
from dnslib.server import BaseResolver, DNSError
from loguru import logger
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from src.constants import (
    DEFAULT_PORT,
    MAX_TXT_CHUNK_SIZE,
    NS_RECORD_NAME,
    RECV_BUFFER_SIZE,
)
from src.models import DNSUrlsTable, RequestsTable, SpeedtestResultsTable
from src.utils import ChunkCache, DNSUrl, calc_speed


class DNSHandler(socketserver.BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        self.udplen = 0
        super().__init__(*args, **kwargs)

    def handle(self):
        start_time = time.perf_counter_ns()
        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.receive_tcp_data()
        else:
            self.protocol = 'udp'
            data, connection = self.request

        self.on_recieve(data=data, delta=time.perf_counter_ns() - start_time)

        try:
            rdata = self.get_reply(data)

            start_time = time.perf_counter_ns()

            if self.protocol == 'tcp':
                self.send_tcp_reply(rdata)
            else:
                self.send_udp_reply(rdata, connection)

            self.on_send(data=rdata, delta=time.perf_counter_ns() - start_time)

        except DNSError as e:
            logger.error(f"DNS Error: {e}")

    def receive_tcp_data(self):
        data = self.request.recv(RECV_BUFFER_SIZE)
        if len(data) < 2:
            # self.server.logger.log_error(self, "Request Truncated")
            return None

        length = struct.unpack("!H", bytes(data[:2]))[0]

        while len(data) - 2 < length:
            new_data = self.request.recv(RECV_BUFFER_SIZE)
            if not new_data:
                break
            data += new_data

        return data[2:]

    def send_tcp_reply(self, rdata):
        rdata = struct.pack("!H", len(rdata)) + rdata
        self.request.sendall(rdata)

    def send_udp_reply(self, rdata, connection):
        connection.sendto(rdata, self.client_address)

    def get_reply(self, data):
        request = DNSRecord.parse(data)

        resolver = self.server.resolver
        reply = resolver.resolve(request, self)

        if self.protocol == 'udp':
            rdata = reply.pack()
            if self.udplen and len(rdata) > self.udplen:
                truncated_reply = reply.truncate()
                rdata = truncated_reply.pack()

        else:
            rdata = reply.pack()

        return rdata

    def on_recieve(self, data: bytes, delta: float):
        pass

    def on_send(self, data: bytes, delta: float):
        pass


class SpeedtestDNSHandler(DNSHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.request_id: int = None

        self.dns_url: DNSUrl = None

        self.start_time: datetime = None

    @override
    def handle(self):
        self.start_time = datetime.now()

        return super().handle()

    @override
    def get_reply(self, data: bytes):
        request = DNSRecord.parse(data)
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]

        url = str(qname).rstrip('.')
        ip = self.client_address[0]

        self.dns_url = DNSUrl.from_url(url)

        # TODO! hack to get the engine
        with Session(self.server.engine) as session:
            dns_url_table_obj = DNSUrlsTable(
                byte_amount=self.dns_url.byte_amount,
                uid=self.dns_url.uid,
                domain=self.dns_url.domain,
            )

            request = RequestsTable(
                protocol=self.protocol,
                qtype=qtype,
                start_time=self.start_time,
                ip=ip,
                dns_url=dns_url_table_obj,
            )

            session.add(request)
            session.commit()

            self.request_id = request.id

            logger.info(
                f"Logged DNS request: {qtype} from {ip} for {self.dns_url.domain}"
            )

        return super().get_reply(data)

    @override
    def on_send(self, data: bytes, delta: float):
        end_time = datetime.now()

        dl_speed = calc_speed(
            delta=delta,
            byte_amount=self.dns_url.byte_amount,
        )

        with Session(self.server.engine) as session:
            speedtest_result = SpeedtestResultsTable(
                request_id=self.request_id,
                delta=delta,
                dl_speed=dl_speed,
            )

            session.add(speedtest_result)

            request = session.get(RequestsTable, self.request_id)
            request.end_time = end_time

            session.commit()

            logger.info(f"Logged Speed Test result for request {self.request_id}")


class BaseResolver(object):
    """
    Base resolver implementation. Provides 'resolve' method which is
    called by DNSHandler with the decode request (DNSRecord instance)
    and returns a DNSRecord instance as reply.

    In most cases you should be able to create a custom resolver by
    just replacing the resolve method with appropriate resolver code for
    application (see fixedresolver/zoneresolver/shellresolver for
    examples)

    Note that a single instance is used by all DNSHandler instances so
    need to consider blocking & thread safety.
    """

    def resolve(self, request, handler):
        """
        Example resolver - respond to all requests with NXDOMAIN
        """
        reply = request.reply()
        reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        return reply


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
                byte_amount=handler.dns_url.byte_amount,
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

    def handle_txt_or_a_query(self, request: DNSRecord, qname: str, byte_amount: int):
        reply = request.reply()

        num_chunks = byte_amount // MAX_TXT_CHUNK_SIZE
        chunks = self.chunk_cache.get_random_chunks(num_chunks)

        for chunk in chunks:
            reply.add_answer(
                RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=0, rdata=TXT(chunk))
            )

        logger.info(f"Resolved TXT query for {qname} with {byte_amount} bytes")

        return reply

    def handle_unsupported_query(self, request: DNSRecord, qtype: str) -> None:
        reply = request.reply()

        reply.header.rcode = 3

        logger.warning(f"Unsupported query type: {qtype}")

        return reply


class UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer, object):
    def __init__(self, server_address, handler):
        self.allow_reuse_address = True
        self.daemon_threads = True
        if server_address[0] != '' and ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        super(UDPServer, self).__init__(server_address, handler)


class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer, object):
    def __init__(self, server_address, handler):
        self.allow_reuse_address = True
        self.daemon_threads = True
        if server_address[0] != '' and ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        super(TCPServer, self).__init__(server_address, handler)


class DNSServer(object):
    """
    Convenience wrapper for socketserver instance allowing
    either UDP/TCP server to be started in blocking more
    or as a background thread.

    Processing is delegated to custom resolver (instance) and
    optionally custom logger (instance), handler (class), and
    server (class)

    In most cases only a custom resolver instance is required
    (and possibly logger)
    """

    def __init__(
        self,
        resolver: BaseResolver,
        address: str = "",
        port: int = DEFAULT_PORT,
        tcp: bool = False,
        handler: DNSHandler = DNSHandler,
        server: socketserver.BaseServer | None = None,
    ):
        """
        resolver:   resolver instance
        address:    listen address (default: "")
        port:       listen port (default: DEFAULT_PORT)
        tcp:        UDP (false) / TCP (true) (default: False)
        logger:     logger instance (default: DNSLogger)
        handler:    handler class (default: DNSHandler)
        server:     socketserver class (default: UDPServer/TCPServer)
        """
        if server is None:
            if tcp:
                server = TCPServer
            else:
                server = UDPServer

        self.server = server((address, port), handler)
        self.server.resolver = resolver

    def start(self):
        self.server.serve_forever()

    def start_thread(self):
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.server.shutdown()

    def isAlive(self):
        return self.thread.is_alive()


class SpeedtestDNSServer(DNSServer):
    def __init__(
        self,
        engine: Engine,
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


def run_server(port: int, engine: Engine, cache_size: int) -> None:
    # chunk_cache = ChunkCache(cache_size, MAX_TXT_CHUNK_SIZE)

    # resolver = SpeedTestResolver(
    #     engine=engine,
    #     chunk_cache=chunk_cache,
    # )

    # tcp_server = DNSServer(
    #     resolver=resolver,
    #     port=port,
    #     address="0.0.0.0",
    #     tcp=True,
    #     handler=SpeedtestDNSHandler,
    # )
    # udp_server = DNSServer(
    #     resolver=resolver,
    #     port=port,
    #     address="0.0.0.0",
    #     tcp=False,
    #     handler=SpeedtestDNSHandler,
    # )

    tcp_server = SpeedtestDNSServer(
        engine=engine,
        cache_size=cache_size,
        port=port,
        address="0.0.0.0",
        tcp=True,
    )

    logger.info(f"Starting DNS Speed Test Server on port {port} using TCP and UDP...")

    tcp_server.start_thread()
    # udp_server.start_thread()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Server stopping due to keyboard interrupt...")
    finally:
        tcp_server.stop()
        # udp_server.stop()
        logger.info("Server stopped.")
