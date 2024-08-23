import socket
import socketserver
import struct
import threading
import time

from dnslib import RCODE, DNSRecord
from dnslib.server import BaseResolver, DNSError
from loguru import logger

from src.constants import DEFAULT_PORT, RECV_BUFFER_SIZE


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
