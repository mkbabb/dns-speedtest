from __future__ import annotations

import ctypes
import select
import socket
import socketserver
import statistics
import struct
import threading
import time
import uuid
from typing import Any, Optional, override

from dnslib import RCODE, DNSRecord
from dnslib.server import BaseResolver, DNSError
from loguru import logger
from sqlalchemy.engine import Engine

from src.constants import (
    DEFAULT_ADDRESS,
    DEFAULT_INTERFACE,
    DEFAULT_PORT,
    RECV_BUFFER_SIZE,
)
from src.server.pcap import DNSPacketCapture
from src.utils import get_interface_ip

# Load time.h for high-precision timing
libc = ctypes.CDLL('libc.so.6')
CLOCK_MONOTONIC_RAW = 4  # system-wide clock that isn't subject to NTP adjustments

LENGTH_SIZE = 2
LENGTH_TYPE = "!H"


class timespec(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_nsec', ctypes.c_long)]


libc.clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]


def get_time_ns():
    t = timespec()
    libc.clock_gettime(CLOCK_MONOTONIC_RAW, ctypes.pointer(t))
    return t.tv_sec * 1e9 + t.tv_nsec


def measure_python_overhead():
    start = get_time_ns()
    end = get_time_ns()
    return end - start


class DNSHandler(socketserver.BaseRequestHandler):
    server: (
        socketserver.BaseServer
        | socketserver.UDPServer
        | socketserver.TCPServer
        | "DNSServer"
    )
    request: socket.socket | tuple[bytes, socket.socket]
    udplen: int
    client_address: tuple[str, int]
    protocol: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.udplen = 0

        super().__init__(*args, **kwargs)

    @override
    def handle(self) -> None:
        if self.server.socket_type == socket.SOCK_STREAM:
            logger.info(f"TCP Connection from {self.client_address}")
            self.protocol = "TCP"

            self.handle_tcp()
        else:
            logger.info(f"UDP Connection from {self.client_address}")
            self.protocol = "UDP"

            self.handle_udp()

    def handle_tcp(self) -> None:
        receive_start_time = time.perf_counter_ns()

        data = self.receive_tcp_data()

        receive_end_time = time.perf_counter_ns()
        receive_latency = receive_end_time - receive_start_time

        if data is None:
            return

        transaction_uuid = self.on_receive(data=data, latency=receive_latency)

        try:
            rdata = self.get_reply(data=data, transaction_uuid=transaction_uuid)

            send_latency = self.send_tcp_reply(rdata=rdata)

            self.on_send(data=rdata, latency=send_latency)
        except DNSError as e:
            logger.error(f"DNS Error: {e}")

    def handle_udp(self) -> None:
        receive_start_time = time.perf_counter_ns()

        data, connection = self.request  # type: ignore

        receive_end_time = time.perf_counter_ns()
        receive_latency = receive_end_time - receive_start_time

        transaction_uuid = self.on_receive(data=data, latency=receive_latency)

        try:
            rdata = self.get_reply(data=data, transaction_uuid=transaction_uuid)

            send_latency = self.send_udp_reply(rdata=rdata, connection=connection)

            self.on_send(data=rdata, latency=send_latency)
        except DNSError as e:
            logger.error(f"DNS Error: {e}")

    def receive_tcp_data(self) -> bytes | None:
        data = self.request.recv(RECV_BUFFER_SIZE)

        if len(data) < LENGTH_SIZE:
            return None

        length = struct.unpack(LENGTH_TYPE, bytes(data[:LENGTH_SIZE]))[0]

        while len(data) - LENGTH_SIZE < length:
            new_data = self.request.recv(RECV_BUFFER_SIZE)
            if not new_data:
                break
            data += new_data

        return data[LENGTH_SIZE:]

    def send_tcp_reply(
        self,
        rdata: bytes,
    ) -> float:
        rdata = struct.pack(LENGTH_TYPE, len(rdata)) + rdata
        self.request.setblocking(False)

        send_start_time = get_time_ns()

        self.request.sendall(rdata)

        send_end_time = get_time_ns()

        latency = send_end_time - send_start_time

        self.request.setblocking(True)

        logger.info(f"Sent data of length {len(rdata)} in {latency/1e6:.2f} ms")

        return latency

    def send_udp_reply(
        self,
        rdata: bytes,
        connection: socket.socket,
    ) -> None:
        send_start_time = get_time_ns()

        connection.sendto(rdata, self.client_address)

        send_end_time = get_time_ns()

        latency = send_end_time - send_start_time

        logger.info(f"Sent data of length {len(rdata)} in {latency/1e6:.2f} ms")

        return latency

    def get_reply(self, data: bytes) -> bytes:
        request = DNSRecord.parse(data)

        resolver: BaseResolver = self.server.resolver  # type: ignore

        reply = resolver.resolve(request=request, handler=self)

        # Handle UDP truncation
        if self.server.socket_type == socket.SOCK_DGRAM:
            rdata = reply.pack()

            if self.udplen and len(rdata) > self.udplen:
                truncated_reply = reply.truncate()
                rdata = truncated_reply.pack()
        else:
            rdata = reply.pack()

        return rdata

    def on_receive(self, data: bytes, latency: float) -> Optional[uuid.UUID]:
        logger.info(f"Received data of length {len(data)} in {latency/1e6:.2f} ms")
        if self.server.packet_capture is None:
            return

        transaction_uuid = uuid.uuid4()

        transaction_key = DNSPacketCapture.make_transaction_key(
            ip_src=self.client_address[0],
            src_port=self.client_address[1],
            # The server address is not the correct destination address; it's always
            # 0.0.0.0. Instead, use the interface IP address.
            # ip_dst=self.server.server_address[0],
            ip_dst=self.server.interface_ip,
            dst_port=self.server.server_address[1],
        )

        self.server.packet_capture.add_uuid(
            transaction_uuid=transaction_uuid, transaction_key=transaction_key
        )

        logger.info(
            f"Assigned UUID {transaction_uuid} to transaction {transaction_key}"
        )

        return transaction_uuid

    def on_send(self, data: bytes, latency: float) -> None:
        logger.info(f"Sent data of length {len(data)} in {latency/1e6:.2f} ms")


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
    def __init__(
        self,
        resolver: BaseResolver,
        address: str = DEFAULT_ADDRESS,
        port: int = DEFAULT_PORT,
        interface: str = DEFAULT_INTERFACE,
        tcp: bool = False,
        handler: type[DNSHandler] = DNSHandler,
        server: Optional[type[socketserver.BaseServer]] = None,
        packet_capture: Optional[DNSPacketCapture] = None,
    ):
        if server is None:
            server = TCPServer if tcp else UDPServer

        self.server = server((address, port), handler)
        self.server.resolver = resolver
        self.server.interface_ip = get_interface_ip(interface_name=interface)

        self.packet_capture = packet_capture

    def start(self) -> None:
        self.server.serve_forever()

    def stop(self) -> None:
        self.server.shutdown()

    def start_thread(self) -> None:
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop_thread(self) -> None:
        self.server.shutdown()
        self.thread.join()
