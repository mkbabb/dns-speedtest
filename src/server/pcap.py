from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from loguru import logger
from scapy.all import IP, TCP, UDP, Raw, sniff
from scapy.packet import Packet
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from src.constants import DEFAULT_INTERFACE, DEFAULT_PORT
from src.models import PacketCaptureResultsTable, RequestsTable
from src.utils import calc_throughput, is_private_ip


@dataclass
class PacketInfo:
    timestamp: int
    packet: Optional[Packet] = None


@dataclass
class DNSTransaction:
    uuid: uuid.UUID = None
    transactions: list[PacketInfo] = field(default_factory=list)


TransactionKey = Tuple[str, int, str, int]


class DNSPacketCapture:
    def __init__(
        self,
        engine: Engine = None,
        interface: str = DEFAULT_INTERFACE,
        port: int = DEFAULT_PORT,
    ):
        self.engine = engine
        self.interface: str = interface
        self.port: int = port

        self.dns_transactions: Dict[TransactionKey, DNSTransaction] = defaultdict(
            DNSTransaction
        )

        self.uuid_transactions: Dict[uuid.UUID, TransactionKey] = {}

        self.lock: threading.Lock = threading.Lock()
        self.stop_sniffing: threading.Event = threading.Event()

    @staticmethod
    def reverse_transaction_key(transaction_key: TransactionKey) -> TransactionKey:
        return (
            transaction_key[2],
            transaction_key[3],
            transaction_key[0],
            transaction_key[1],
        )

    @staticmethod
    def make_transaction_key(
        ip_src: str, src_port: int, ip_dst: str, dst_port: int
    ) -> TransactionKey:
        return (ip_src, src_port, ip_dst, dst_port)

    @staticmethod
    def make_reverse_transaction_key(
        ip_src: str, src_port: int, ip_dst: str, dst_port: int
    ) -> TransactionKey:
        return DNSPacketCapture.reverse_transaction_key(
            DNSPacketCapture.make_transaction_key(
                ip_src=ip_src, src_port=src_port, ip_dst=ip_dst, dst_port=dst_port
            )
        )

    @staticmethod
    def get_sequence_number(packet: Packet) -> Optional[int]:
        return packet['TCP'].seq if packet.haslayer('TCP') else None

    @staticmethod
    def get_acknowledgment_number(packet: Packet) -> Optional[int]:
        return packet['TCP'].ack if packet.haslayer('TCP') else None

    @staticmethod
    def is_valid_packet(packet: Packet) -> bool:
        return IP in packet and (TCP in packet or UDP in packet)

    @staticmethod
    def get_ports(packet: Packet) -> Tuple[int, int]:
        if TCP in packet:
            tcp_layer = packet[TCP]
            return tcp_layer.sport, tcp_layer.dport
        else:  # UDP
            udp_layer = packet[UDP]
            return udp_layer.sport, udp_layer.dport

    @staticmethod
    def get_flags(packet: Packet) -> str:
        return packet.sprintf("%TCP.flags%") if TCP in packet else ""

    @staticmethod
    def get_full_packet_size(packet: Packet) -> int:
        # Get the length of the IP layer
        # ip_layer_len = packet[IP].len

        # Initialize transport layer length
        transport_layer_len = 0

        # Check for TCP or UDP layer and get its length
        if TCP in packet:
            if Raw in packet:
                transport_layer_len = len(packet[Raw].load)
            else:
                transport_layer_len = len(packet[TCP])
        elif UDP in packet:
            transport_layer_len = packet[UDP].len

        # Return the sum of IP and transport layer lengths
        return transport_layer_len

    def capture_packets(self) -> None:
        logger.info(
            f"Starting packet capture on interface {self.interface}, port {self.port}"
        )

        sniff(
            iface=self.interface,
            filter=f"port {self.port}",
            prn=self.process_packet,
            stop_filter=lambda _: self.stop_sniffing.is_set(),
            store=0,
        )

    def process_packet(self, packet: Packet) -> None:
        if not self.is_valid_packet(packet):
            return

        ip_layer = packet[IP]
        ip_src, ip_dst = ip_layer.src, ip_layer.dst
        src_port, dst_port = self.get_ports(packet)

        transaction_key = self.make_transaction_key(
            ip_src=ip_src, src_port=src_port, ip_dst=ip_dst, dst_port=dst_port
        )

        with self.lock:
            logger.info(
                f"Processing packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}"
            )

            if dst_port == self.port:
                self.process_dns_request(transaction_key=transaction_key, packet=packet)
            elif src_port == self.port:
                self.process_dns_response(
                    transaction_key=transaction_key, packet=packet
                )

    def process_dns_request(
        self, transaction_key: Tuple[str, int, str, int], packet: Packet
    ) -> None:
        logger.info(f"Processing DNS request: {transaction_key}", pcap=True)
        logger.info(f"Packet: {packet.show(dump=True)}", pcap=True)

        packet_info = PacketInfo(
            packet=packet,
            timestamp=time.time_ns(),
        )
        transaction_uuid = self.find_transaction_uuid(transaction_key)

        self.write_to_db(
            transaction_key=transaction_key,
            transaction_uuid=transaction_uuid,
            packet_info=packet_info,
        )

        logger.info(
            f"Captured DNS request: {transaction_key} : {transaction_uuid}", pcap=True
        )

    def process_dns_response(
        self, transaction_key: TransactionKey, packet: Packet
    ) -> None:
        logger.info(f"Processing DNS response: {transaction_key}", pcap=True)
        logger.info(f"Packet: { packet.show(dump=True)}", pcap=True)

        packet_info = PacketInfo(
            packet=packet,
            timestamp=time.time_ns(),
        )
        transaction_uuid = self.find_transaction_uuid(
            self.reverse_transaction_key(transaction_key)
        )

        self.write_to_db(
            transaction_key=transaction_key,
            transaction_uuid=transaction_uuid,
            packet_info=packet_info,
        )

        logger.info(
            f"Captured DNS response: {transaction_key} : {transaction_uuid}", pcap=True
        )

    def write_to_db(
        self,
        transaction_key: TransactionKey,
        transaction_uuid: uuid.UUID,
        packet_info: PacketInfo,
    ):
        src_ip, src_port, dst_ip, dst_port = transaction_key

        with Session(self.engine) as session:

            packet_capture_result = PacketCaptureResultsTable(
                transaction_uuid=str(transaction_uuid),
                timestamp=int(packet_info.packet.time * 1.0e6),
                size=self.get_full_packet_size(packet_info.packet),
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP" if TCP in packet_info.packet else "UDP",
                flags=self.get_flags(packet_info.packet),
                sequence_number=self.get_sequence_number(packet_info.packet),
                acknowledgment_number=self.get_acknowledgment_number(
                    packet_info.packet
                ),
                capture_time=datetime.fromtimestamp(packet_info.packet.time),
                sent_time=(
                    datetime.fromtimestamp(packet_info.packet.sent_time)
                    if packet_info.packet.sent_time is not None
                    else None
                ),
                raw_packet=packet_info.packet.json(),
            )

            session.add(packet_capture_result)

            session.commit()

            logger.success(
                f"Logged packet capture result: {transaction_uuid} : {packet_info.timestamp}"
            )

    def start(self) -> None:
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logger.info("Packet capture thread started", pcap=True)

    def stop(self) -> None:
        logger.info("Stopping packet capture...", pcap=True)
        self.stop_sniffing.set()
        self.capture_thread.join()
        logger.info("Packet capture stopped", pcap=True)

    def add_uuid(
        self, transaction_uuid: uuid.UUID, transaction_key: TransactionKey
    ) -> None:
        with self.lock:
            self.uuid_transactions[transaction_uuid] = transaction_key

        logger.info(
            f"Added UUID {transaction_uuid} for transaction {transaction_key}",
            pcap=True,
        )

    def find_transaction_uuid(
        self, transaction_key: TransactionKey
    ) -> Optional[uuid.UUID]:
        # with self.lock:
        for uuid_transaction_key, key in self.uuid_transactions.items():
            if key == transaction_key:
                return uuid_transaction_key

        return None
