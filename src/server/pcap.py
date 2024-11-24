from __future__ import annotations

import datetime
import json
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from io import BytesIO
from typing import Dict, Optional, Tuple

from cachetools import TTLCache
from loguru import logger
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from src.constants import DEFAULT_INTERFACE, DEFAULT_PORT
from src.models import PacketCaptureRawData, PacketCaptureResultsTable
from src.utils import is_private_ip, packet_to_json, uncloseable


@dataclass
class PacketInfo:
    timestamp: int
    packet: Packet | None = None


@dataclass
class DNSTransaction:
    uuid: uuid.UUID | None = None
    transactions: list[PacketInfo] = field(default_factory=list)


TransactionKey = Tuple[str, int, str, int]


UUID_CACHE_TTL = 60  # 60 seconds

UUID_CACHE_SIZE = 1000

UUID_TIMEDELTA = datetime.timedelta(seconds=1.25 * UUID_CACHE_TTL)


class DNSPacketCapture:
    def __init__(
        self,
        engine: Engine | None = None,
        interface: str = DEFAULT_INTERFACE,
        port: int = DEFAULT_PORT,
    ):
        self.engine = engine
        self.interface: str = interface
        self.port: int = port

        self.dns_transactions: Dict[TransactionKey, DNSTransaction] = defaultdict(
            DNSTransaction
        )

        # TTL-based cache to store transaction UUIDs
        self.uuid_transactions: TTLCache[uuid.UUID, TransactionKey] = TTLCache(
            maxsize=UUID_CACHE_SIZE, ttl=UUID_CACHE_TTL
        )

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
        is_tcp_ip = IP in packet and (TCP in packet or UDP in packet)

        is_private = is_private_ip(packet[IP].src) and is_private_ip(packet[IP].dst)

        return is_tcp_ip and not is_private

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
    def get_protocol(packet: Packet) -> str:
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        else:
            return ""

    @staticmethod
    def get_full_packet_size(packet: Packet) -> int:
        transport_layer_len = 0
        # Check for TCP or UDP layer and get its length
        if TCP in packet and Raw in packet:
            transport_layer_len = len(packet[Raw].load)
        elif UDP in packet:
            transport_layer_len = packet[UDP].len

        return transport_layer_len

    def capture_packets(self) -> None:
        logger.info(
            f"Starting packet capture on interface {self.interface}, port {self.port}"
        )

        # Filter for only port self.port;
        # Ignore exclusively local traffic and 8.8.8.8 and 1.1.1.1
        filter = f"""
            port {self.port}
            and not (src net 8.8.8.8 or dst net 8.8.8.8
                or src host 1.1.1.1 or dst host 1.1.1.1
                or (src net 127.0.0.0/8 and dst net 127.0.0.0/8)
                or (src net 10.0.0.0/8 and dst net 10.0.0.0/8)
                or (src net 172.16.0.0/12 and dst net 172.16.0.0/12)
                or (src net 192.168.0.0/16 and dst net 192.168.0.0/16))
        """

        sniff(
            iface=self.interface,
            filter=filter,
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

        self.reconcile_db_transcation_ids()

        logger.info(
            f"Captured DNS response: {transaction_key} : {transaction_uuid}", pcap=True
        )

    def reconcile_db_transcation_ids(self) -> None:
        """Function to reconcile null transaction_uuids in the database, based on the formulated transaction_key"""

        # Get the null transaction_uuids from the db:
        with Session(self.engine) as session:
            results = (
                session.query(PacketCaptureResultsTable)
                .filter(PacketCaptureResultsTable.transaction_uuid.is_(None))
                # Filter out timestamped packets older than the UUID time delta
                .filter(
                    PacketCaptureResultsTable.capture_time
                    > datetime.datetime.now() - UUID_TIMEDELTA
                )
                .all()
            )

            for result in results:
                transaction_key = self.make_transaction_key(
                    ip_src=result.src_ip,
                    src_port=result.src_port,
                    ip_dst=result.dst_ip,
                    dst_port=result.dst_port,
                )
                reverse_transaction_key = self.make_reverse_transaction_key(
                    ip_src=result.src_ip,
                    src_port=result.src_port,
                    ip_dst=result.dst_ip,
                    dst_port=result.dst_port,
                )

                transaction_uuid = self.find_transaction_uuid(transaction_key)
                transaction_uuid = (
                    transaction_uuid
                    if transaction_uuid is not None
                    else self.find_transaction_uuid(reverse_transaction_key)
                )

                if transaction_uuid is not None:
                    result.transaction_uuid = str(transaction_uuid)
                    session.commit()

                    logger.info(
                        f"Reconciled transaction_uuid: {transaction_uuid} for transaction_key: {transaction_key}"
                    )

    def write_to_db(
        self,
        transaction_key: TransactionKey,
        transaction_uuid: uuid.UUID | None,
        packet_info: PacketInfo,
    ):
        if packet_info.packet is None:
            return

        src_ip, src_port, dst_ip, dst_port = transaction_key

        packet_binary: bytes | None = None

        packet: Packet = packet_info.packet

        dump = packet.show(dump=True)
        logger.info(f"{dump}", pcap2=True)

        with uncloseable(BytesIO()) as pcap_buffer:
            wrpcap(pcap_buffer, [packet])
            packet_binary = pcap_buffer.getvalue()

        with Session(self.engine) as session:
            packet_capture_result = PacketCaptureResultsTable(
                transaction_uuid=str(transaction_uuid) if transaction_uuid else None,
                # Timestamp in nanoseconds
                timestamp=packet.time * 1.0e6,
                size=self.get_full_packet_size(packet),
                # Source and destination IP and port
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=self.get_protocol(packet),
                flags=self.get_flags(packet),
                sequence_number=self.get_sequence_number(packet),
                acknowledgment_number=self.get_acknowledgment_number(packet),
                capture_time=datetime.datetime.fromtimestamp(float(packet.time)),
                sent_time=(
                    datetime.datetime.fromtimestamp(float(packet.sent_time))
                    if packet.sent_time is not None
                    else None
                ),
            )

            session.add(packet_capture_result)
            session.commit()

            raw_data = PacketCaptureRawData(
                packet_capture_result_id=packet_capture_result.id,
                packet_json=json.loads(
                    packet_to_json(
                        packet,
                        include_raw=False,
                        indent=None,
                        sort_keys=True,
                        stringify_flags=True,
                    )
                ),
                packet_binary=packet_binary,
            )

            session.add(raw_data)
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
