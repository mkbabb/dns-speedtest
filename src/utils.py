import binascii
import contextlib
import ipaddress
import json
import random
import re
import string
import subprocess
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Generator, TypeVar

from loguru import logger
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from src.constants import DEFAULT_CHUNK_FILEPATH, RECORD_SIZE

T = TypeVar("T")


class ChunkCache:
    def __init__(
        self,
        cache_size: int,
        chunk_size: int,
        file_path: str | Path | None = DEFAULT_CHUNK_FILEPATH,
    ):
        self.cache_size = cache_size
        self.chunk_size = chunk_size

        self.file_path = Path(file_path) if file_path is not None else None

        self.chunks: list[bytes] = []

        if self.file_path is not None:
            self.chunks = self.read_and_chunk_file()
        else:
            self.chunks = self.generate_random_chunks()

    def get_random_chunks(self, num_chunks: int) -> list[bytes]:
        num_chunks = clamp(num_chunks, 1, len(self.chunks))
        start = random.randint(0, len(self.chunks) - num_chunks)

        return self.chunks[start : start + num_chunks]

    def read_and_chunk_file(self) -> list[bytes]:
        """Read the file and split it into chunks of specified size."""
        try:
            content = self.file_path.read_bytes()
            return [
                content[i : i + self.chunk_size]
                for i in range(0, len(content), self.chunk_size)
            ]
        except FileNotFoundError:
            print(f"Error: File not found at {self.file_path}")
            return []
        except IOError:
            print(f"Error: Could not read file at {self.file_path}")
            return []

    def generate_random_chunks(self) -> list[bytes]:
        """Generate random chunks of specified size."""
        content = ''.join(
            random.choices((string.ascii_letters + string.digits), k=self.cache_size)
        ).encode()

        return [
            content[i : i + self.chunk_size]
            for i in range(0, len(content), self.chunk_size)
        ]


def clamp(value: int, min_value: int, max_value: int) -> int:
    """Clamp a value between a minimum and maximum value."""
    return max(min_value, min(value, max_value))


@lru_cache
def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def ipv4_to_ipv6(ip: str | int | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Convert an IPv4 address to an IPv6 address."""
    ipv4 = ipaddress.IPv4Address(ip)

    return str(ipaddress.IPv6Address(f"::ffff:{ipv4}"))


@lru_cache
def get_interface_ip(interface_name: str) -> str | None:
    try:
        # Run the ip addr show command for the specified interface
        result = subprocess.run(
            ['ip', 'addr', 'show', interface_name],
            capture_output=True,
            text=True,
            check=True,
        )
        output = result.stdout

        # Parse the output to find the IPv4 address
        for line in output.split('\n'):
            if 'inet ' in line:
                ip = line.split()[1].split('/')[0]
                return ip

        # If we couldn't find the IP, return None
        return None

    except subprocess.CalledProcessError:
        # Command failed, likely due to non-existent interface
        return None


@dataclass
class DNSUrl:
    """
    EBNF Grammar for a DNS URL:

    url           = byte_len?, uid?, domain

    byte_len   = digit+, "_"

    uid           = \\w+, "_"

    top_level_domain = \\w{2,}

    subdomain     = \\w+

    domain        = subdomain, (".", subdomain)*, ".", top_level_domain
    """

    # The amount of bytes to download
    byte_len: int
    # The unique identifier
    uid: str
    # The domain to download from
    domain: str

    @staticmethod
    def from_url(url: str) -> "DNSUrl":
        """
        Parse a DNS URL into its components.

        Args:
            url (str): The DNS URL to parse
        """

        logger.debug(f"Parsing DNS URL: {url}")

        match = re.match(r"(\d+_)?(\w+_)?(.+)", url)
        if not match:
            logger.error(f"Invalid DNS URL format: {url}")

            return DNSUrl(byte_len=RECORD_SIZE, uid="", domain=url)
            # raise ValueError("Invalid DNS URL format")

        byte_len, uid, domain = match.groups()

        logger.debug(f"Unparsed; Byte length: {byte_len}, UID: {uid}, Domain: {domain}")

        if byte_len:
            try:
                byte_len = clamp(int(byte_len[:-1]), 1, RECORD_SIZE)
            except ValueError:
                byte_len = RECORD_SIZE
        else:
            byte_len = RECORD_SIZE

        if uid:
            uid = uid[:-1]
        else:
            uid = ""

        logger.debug(f"Byte length: {byte_len}, UID: {uid}, Domain: {domain}")

        return DNSUrl(byte_len=byte_len, uid=uid, domain=domain)


@contextlib.contextmanager
def uncloseable(fd: T) -> Generator[T, None, None]:
    """
    Context manager which turns the fd's close operation to no-op for the duration of the context.
    """
    close = fd.close  # type: ignore
    fd.close = lambda: None  # type: ignore
    yield fd  # type: ignore
    fd.close = close  # type: ignore


class PacketEncoder(json.JSONEncoder):
    """Custom JSON encoder for handling network packet data types."""

    def default(self, obj: Any) -> Any:
        # Convert bytes to UTF-8 or hex if UTF-8 fails
        if isinstance(obj, bytes):
            try:
                return obj.decode('utf-8')
            except UnicodeDecodeError:
                return binascii.hexlify(obj).decode('ascii')
        # Convert datetime to ISO format
        if isinstance(obj, datetime):
            return obj.isoformat()
        # Convert sets to lists for JSON serialization
        if isinstance(obj, (set, frozenset)):
            return list(obj)

        return super().default(obj)


def get_protocol_fields(layer_type: str) -> dict[str, str]:
    """Return sprintf format strings for protocol-specific fields."""
    protocol_fields = {
        'TCP': {
            'flags': '%TCP.flags%',  # TCP flags (SYN, ACK, etc.)
            'options': '%TCP.options%',  # TCP options
            'window': '%TCP.window%',  # Window size
        },
        'IP': {
            'flags': '%IP.flags%',  # IP flags (DF, MF)
            'tos': '%IP.tos%',  # Type of Service
            'frag': '%IP.frag%',  # Fragmentation offset
        },
        'ICMP': {
            'type': '%ICMP.type%',  # ICMP message type
            'code': '%ICMP.code%',  # ICMP message code
        },
        'DNS': {
            'qr': '%DNS.qr%',  # Query/Response flag
            'opcode': '%DNS.opcode%',  # Operation code
            'aa': '%DNS.aa%',  # Authoritative Answer
            'tc': '%DNS.tc%',  # Truncation flag
            'rd': '%DNS.rd%',  # Recursion Desired
            'ra': '%DNS.ra%',  # Recursion Available
            'z': '%DNS.z%',  # Reserved field
            'rcode': '%DNS.rcode%',  # Response code
            'qtype': '%DNS.qtype%',  # Query type
            'qclass': '%DNS.qclass%',  # Query class
        },
    }
    return protocol_fields.get(layer_type, {})


def get_layer_fields(packet: Packet, layer_type: str) -> dict[str, Any]:
    """Extract protocol-specific fields using sprintf formatting."""
    field_dict = {}
    if not hasattr(packet, layer_type):
        return field_dict

    layer = getattr(packet, layer_type)

    protocol_fields = get_protocol_fields(layer_type)

    for field_name, sprintf_format in protocol_fields.items():
        try:
            field_value = packet.sprintf(sprintf_format)
            if field_value != "??":  # Skip invalid/undefined fields
                field_dict[field_name] = field_value
        except Exception:
            continue

    return field_dict


def process_layer(
    current_layer: Packet, packet: Packet, include_raw: bool, stringify_flags: bool
) -> tuple[dict, dict]:
    """Process individual packet layer, extracting fields and raw data."""
    layer_name = current_layer.name
    layer_dict = {}
    raw_dict = {}

    # Include raw layer data if requested
    if include_raw:
        raw_dict = {
            'raw': binascii.hexlify(bytes(current_layer)).decode('ascii'),
            'length': len(current_layer),
        }

    # Process layer fields
    for field_name, field_value in current_layer.fields.items():
        if field_name.startswith('_'):  # Skip private fields
            continue

        layer_dict[field_name] = str(field_value)

    # Add protocol-specific formatted fields
    if stringify_flags:
        layer_dict.update(get_layer_fields(packet, layer_name))

    # Layer-specific processing
    if isinstance(current_layer, IP):
        layer_dict['total_length'] = len(current_layer)
        if include_raw:
            layer_dict['header_length'] = current_layer.ihl * 4  # IHL * 4 bytes
            layer_dict['payload_length'] = len(current_layer.payload)

    elif isinstance(current_layer, (TCP, UDP)):
        layer_dict['sport'] = current_layer.sport
        layer_dict['dport'] = current_layer.dport
        if include_raw:
            # UDP header = 8 bytes, TCP header = data offset * 4 bytes
            layer_dict['header_length'] = (
                8 if isinstance(current_layer, UDP) else (current_layer.dataofs * 4)
            )
            layer_dict['payload_length'] = len(current_layer.payload)
            if hasattr(current_layer, 'load'):
                layer_dict['load'] = (
                    binascii.hexlify(current_layer.load).decode('ascii')
                    if isinstance(current_layer.load, bytes)
                    else current_layer.load
                )

    elif isinstance(current_layer, HTTP):
        if hasattr(current_layer, 'Headers'):
            layer_dict['headers'] = dict(current_layer.Headers)

    return layer_dict, raw_dict


def packet_to_dict(
    packet: Packet, include_raw: bool = False, stringify_flags: bool = True
) -> dict[str, Any]:
    """Convert packet to dictionary with optional raw data inclusion."""
    result = {
        'summary': packet.summary(),
        'time': getattr(packet, 'time', None),
        'layers': {},
        'raw_layers': {} if include_raw else {},
    }

    # Process each layer recursively
    current_layer = packet
    while current_layer:
        layer_dict, raw_dict = process_layer(
            current_layer, packet, include_raw, stringify_flags
        )

        layer_name = current_layer.name
        result['layers'][layer_name] = layer_dict
        if include_raw:
            result['raw_layers'][layer_name] = raw_dict

        current_layer = current_layer.payload if current_layer.payload else None

    return result


def packet_to_json(
    packet: Packet,
    include_raw: bool = False,
    stringify_flags: bool = True,
    indent: int | None = None,
    sort_keys: bool = False,
    **kwargs: Any,
) -> str:
    """Convert packet to JSON string with customizable formatting options."""
    try:
        packet_dict = packet_to_dict(packet, include_raw, stringify_flags)
        return json.dumps(
            packet_dict, cls=PacketEncoder, indent=indent, sort_keys=sort_keys, **kwargs
        )
    except Exception as e:
        raise ValueError(f"Failed to convert packet to JSON: {str(e)}") from e
