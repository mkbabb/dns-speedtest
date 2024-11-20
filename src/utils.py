import contextlib
import ipaddress
import random
import re
import string
import subprocess
from dataclasses import dataclass
from functools import lru_cache, wraps
from pathlib import Path
from typing import Generator, Optional, TypeVar

from loguru import logger

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


def calc_throughput(latency: float, byte_len: int) -> float:
    """Calculate the download speed in MB/s.

    Args:
        latency (float): The latency in nanoseconds
        byte_len (int): The amount of bytes downloaded
    """
    return byte_len / (latency * 1e-9) / 1e6


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
def get_interface_ip(interface_name: str) -> Optional[str]:
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

    uid           = \w+, "_"

    top_level_domain = \w{2,}

    subdomain     = \w+

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
    close = fd.close
    fd.close = lambda: None
    yield fd
    fd.close = close
