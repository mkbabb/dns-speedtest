import random
import re
import string
from dataclasses import dataclass

from src.constants import RECORD_SIZE


class ChunkCache:
    def __init__(self, cache_size: int, chunk_size: int):
        self.chunks = self._generate_random_chunks(cache_size, chunk_size)

    def get_random_chunks(self, num_chunks: int) -> list[str]:
        start = random.randint(0, len(self.chunks) - num_chunks)
        return self.chunks[start : start + num_chunks]

    @staticmethod
    def _generate_random_chunks(size: int, chunk_size: int) -> list[str]:
        """Generate random chunks of specified size."""
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        return [content[i : i + chunk_size] for i in range(0, len(content), chunk_size)]


def clamp(value: int, min_value: int, max_value: int) -> int:
    """Clamp a value between a minimum and maximum value."""
    return max(min_value, min(value, max_value))


def calc_speed(delta: float, byte_amount: int) -> float:
    """Calculate the download speed in MB/s.

    Args:
        delta (float): The time delta in nanoseconds
        byte_amount (int): The amount of bytes downloaded
    """

    return byte_amount / delta * 1e9 / 2**20


@dataclass
class DNSUrl:
    """
    EBNF Grammar for a DNS URL:

    url           = byte_amount?, uid?, domain

    byte_amount   = digit+, "_"

    uid           = \w+, "_"

    top_level_domain = \w{2,}

    subdomain     = \w+

    domain        = subdomain, (".", subdomain)*, ".", top_level_domain
    """

    # The amount of bytes to download
    byte_amount: int
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

        match = re.match(r"(\d+_)?(\w+_)?(.+)", url)
        if not match:
            raise ValueError("Invalid DNS URL format")

        byte_amount, uid, domain = match.groups()

        if byte_amount:
            try:
                byte_amount = clamp(int(byte_amount[:-1]), 1, RECORD_SIZE)
            except ValueError:
                byte_amount = RECORD_SIZE
        else:
            byte_amount = RECORD_SIZE

        if uid:
            uid = uid[:-1]
        else:
            uid = ""

        return DNSUrl(byte_amount=byte_amount, uid=uid, domain=domain)
