import random
import re
import string
from dataclasses import dataclass
from pathlib import Path
from src.constants import RECORD_SIZE, DEFAULT_CHUNK_FILEPATH


class ChunkCache:
    def __init__(
        self, cache_size: int, chunk_size: int, file_path: str | Path | None = DEFAULT_CHUNK_FILEPATH
    ):
        self.cache_size = cache_size
        self.chunk_size = chunk_size

        self.file_path = Path(file_path) if file_path is not None else None
        
        if self.file_path is not None:
            self.chunks = self.read_and_chunk_file()
        else:
            self.chunks = self.generate_random_chunks()

    def get_random_chunks(self, num_chunks: int) -> list[str]:
        num_chunks = clamp(num_chunks, 1, len(self.chunks))
        start = random.randint(0, len(self.chunks) - num_chunks)
        
        return self.chunks[start : start + num_chunks]

    def read_and_chunk_file(self) -> list[str]:
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

    def generate_random_chunks(self) -> list[str]:
        """Generate random chunks of specified size."""
        content = ''.join(
            random.choices(string.ascii_letters + string.digits, k=self.cache_size)
        )
        return [
            content[i : i + self.chunk_size]
            for i in range(0, len(content), self.chunk_size)
        ]


def clamp(value: int, min_value: int, max_value: int) -> int:
    """Clamp a value between a minimum and maximum value."""
    return max(min_value, min(value, max_value))


def calc_speed(delta: float, byte_len: int) -> float:
    """Calculate the download speed in MB/s.

    Args:
        delta (float): The time delta in nanoseconds
        byte_len (int): The amount of bytes downloaded
    """

    return byte_len / delta * 1e9 / 2**20


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

        match = re.match(r"(\d+_)?(\w+_)?(.+)", url)
        if not match:
            raise ValueError("Invalid DNS URL format")

        byte_len, uid, domain = match.groups()

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

        return DNSUrl(byte_len=byte_len, uid=uid, domain=domain)
