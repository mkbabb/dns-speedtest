# Default port to run the DNS server on
DEFAULT_PORT = 53
# The address to bind the DNS server to
DEFAULT_ADDRESS = ""
# The interface to use for the DNS packet capture
DEFAULT_INTERFACE = "enX0"

# Size in bytes of the buffer used to receive data from the network
RECV_BUFFER_SIZE = 2**20

# Default size in bytes of a DNS record for speed tests
RECORD_SIZE = 2**16 - 2**12
# RECORD_SIZE = 2**20

DNS_TTL = 1

# The domain name to use for the DNS server
DOMAIN_NAME = "friday.institute."
# The IP address of the DNS server
NS_1_IP = "100.28.199.23"

# Time in seconds for the refresh, retry, expire, and minimum fields of the SOA record
# REFRESH_TIME = 60 * 60 * 1
# RETRY_TIME = 60 * 60 * 3
# EXPIRE_TIME = 60 * 60 * 24
# MINIMUM_TIME = 60 * 60 * 1

REFRESH_TIME = 0  # No refresh
RETRY_TIME = 0  # No retry
EXPIRE_TIME = 0  # No expiration
MINIMUM_TIME = 0  # No minimum TTL for negative caching


# Size in bytes of the cache used to store chunks of data
CACHE_SIZE = 10 * RECORD_SIZE  # 10 times the normal record size
# Maximum size in bytes of a chunk of data to send in a TXT record
MAX_TXT_CHUNK_SIZE = 2**8 - 1
# Default filepath whereof to read for the random chunks
DEFAULT_CHUNK_FILEPATH = "./data/canto-5.txt"
