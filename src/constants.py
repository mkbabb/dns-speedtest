# Size in bytes of the buffer used to receive data from the network
RECV_BUFFER_SIZE = 2**13

# Default size in bytes of a DNS record for speed tests
RECORD_SIZE = 2**16 - 2**12

# Default port to run the DNS server on
DEFAULT_PORT = 53
# The address to bind the DNS server to
DEFAULT_ADDRESS = "127.0.0.1"

# The domain name to use for the DNS server
DOMAIN_NAME = "friday.institute."
# Time to live of the DNS records
TTL = 60 * 5

# The serial number of the SOA record
SERIAL_NUMBER = 201307231

# Time in seconds for the refresh, retry, expire, and minimum fields of the SOA record
REFRESH_TIME = 60 * 60 * 1
RETRY_TIME = 60 * 60 * 3
EXPIRE_TIME = 60 * 60 * 24
MINIMUM_TIME = 60 * 60 * 1

# Size in bytes of the cache used to store chunks of data
CACHE_SIZE = 10 * RECORD_SIZE  # 10 times the normal record size

# Maximum size in bytes of a chunk of data to send in a TXT record
MAX_TXT_CHUNK_SIZE = 255


# Default filepath whereof to read for the random chunks
DEFAULT_CHUNK_FILEPATH = "./data/canto-5.txt"
