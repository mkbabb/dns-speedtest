# Size in bytes of the buffer used to receive data from the network
RECV_BUFFER_SIZE = 2**13

# Default size in bytes of a DNS record for speed tests
RECORD_SIZE = 2**16 - 2**12

# Default port to run the DNS server on
DEFAULT_PORT = 53
# The address to bind the DNS server to
DEFAULT_ADDRESS = "0.0.0.0"

# Size in bytes of the cache used to store chunks of data
CACHE_SIZE = 10 * RECORD_SIZE  # 10 times the normal record size

# Maximum size in bytes of a chunk of data to send in a TXT record
MAX_TXT_CHUNK_SIZE = 255

# The name of the NS record(s) for the DNS server
NS_RECORD_NAME = "ns-1.friday.institute."
