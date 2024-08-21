import time
import uuid
import random
import string
import statistics
from dnslib import *
from dnslib.server import DNSServer
import threading
import argparse
from loguru import logger

class SpeedTestResolver:
    def __init__(self, record_sizes):
        self.record_sizes = record_sizes
        self.response_times = []
        self.lock = threading.Lock()

    def resolve(self, request, handler):
        start_time = time.perf_counter_ns()
        
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        
        size = random.choice(self.record_sizes)
        unique_id = uuid.uuid4()
        timestamp = time.perf_counter_ns()
        record_name = f"{unique_id}-{timestamp}-{size}"
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        
        if qtype == 'TXT':
            reply.add_answer(RR(rname=qname, rtype=QTYPE.TXT, rclass=1, ttl=0,
                                rdata=TXT(record_name + "\n" + content)))
        
        end_time = time.perf_counter_ns()
        response_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        with self.lock:
            self.response_times.append(response_time)
        
        logger.info(f"Resolved query for {qname} with {size} bytes in {response_time:.2f} ms")
        return reply

    def get_stats(self):
        with self.lock:
            if not self.response_times:
                return "No data available yet."
            
            stats = f"""
            Total Queries: {len(self.response_times)}
            Min Response Time: {min(self.response_times):.2f} ms
            Max Response Time: {max(self.response_times):.2f} ms
            Average Response Time: {statistics.mean(self.response_times):.2f} ms
            Median Response Time: {statistics.median(self.response_times):.2f} ms
            """
            logger.info("Current Statistics:\n" + stats)
            return stats

def run_server(port, record_sizes):
    resolver = SpeedTestResolver(record_sizes)
    server = DNSServer(resolver, port=port, address="0.0.0.0")
    
    logger.info(f"Starting DNS Speed Test Server on port {port}...")
    server.start_thread()
    
    try:
        while True:
            time.sleep(10)
            resolver.get_stats()
    except KeyboardInterrupt:
        logger.info("Server stopping due to keyboard interrupt...")
    finally:
        server.stop()
        logger.info("Server stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS-based Speed Test Server")
    parser.add_argument("--port", type=int, default=53, help="Port to run the DNS server on")
    parser.add_argument("--sizes", type=int, nargs="+", default=[1024, 10240, 102400, 1048576],
                        help="List of record sizes to use (in bytes)")
    parser.add_argument("--log-file", type=str, default="./log/dns_speed_test.log",
                        help="Path to the log file")
    
    args = parser.parse_args()
    
    # Configure Loguru
    logger.add(sys.stderr, format="{time} {level} {message}", level="INFO")
    logger.add(args.log_file, rotation="10 MB", compression="zip", level="INFO")
    
    logger.info(f"Starting DNS Speed Test Server with sizes: {args.sizes}")
    run_server(args.port, args.sizes)