import argparse
import sys
from pathlib import Path
import toml
from loguru import logger
from sqlalchemy import URL, create_engine
from src.models import Base
from src.constants import CACHE_SIZE, DEFAULT_INTERFACE, DEFAULT_PORT
from src.server.speedtest import run_server
from src.utils import RECORD_SIZE
import ipinfo
from typing import Any


def configure_logging(log_dir: Path, log_configs: list[dict]) -> None:
    logger.add(sys.stderr, format="{time} {level} {message}", level="INFO")

    for config in log_configs:
        logger.add(
            log_dir / config['filename'],
            rotation="10 MB",
            compression="zip",
            level="INFO",
            filter=config.get('filter', None),
        )


def load_config(config_file: Path) -> dict:
    try:
        return toml.load(config_file)
    except (toml.TomlDecodeError, FileNotFoundError) as e:
        logger.error(f"Config error: {e}")
        sys.exit(1)


def create_db_engine(config: dict) -> URL:
    db_config = config['mysql']
    url = URL.create(
        "mysql+mysqlconnector",
        username=db_config['username'],
        password=db_config['password'],
        host=db_config['host'],
        port=int(db_config['port']),
        database=db_config['database'],
    )
    return create_engine(url)


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS-based Speed Test Server")
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="Port to run the DNS server on"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="./log/dns_speed_test.log",
        help="Path to the log file",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default="./auth/config.toml",
        help="Path to the TOML configuration file",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=DEFAULT_INTERFACE,
        help="Interface to capture packets",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        default=True,
        help="Clear database and log files on startup",
    )
    args = parser.parse_args()

    log_file_path = Path(args.log_file)
    log_dir = log_file_path.parent

    log_configs = [
        {'filename': log_file_path.name},
        {
            'filename': 'pcap.log',
            'filter': lambda record: record["extra"].get("pcap") == True,
        },
        {
            'filename': 'pcap2.log',
            'filter': lambda record: record["extra"].get("pcap2") == True,
        },
    ]

    config = load_config(args.config)

    engine = create_db_engine(config)

    if args.purge:
        logger.info("Clearing database tables")
        Base.metadata.drop_all(engine)
        # Clear log dir:
        for log_file in log_dir.glob("*.log*"):
            log_file.unlink()

    configure_logging(log_dir, log_configs)

    Base.metadata.create_all(engine)

    ipinfo_handler = ipinfo.getHandler(config['ipinfo']['token'])
    logger.info(
        f"Starting DNS Speed Test Server with fixed record size: {RECORD_SIZE} bytes"
    )

    run_server(
        engine=engine,
        ipinfo_handler=ipinfo_handler,
        interface=args.interface,
        port=args.port,
        cache_size=CACHE_SIZE,
    )


if __name__ == "__main__":
    main()
