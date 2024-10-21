import argparse
import sys
from pathlib import Path

import toml
from loguru import logger
from sqlalchemy import URL, create_engine

from src.models import Base
from src.constants import CACHE_SIZE, DEFAULT_PORT
from src.server.speedtest import run_server
from src.utils import RECORD_SIZE
import ipinfo


def load_config(config_file: Path) -> dict:
    try:
        return toml.load(config_file)
    except toml.TomlDecodeError as e:
        logger.error(f"Error decoding TOML file: {e}")
        sys.exit(1)
    except FileNotFoundError:
        logger.error(f"Config file not found: {config_file}")
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

    args = parser.parse_args()

    log_file_path = Path(args.log_file)

    # Configure Loguru
    logger.add(sys.stderr, format="{time} {level} {message}", level="INFO")
    logger.add(log_file_path, rotation="10 MB", compression="zip", level="INFO")
    # pcap log
    logger.add(
        log_file_path.parent / "pcap.log",
        rotation="10 MB",
        compression="zip",
        level="INFO",
        filter=lambda record: record["extra"].get("pcap") == True,
    )

    # Load configuration
    config = load_config(args.config)

    # Create database engine
    engine = create_db_engine(config)

    # delete all tables
    Base.metadata.drop_all(engine)
    # Create tables
    Base.metadata.create_all(engine)

    ipinfo_handler = ipinfo.getHandler(config['ipinfo']['token'])

    logger.info(
        f"Starting DNS Speed Test Server with fixed record size: {RECORD_SIZE} bytes"
    )

    run_server(
        port=args.port,
        cache_size=CACHE_SIZE,
        engine=engine,
        ipinfo_handler=ipinfo_handler,
    )


if __name__ == "__main__":
    main()
