import argparse
import sys
from pathlib import Path

import toml
from loguru import logger
from sqlalchemy import URL, create_engine

from models import Base
from src.constants import CACHE_SIZE, DEFAULT_PORT
from src.server import run_server
from src.utils import RECORD_SIZE


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

    # Configure Loguru
    logger.add(sys.stderr, format="{time} {level} {message}", level="INFO")
    logger.add(args.log_file, rotation="10 MB", compression="zip", level="INFO")

    # Load configuration
    config = load_config(args.config)

    # Create database engine
    engine = create_db_engine(config)

    # Create tables
    Base.metadata.create_all(engine)

    logger.info(
        f"Starting DNS Speed Test Server with fixed record size: {RECORD_SIZE} bytes"
    )

    run_server(
        port=args.port,
        engine=engine,
        cache_size=CACHE_SIZE,
    )


if __name__ == "__main__":
    main()
