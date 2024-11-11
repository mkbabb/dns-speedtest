from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    case,
    BigInteger,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class DNSUrlsTable(Base):
    __tablename__ = "dns_urls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    byte_len: Mapped[int] = mapped_column(Integer)

    uid: Mapped[str] = mapped_column(Text)

    domain: Mapped[str] = mapped_column(Text)

    request: Mapped["RequestsTable"] = relationship(
        "RequestsTable", back_populates="dns_url", uselist=False
    )


class SpeedtestResultsTable(Base):
    __tablename__ = "speedtest_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("requests.id"))
    request: Mapped["RequestsTable"] = relationship(
        "RequestsTable", back_populates="speedtest_result"
    )
    # Latency in nanoseconds
    latency: Mapped[float] = mapped_column(Float)
    # Download speed in MB/s
    throughput: Mapped[float] = mapped_column(Float)


class IPInfoTable(Base):
    __tablename__ = "ipinfo"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    request: Mapped["RequestsTable"] = relationship(
        "RequestsTable", back_populates="ipinfo"
    )

    ip_address: Mapped[str] = mapped_column(Text)
    location: Mapped[str] = mapped_column(Text)
    org: Mapped[str] = mapped_column(Text)
    postal: Mapped[str] = mapped_column(Text)
    city: Mapped[str] = mapped_column(Text)
    region: Mapped[str] = mapped_column(Text)
    country: Mapped[str] = mapped_column(Text)


class PacketCaptureResultsTable(Base):
    __tablename__ = "packet_capture_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    transaction_uuid: Mapped[str] = mapped_column(String(64), nullable=True, index=True)

    timestamp: Mapped[int] = mapped_column(BigInteger, nullable=False)

    size: Mapped[int] = mapped_column(Integer, nullable=False)

    src_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int] = mapped_column(Integer)

    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)

    protocol: Mapped[str] = mapped_column(String(10))
    flags: Mapped[str] = mapped_column(String(20), nullable=True)

    sequence_number: Mapped[int] = mapped_column(Integer, nullable=True)
    acknowledgment_number: Mapped[int] = mapped_column(Integer, nullable=True)

    capture_time: Mapped[datetime] = mapped_column(DateTime)
    sent_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    raw_data: Mapped["PacketCaptureRawData"] = relationship(
        "PacketCaptureRawData", back_populates="capture_result"
    )


class PacketCaptureRawData(Base):
    __tablename__ = 'packet_capture_raw_data'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    packet_capture_result_id: Mapped[int] = mapped_column(
        ForeignKey('packet_capture_results.id'), nullable=False
    )

    capture_time: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    packet_json: Mapped[str] = mapped_column(JSON, nullable=True)
    packet_binary: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)

    # Relationship to the results table
    capture_result = relationship(
        "PacketCaptureResultsTable", back_populates="raw_data"
    )


class RequestsTable(Base):
    __tablename__ = "requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol: Mapped[str] = mapped_column(Text)
    qtype: Mapped[str] = mapped_column(Text)
    start_time: Mapped[datetime] = mapped_column(DateTime)
    end_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    ip: Mapped[str] = mapped_column(Text)
    dns_url_id: Mapped[int] = mapped_column(ForeignKey("dns_urls.id"), nullable=True)
    ipinfo_id: Mapped[int] = mapped_column(ForeignKey("ipinfo.id"), nullable=True)

    transaction_uuid: Mapped[str] = mapped_column(String(64), nullable=True)

    dns_url: Mapped["DNSUrlsTable"] = relationship(
        "DNSUrlsTable", back_populates="request"
    )
    speedtest_result: Mapped["SpeedtestResultsTable"] = relationship(
        "SpeedtestResultsTable", back_populates="request", uselist=False
    )
    ipinfo: Mapped["IPInfoTable"] = relationship(
        "IPInfoTable", back_populates="request", uselist=False
    )
