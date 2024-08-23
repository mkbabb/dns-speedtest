from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, case
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


class RequestsTable(Base):
    __tablename__ = "requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    protocol: Mapped[str] = mapped_column(Text)
    qtype: Mapped[str] = mapped_column(Text)

    start_time: Mapped[datetime] = mapped_column(DateTime)
    end_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    ip: Mapped[str] = mapped_column(Text)

    dns_url_id: Mapped[int] = mapped_column(ForeignKey("dns_urls.id"))

    dns_url: Mapped["DNSUrlsTable"] = relationship(
        "DNSUrlsTable", back_populates="request"
    )

    speedtest_result: Mapped["SpeedtestResultsTable"] = relationship(
        "SpeedtestResultsTable", back_populates="request", uselist=False
    )


class SpeedtestResultsTable(Base):
    __tablename__ = "speedtest_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    request_id: Mapped[int] = mapped_column(ForeignKey("requests.id"))

    request: Mapped[RequestsTable] = relationship(
        "RequestsTable", back_populates="speedtest_result"
    )

    # Time delta in nanoseconds
    delta: Mapped[float] = mapped_column(Float)

    # Download speed in MB/s
    dl_speed: Mapped[float] = mapped_column(Float)
