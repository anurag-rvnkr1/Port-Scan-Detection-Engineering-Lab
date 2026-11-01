from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


Protocol = Literal["tcp", "udp", "icmp", "other"]
Severity = Literal["Informational", "Low", "Medium", "High", "Critical"]


class NetworkEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    timestamp: datetime
    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=128)
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol
    tcp_flags: list[str] | None = None
    event_type: str = Field(default="connection", min_length=1, max_length=80)
    connection_state: str | None = Field(default=None, max_length=80)
    sensor_type: str = Field(min_length=1, max_length=40)
    source_file: str | None = Field(default=None, max_length=255)
    scenario_id: str | None = Field(default=None, max_length=80)
    raw_event: dict = Field(default_factory=dict)
    alert_signature: str | None = Field(default=None, max_length=255)
    severity: str | None = Field(default=None, max_length=40)
    confidence: float | None = Field(default=None, ge=0, le=1)
    scan_type: str | None = Field(default=None, max_length=40)
    direction: str | None = Field(default=None, max_length=40)
    tags: list[str] = Field(default_factory=list)
    ground_truth: Literal["benign", "malicious"] | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_to_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("protocol", mode="before")
    @classmethod
    def normalize_protocol(cls, value: object) -> str:
        normalized = str(value).strip().lower()
        if normalized in {"tcp", "udp", "icmp", "icmpv6", "icmp6"}:
            return "icmp" if normalized in {"icmpv6", "icmp6"} else normalized
        return "other"

    @field_validator("tcp_flags", mode="before")
    @classmethod
    def normalize_flags(cls, value: object) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, str):
            if value.strip().upper() in {"", "NONE", "0", "-"}:
                return []
            value = value.replace(",", " ").split()
        return sorted({str(flag).strip().upper() for flag in value if str(flag).strip()})


class SecurityAlert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    source_ip: str
    destination_ip: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    first_seen: datetime
    last_seen: datetime
    event_count: int = Field(ge=1)
    unique_ports: list[int] = Field(default_factory=list)
    unique_destinations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    detection_reason: str
    recommended_actions: list[str] = Field(default_factory=list)
    status: str = "New"
    scan_type: str
