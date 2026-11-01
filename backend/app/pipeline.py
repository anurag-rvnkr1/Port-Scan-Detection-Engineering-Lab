from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from pydantic import ValidationError

from backend.app.schemas import NetworkEvent, SecurityAlert


DEFAULT_THRESHOLD = 8
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
RECOMMENDED_ACTIONS = [
    "Confirm whether the source is authorized for network discovery.",
    "Review the source and destination timeline alongside firewall and endpoint telemetry.",
    "Validate targeted services with the system owner before escalation.",
]


def parse_source_allowlist(value: str | None) -> tuple[IPNetwork, ...]:
    networks: list[IPNetwork] = []
    for item in (value or "").split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError as error:
            raise ValueError(f"invalid source allowlist entry: {candidate}") from error
    return tuple(networks)


def _stable_event_id(source_file: str, line_number: int, raw: str) -> str:
    return hashlib.sha256(f"{source_file}:{line_number}:{raw}".encode()).hexdigest()


def _event(record: dict, sensor: str, source_file: str, line_number: int, raw: str) -> NetworkEvent:
    source = record.get("source_ip", record.get("src_ip", record.get("id.orig_h")))
    destination = record.get("destination_ip", record.get("dest_ip", record.get("id.resp_h")))
    source_port = record.get("source_port", record.get("src_port", record.get("id.orig_p")))
    destination_port = record.get("destination_port", record.get("dest_port", record.get("id.resp_p")))
    if source is None or destination is None:
        raise ValueError("record is missing source or destination address")

    timestamp = record.get("timestamp", record.get("ts"))
    if isinstance(timestamp, (int, float)) or (isinstance(timestamp, str) and timestamp.replace(".", "", 1).isdigit()):
        timestamp = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)

    alert = record.get("alert")
    if alert is None:
        alert = {}
    if not isinstance(alert, dict):
        raise ValueError("alert metadata must be an object")
    tcp = record.get("tcp")
    if tcp is None:
        tcp = {}
    if not isinstance(tcp, dict):
        raise ValueError("tcp metadata must be an object")
    proto = record.get("protocol", record.get("proto", "other"))
    flags = tcp.get("flags", tcp.get("tcp_flags", record.get("tcp_flags")))
    if sensor == "suricata":
        flags = _suricata_flags(flags)
    normalized = {
        "timestamp": timestamp,
        "event_id": str(record.get("event_id") or record.get("uid") or _stable_event_id(source_file, line_number, raw)),
        "source_ip": source,
        "destination_ip": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": proto,
        "tcp_flags": flags,
        "event_type": record.get("event_type", record.get("type", "connection")),
        "connection_state": record.get("connection_state", record.get("conn_state", tcp.get("state"))),
        "sensor_type": sensor,
        "source_file": source_file,
        "scenario_id": record.get("scenario_id"),
        "raw_event": record,
        "alert_signature": alert.get("signature"),
        "severity": str(alert.get("severity")) if alert.get("severity") is not None else None,
    }
    return NetworkEvent.model_validate(normalized)


def _suricata_flags(value: object) -> object:
    if not isinstance(value, str):
        return value
    flags = value.strip().upper()
    if flags in {"", "-", "NONE"}:
        return []
    names = {1: "FIN", 2: "SYN", 4: "RST", 8: "PSH", 16: "ACK", 32: "URG", 64: "ECE", 128: "CWR"}
    tokens = {token for token in re.split(r"[\s,|]+", flags) if token}
    if tokens and tokens <= set(names.values()):
        return sorted(tokens)
    try:
        mask = int(flags, 16)
    except ValueError:
        letters = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
        if not set(flags) <= set(letters):
            raise ValueError(f"unsupported Suricata TCP flags: {value}")
        return sorted({letters[letter] for letter in flags})
    if mask < 0 or mask & ~0xFF:
        raise ValueError(f"unsupported Suricata TCP flag mask: {value}")
    return sorted(name for bit, name in names.items() if mask & bit)


def parse_log(
    content: str,
    format_name: str,
    source_file: str = "upload",
    line_offset: int = 0,
) -> tuple[list[NetworkEvent], list[dict]]:
    format_name = format_name.lower()
    events: list[NetworkEvent] = []
    errors: list[dict] = []
    zeek_fields: list[str] | None = None

    for line_number, raw_line in enumerate(content.splitlines(), start=line_offset + 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            if format_name == "suricata":
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("JSON log record must be an object")
                sensor = "suricata"
            elif format_name == "zeek":
                if line.startswith("#fields"):
                    zeek_fields = line.split("\t")[1:]
                    continue
                if line.startswith("#"):
                    continue
                if not zeek_fields:
                    raise ValueError("Zeek file has no #fields header")
                values = raw_line.rstrip("\r\n").split("\t")
                if len(values) != len(zeek_fields):
                    raise ValueError("Zeek row does not match its #fields header")
                record = dict(zip(zeek_fields, values, strict=True))
                if record.get("ts") in {"-", "(empty)"}:
                    raise ValueError("Zeek row has no timestamp")
                if record.get("id.orig_p") in {"-", "(empty)"}:
                    record["id.orig_p"] = None
                if record.get("id.resp_p") in {"-", "(empty)"}:
                    record["id.resp_p"] = None
                sensor = "zeek"
            elif format_name == "firewall":
                record = _parse_firewall_line(line)
                sensor = "firewall"
            else:
                raise ValueError("format must be zeek, suricata, or firewall")
            events.append(_event(record, sensor, source_file, line_number, raw_line))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, ValidationError, OverflowError) as error:
            errors.append({"line": line_number, "message": str(error)})

    return events, errors


def _parse_firewall_line(line: str) -> dict:
    match = re.match(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+", line)
    fields = dict(re.findall(r"\b(SRC|DST|SPT|DPT|PROTO)=([^\s]+)", line))
    if not match or "SRC" not in fields or "DST" not in fields:
        raise ValueError("unsupported firewall record; expected syslog timestamp and SRC/DST fields")
    timestamp = datetime.strptime(
        f"{datetime.now(timezone.utc).year} {match['month']} {match['day']} {match['clock']}",
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=timezone.utc)
    flag_tokens = {token for token in re.findall(r"\b[A-Z]+\b", line) if token in {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"}}
    return {
        "timestamp": timestamp,
        "source_ip": fields["SRC"],
        "destination_ip": fields["DST"],
        "source_port": fields.get("SPT"),
        "destination_port": fields.get("DPT"),
        "protocol": fields.get("PROTO", "other"),
        "tcp_flags": sorted(flag_tokens) if fields.get("PROTO", "").upper() == "TCP" else None,
        "event_type": "firewall",
        "connection_state": "blocked" if "BLOCK" in line else "observed",
    }


def detect_scans(
    events: Iterable[NetworkEvent],
    threshold: int = DEFAULT_THRESHOLD,
    allowlisted_sources: Iterable[IPNetwork] = (),
) -> list[SecurityAlert]:
    if threshold < 3:
        raise ValueError("threshold must be at least 3 events")

    allowlisted_sources = tuple(allowlisted_sources)
    events = [
        event
        for event in events
        if not any(event.source_ip in network for network in allowlisted_sources)
    ]
    groups: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
    for event in events:
        if event.protocol == "tcp" and event.destination_port is not None:
            groups[(str(event.source_ip), str(event.destination_ip))].append(event)

    alerts: list[SecurityAlert] = []
    for (source, destination), records in groups.items():
        ports = {record.destination_port for record in records if record.destination_port is not None}
        if len(ports) >= threshold:
            alerts.append(_make_alert("horizontal_port_scan", "Horizontal port scan", source, destination, records, sorted(ports), "syn"))

        connected_records = [
            record
            for record in records
            if (record.connection_state or "").upper() in {"SF", "S1", "ESTABLISHED", "CONNECTED", "OPEN"}
        ]
        connected_ports = {record.destination_port for record in connected_records if record.destination_port is not None}
        if len(connected_ports) >= threshold:
            alerts.append(_make_alert("tcp_connect_scan", "TCP connect scan", source, destination, connected_records, sorted(connected_ports), "connect"))

        ordered_records = sorted(records, key=lambda event: event.timestamp)
        elapsed = ordered_records[-1].timestamp - ordered_records[0].timestamp
        if len(ports) >= threshold and elapsed >= timedelta(minutes=5):
            alerts.append(_make_alert("low_and_slow_recon", "Low-and-slow reconnaissance", source, destination, ordered_records, sorted(ports), "low_and_slow"))

        syn_records = [record for record in records if record.tcp_flags is not None and "SYN" in record.tcp_flags and "ACK" not in record.tcp_flags]
        syn_ports = {record.destination_port for record in syn_records if record.destination_port is not None}
        if len(syn_ports) >= threshold:
            alerts.append(_make_alert("tcp_syn_scan", "TCP SYN scan", source, destination, syn_records, sorted(syn_ports), "syn"))

        for rule_id, rule_name, expected_flags, scan_type in (
            ("tcp_fin_scan", "TCP FIN scan", {"FIN"}, "fin"),
            ("tcp_null_scan", "TCP NULL scan", set(), "null"),
            ("tcp_xmas_scan", "TCP XMAS scan", {"FIN", "PSH", "URG"}, "xmas"),
        ):
            matching = [record for record in records if record.tcp_flags is not None and set(record.tcp_flags) == expected_flags]
            matching_ports = {record.destination_port for record in matching if record.destination_port is not None}
            if len(matching) >= 3 and len(matching_ports) >= 3:
                alerts.append(_make_alert(rule_id, rule_name, source, destination, matching, sorted(matching_ports), scan_type))

    by_source_port: dict[tuple[str, int], list[NetworkEvent]] = defaultdict(list)
    for event in events:
        if event.protocol == "tcp" and event.destination_port is not None:
            by_source_port[(str(event.source_ip), event.destination_port)].append(event)
    for (source, port), records in by_source_port.items():
        destinations = {str(record.destination_ip) for record in records}
        if len(destinations) >= threshold:
            alerts.append(_make_alert("vertical_port_sweep", "Vertical port sweep", source, "multiple", records, [port], "sweep", sorted(destinations)))
    return alerts


def _make_alert(rule_id: str, name: str, source: str, destination: str, records: list[NetworkEvent], ports: list[int], scan_type: str, destinations: list[str] | None = None) -> SecurityAlert:
    ordered = sorted(records, key=lambda event: event.timestamp)
    first_seen, last_seen = ordered[0].timestamp, ordered[-1].timestamp
    identity = f"{rule_id}|{source}|{destination}|{'|'.join(event.event_id for event in ordered)}"
    alert_id = hashlib.sha256(identity.encode()).hexdigest()[:32]
    severity = "Critical" if len(ports) >= 50 else "High" if len(ports) >= 20 else "Medium"
    confidence = min(0.99, 0.65 + max(0, len(ports) - DEFAULT_THRESHOLD) * 0.01)
    return SecurityAlert(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_name=name,
        source_ip=source,
        destination_ip=destination,
        severity=severity,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=len(ordered),
        unique_ports=ports,
        unique_destinations=destinations or [destination],
        evidence=[event.event_id for event in ordered],
        detection_reason=(
            f"{len(ordered)} TCP events from {source} matched {name}; "
            f"{len(destinations or [destination])} destination host(s) and {len(ports)} distinct port(s) observed."
        ),
        recommended_actions=RECOMMENDED_ACTIONS,
        scan_type=scan_type,
    )