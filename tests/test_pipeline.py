import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.app.generator import generate_events
from backend.app.pipeline import detect_scans, parse_log, parse_source_allowlist
from backend.app.schemas import NetworkEvent


ROOT = Path(__file__).resolve().parents[1]


def test_event_normalizes_address_protocol_flags_and_timestamp() -> None:
    event = NetworkEvent(
        timestamp=datetime(2024, 1, 1),
        source_ip="2001:db8::1",
        destination_ip="192.0.2.1",
        protocol="TCP",
        tcp_flags="syn ack",
        sensor_type="test",
    )

    assert str(event.source_ip) == "2001:db8::1"
    assert event.protocol == "tcp"
    assert event.tcp_flags == ["ACK", "SYN"]
    assert event.timestamp.tzinfo == timezone.utc


def test_event_rejects_invalid_address_and_port() -> None:
    with pytest.raises(ValidationError):
        NetworkEvent(timestamp="2024-01-01T00:00:00Z", source_ip="999.1.1.1", destination_ip="192.0.2.1", protocol="tcp", sensor_type="test")
    with pytest.raises(ValidationError):
        NetworkEvent(timestamp="2024-01-01T00:00:00Z", source_ip="192.0.2.2", destination_ip="192.0.2.1", destination_port=70000, protocol="tcp", sensor_type="test")


@pytest.mark.parametrize("filename,format_name", [("zeek_conn.log", "zeek"), ("suricata_eve.json", "suricata"), ("sample_syslog.log", "firewall")])
def test_checked_in_samples_parse_to_canonical_events(filename: str, format_name: str) -> None:
    content = (ROOT / "port_scan_detection_lab" / "logs" / filename).read_text()
    events, errors = parse_log(content, format_name, filename)

    assert events
    assert not errors
    assert all(event.sensor_type == format_name for event in events)
    assert all(event.raw_event for event in events)


def test_malformed_records_are_reported_without_discarding_valid_events() -> None:
    content = '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"192.0.2.1","dest_ip":"192.0.2.2","proto":"TCP"}\nnot-json'

    events, errors = parse_log(content, "suricata")

    assert len(events) == 1
    assert len(errors) == 1
    assert errors[0]["line"] == 2


@pytest.mark.parametrize("scenario,expected_rule", [("syn", "tcp_syn_scan"), ("syn", "horizontal_port_scan"), ("connect", "tcp_connect_scan"), ("fin", "tcp_fin_scan"), ("null", "tcp_null_scan"), ("xmas", "tcp_xmas_scan"), ("sweep", "vertical_port_sweep"), ("low_slow", "low_and_slow_recon")])
def test_scan_scenarios_produce_explainable_alerts(scenario: str, expected_rule: str) -> None:
    events = generate_events(count=30, scenario=scenario, seed=10)

    alerts = detect_scans(events)

    matching = [alert for alert in alerts if alert.rule_id == expected_rule]
    assert matching
    assert matching[0].event_count >= 3
    assert matching[0].evidence
    assert matching[0].detection_reason


def test_slow_multiport_activity_is_labeled_as_a_heuristic() -> None:
    events = generate_events(count=30, scenario="syn", seed=11)
    events = [
        event.model_copy(update={"timestamp": event.timestamp + timedelta(seconds=index * 15 * 60 // len(events))})
        for index, event in enumerate(events)
    ]

    alerts = detect_scans(events)

    assert any(alert.rule_id == "low_and_slow_recon" for alert in alerts)


def test_synthetic_low_slow_dataset_is_labeled_and_spans_multiple_minutes() -> None:
    events = generate_events(count=30, scenario="low_slow", seed=12)

    assert {event.ground_truth for event in events} == {"malicious"}
    assert events[-1].timestamp - events[0].timestamp >= timedelta(minutes=5)
    assert any(alert.rule_id == "low_and_slow_recon" for alert in detect_scans(events))


def test_benign_and_single_events_do_not_create_scan_alerts() -> None:
    benign = generate_events(count=100, scenario="benign")
    single = generate_events(count=1, scenario="syn")

    assert detect_scans(benign) == []
    assert any(event.protocol == "udp" and event.event_type == "dns" for event in benign)
    assert all(event.tcp_flags is None for event in benign if event.protocol == "udp")
    assert detect_scans(single) == []


def test_detection_threshold_and_source_cidr_allowlist() -> None:
    events = generate_events(count=8, scenario="syn", seed=14)
    events = [
        NetworkEvent.model_validate({**event.model_dump(), "source_ip": "203.0.113.10"})
        if index < 4
        else event
        for index, event in enumerate(events)
    ]

    assert detect_scans(events, threshold=8) == []
    alerts = detect_scans(
        events,
        threshold=4,
        allowlisted_sources=parse_source_allowlist("198.51.100.0/24"),
    )

    assert alerts
    assert {alert.source_ip for alert in alerts} == {"203.0.113.10"}


def test_source_allowlist_accepts_ipv4_and_ipv6_and_rejects_invalid_entries() -> None:
    networks = parse_source_allowlist("192.0.2.1, 2001:db8::/32")

    assert ipaddress.ip_address("192.0.2.1") in networks[0]
    assert ipaddress.ip_address("2001:db8::1") in networks[1]
    assert parse_source_allowlist(None) == ()
    with pytest.raises(ValueError, match="invalid source allowlist entry"):
        parse_source_allowlist("192.0.2.0/24,not-an-ip")


def test_generator_is_repeatable_for_the_same_seed() -> None:
    first = generate_events(count=3, scenario="syn", seed=42)
    second = generate_events(count=3, scenario="syn", seed=42)

    assert [event.event_id for event in first] == [event.event_id for event in second]
    assert [event.destination_port for event in first] == [event.destination_port for event in second]


def test_synthetic_events_include_ground_truth_labels() -> None:
    benign = generate_events(count=3, scenario="benign", seed=1)
    malicious = generate_events(count=3, scenario="syn", seed=2)

    assert {event.ground_truth for event in benign} == {"benign"}
    assert {event.ground_truth for event in malicious} == {"malicious"}


def test_suricata_hex_flags_are_normalized_for_scan_detection() -> None:
    records = [
        '{"timestamp":"2024-01-01T00:00:%02dZ","src_ip":"198.51.100.10","dest_ip":"192.0.2.10","src_port":40000,"dest_port":%d,"proto":"TCP","event_type":"flow","tcp":{"tcp_flags":"02"}}'
        % (index, 20 + index)
        for index in range(8)
    ]

    events, errors = parse_log("\n".join(records), "suricata")

    assert not errors
    assert all(event.tcp_flags == ["SYN"] for event in events)
    assert all(event.event_type == "flow" for event in events)
    assert any(alert.rule_id == "tcp_syn_scan" for alert in detect_scans(events))


def test_unsupported_suricata_flag_encoding_is_reported() -> None:
    content = '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"192.0.2.1","dest_ip":"192.0.2.2","proto":"TCP","tcp":{"flags":"not-flags"}}'

    events, errors = parse_log(content, "suricata")

    assert not events
    assert len(errors) == 1
    assert "unsupported Suricata TCP flags" in errors[0]["message"]


@pytest.mark.parametrize(
    "content",
    [
        "[]",
        '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"192.0.2.1","dest_ip":"192.0.2.2","alert":[1]}',
        '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"192.0.2.1","dest_ip":"192.0.2.2","proto":"TCP","tcp":[1]}',
        '{"timestamp":"2024-01-01T00:00:00Z","src_ip":"192.0.2.1","dest_ip":"192.0.2.2","proto":"TCP","tcp":{"flags":"100"}}',
    ],
)
def test_malformed_suricata_objects_are_counted_not_raised(content: str) -> None:
    events, errors = parse_log(content, "suricata")

    assert not events
    assert len(errors) == 1