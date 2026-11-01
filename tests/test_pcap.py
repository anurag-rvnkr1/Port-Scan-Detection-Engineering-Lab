from __future__ import annotations

from io import BytesIO
import socket

import dpkt
import pytest

from backend.app.pcap import PcapFormatError, parse_pcap


def _capture_packet(source: str, destination: str, protocol: str, port: int = 443) -> bytes:
    if ":" in source:
        network = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, source),
            dst=socket.inet_pton(socket.AF_INET6, destination),
            nxt=dpkt.ip.IP_PROTO_TCP if protocol == "tcp" else dpkt.ip.IP_PROTO_UDP,
        )
    else:
        network = dpkt.ip.IP(
            src=socket.inet_aton(source),
            dst=socket.inet_aton(destination),
            p=dpkt.ip.IP_PROTO_TCP if protocol == "tcp" else dpkt.ip.IP_PROTO_UDP,
        )

    if protocol == "tcp":
        transport = dpkt.tcp.TCP(sport=45000, dport=port, flags=dpkt.tcp.TH_SYN)
    else:
        transport = dpkt.udp.UDP(sport=45000, dport=port)
    network.data = transport
    network.len = len(network)
    frame = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP6 if ":" in source else dpkt.ethernet.ETH_TYPE_IP,
        data=network,
    )
    return bytes(frame)


def _pcap(*packets: tuple[str, str, str, int]) -> bytes:
    buffer = BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    for index, (source, destination, protocol, port) in enumerate(packets):
        writer.writepkt(
            _capture_packet(source, destination, protocol, port),
            ts=1_700_000_000 + index,
        )
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("source", "destination", "protocol"),
    [
        ("192.0.2.10", "198.51.100.20", "tcp"),
        ("2001:db8::10", "2001:db8::20", "udp"),
    ],
)
def test_pcap_parser_normalizes_address_family_and_transport(source, destination, protocol) -> None:
    capture = _pcap((source, destination, protocol, 443))

    events, malformed = parse_pcap(capture, "traffic.pcap")

    assert malformed == 0
    assert len(events) == 1
    assert str(events[0].source_ip) == source
    assert str(events[0].destination_ip) == destination
    assert events[0].protocol == protocol
    assert events[0].sensor_type == "pcap"
    assert events[0].source_file == "traffic.pcap"
    assert events[0].tcp_flags == ["SYN"] if protocol == "tcp" else events[0].tcp_flags is None


def test_pcap_parser_rejects_invalid_capture_header() -> None:
    with pytest.raises(PcapFormatError, match="valid PCAP"):
        parse_pcap(b"not-a-pcap", "bad.pcap")
