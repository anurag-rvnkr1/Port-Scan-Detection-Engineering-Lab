from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO

import dpkt

from backend.app.schemas import NetworkEvent


MAX_PCAP_PACKETS = 20_000
DLT_EN10MB = 1
DLT_RAW = 12
DLT_RAW_ALT = 101

_TCP_FLAG_NAMES = (
    (dpkt.tcp.TH_FIN, "FIN"),
    (dpkt.tcp.TH_SYN, "SYN"),
    (dpkt.tcp.TH_RST, "RST"),
    (dpkt.tcp.TH_PUSH, "PSH"),
    (dpkt.tcp.TH_ACK, "ACK"),
    (dpkt.tcp.TH_URG, "URG"),
    (dpkt.tcp.TH_ECE, "ECE"),
    (dpkt.tcp.TH_CWR, "CWR"),
)


class PcapFormatError(ValueError):
    pass


class PcapRecordLimitError(ValueError):
    pass


def _reader(content: bytes):
    stream = BytesIO(content)
    if content.startswith(b"\x0a\x0d\x0d\x0a"):
        return dpkt.pcapng.Reader(stream)
    return dpkt.pcap.Reader(stream)


def _network_packet(frame: bytes, datalink: int):
    if datalink == DLT_EN10MB:
        return dpkt.ethernet.Ethernet(frame).data
    if datalink in {DLT_RAW, DLT_RAW_ALT} and frame:
        version = frame[0] >> 4
        if version == 4:
            return dpkt.ip.IP(frame)
        if version == 6:
            return dpkt.ip6.IP6(frame)
    raise PcapFormatError("Only Ethernet and raw IPv4/IPv6 PCAP link types are supported")


def parse_pcap(content: bytes, source_file: str) -> tuple[list[NetworkEvent], int]:
    try:
        capture = _reader(content)
        datalink = capture.datalink()
    except (ValueError, dpkt.UnpackError, IndexError) as error:
        raise PcapFormatError("Capture is not a valid PCAP or PCAPNG file") from error
    if datalink not in {DLT_EN10MB, DLT_RAW, DLT_RAW_ALT}:
        raise PcapFormatError(f"Unsupported PCAP link type: {datalink}")

    events: list[NetworkEvent] = []
    malformed = 0
    for index, (timestamp, packet) in enumerate(capture):
        if index >= MAX_PCAP_PACKETS:
            raise PcapRecordLimitError(f"Capture exceeds the {MAX_PCAP_PACKETS} packet limit")
        try:
            network = _network_packet(packet, datalink)
            if isinstance(network, dpkt.ip.IP):
                source_ip = dpkt.utils.inet_to_str(network.src)
                destination_ip = dpkt.utils.inet_to_str(network.dst)
            elif isinstance(network, dpkt.ip6.IP6):
                source_ip = dpkt.utils.inet_to_str(network.src)
                destination_ip = dpkt.utils.inet_to_str(network.dst)
            else:
                continue

            transport = network.data
            source_port = None
            destination_port = None
            flags = None
            if isinstance(transport, dpkt.tcp.TCP):
                protocol = "tcp"
                source_port = transport.sport
                destination_port = transport.dport
                flags = [name for mask, name in _TCP_FLAG_NAMES if transport.flags & mask]
            elif isinstance(transport, dpkt.udp.UDP):
                protocol = "udp"
                source_port = transport.sport
                destination_port = transport.dport
            elif isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                protocol = "icmp"
            else:
                protocol = "other"

            timestamp_utc = datetime.fromtimestamp(timestamp, timezone.utc)
            event_id = sha256(
                f"{index}:{timestamp:.9f}:".encode("ascii") + packet
            ).hexdigest()
            events.append(
                NetworkEvent(
                    event_id=f"pcap-{event_id}",
                    timestamp=timestamp_utc,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    source_port=source_port,
                    destination_port=destination_port,
                    protocol=protocol,
                    tcp_flags=flags,
                    event_type="network_packet",
                    sensor_type="pcap",
                    source_file=source_file,
                    raw_event={
                        "capture_packet_index": index,
                        "captured_bytes": len(packet),
                        "link_type": datalink,
                    },
                )
            )
        except (dpkt.UnpackError, ValueError, IndexError, TypeError):
            malformed += 1
    return events, malformed
