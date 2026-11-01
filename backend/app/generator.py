from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from backend.app.schemas import NetworkEvent


SCENARIOS = {"syn", "connect", "sweep", "fin", "null", "xmas", "low_slow", "benign"}
SCENARIO_SOURCES = {
    "benign": "198.51.100.20",
    "syn": "198.51.100.27",
    "connect": "198.51.100.28",
    "sweep": "198.51.100.29",
    "fin": "198.51.100.30",
    "null": "198.51.100.31",
    "xmas": "198.51.100.32",
    "low_slow": "198.51.100.33",
}


def generate_events(count: int = 40, scenario: str = "syn", seed: int = 7) -> list[NetworkEvent]:
    if not 1 <= count <= 5000:
        raise ValueError("count must be between 1 and 5000")
    if scenario not in SCENARIOS:
        raise ValueError(f"scenario must be one of: {', '.join(sorted(SCENARIOS))}")

    randomizer = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    events = []
    for index in range(count):
        destination_index = index % 20 if scenario == "sweep" else 0
        if scenario == "benign":
            destination_port, protocol = randomizer.choice([(53, "udp"), (80, "tcp"), (443, "tcp"), (22, "tcp")])
            flags = None if protocol == "udp" else ["SYN", "ACK"]
            state = "SF"
            event_type = "dns" if destination_port == 53 else "connection"
        else:
            destination_port = 80 if scenario == "sweep" else 20 + index
            protocol = "tcp"
            flags = {
                "syn": ["SYN"],
                "low_slow": ["SYN"],
                "connect": ["SYN", "ACK"],
                "sweep": ["SYN"],
                "fin": ["FIN"],
                "null": [],
                "xmas": ["FIN", "PSH", "URG"],
            }[scenario]
            state = "SF" if scenario == "connect" else "S0"
            event_type = "connection"
        events.append(
            NetworkEvent(
                timestamp=start + (
                    timedelta(minutes=index)
                    if scenario == "low_slow"
                    else timedelta(milliseconds=index * 250)
                ),
                event_id=f"synthetic-{seed}-{scenario}-{index:05d}",
                source_ip=SCENARIO_SOURCES[scenario],
                destination_ip=f"192.0.2.{destination_index + 10}",
                source_port=45000 + (index % 20000),
                destination_port=destination_port,
                protocol=protocol,
                tcp_flags=flags,
                event_type=event_type,
                connection_state=state,
                sensor_type="simulator",
                scenario_id=f"synthetic-{scenario}",
                raw_event={"generated": True, "scenario": scenario, "sequence": index},
                scan_type=scenario,
                tags=["simulated"],
                ground_truth="benign" if scenario == "benign" else "malicious",
            )
        )
    return events