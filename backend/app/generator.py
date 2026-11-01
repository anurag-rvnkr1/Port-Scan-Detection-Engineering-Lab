from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from backend.app.schemas import NetworkEvent


SCENARIOS = {"syn", "connect", "sweep", "fin", "null", "xmas", "benign"}


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
            destination_port, flags, state, event_type = randomizer.choice([53, 80, 443, 22]), ["SYN", "ACK"], "SF", "connection"
        else:
            destination_port = 80 if scenario == "sweep" else 20 + index
            flags = {
                "syn": ["SYN"],
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
                timestamp=start + timedelta(milliseconds=index * 250),
                event_id=f"synthetic-{seed}-{scenario}-{index:05d}",
                source_ip="198.51.100.27",
                destination_ip=f"192.0.2.{destination_index + 10}",
                source_port=45000 + (index % 20000),
                destination_port=destination_port,
                protocol="tcp",
                tcp_flags=flags,
                event_type=event_type,
                connection_state=state,
                sensor_type="simulator",
                scenario_id=f"synthetic-{scenario}",
                raw_event={"generated": True, "scenario": scenario, "sequence": index},
                scan_type=scenario,
                tags=["simulated"],
            )
        )
    return events