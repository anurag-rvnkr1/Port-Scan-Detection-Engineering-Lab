from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass


COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080)
MAX_SELECTED_PORTS = 256
MAX_XML_BYTES = 2 * 1024 * 1024
SCAN_LOCK = threading.Lock()

_AUTHORIZED_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class NmapConfigurationError(ValueError):
    pass


class NmapUnavailable(RuntimeError):
    pass


class NmapExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ScanConfiguration:
    executable: str | None
    authorized_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    @property
    def enabled(self) -> bool:
        return self.executable is not None and bool(self.authorized_networks)


def load_configuration() -> ScanConfiguration:
    raw_networks = os.getenv("LAB_NMAP_ALLOWED_CIDRS", "").strip()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    if raw_networks:
        values = raw_networks.split(",")
        if len(values) > 64:
            raise NmapConfigurationError("At most 64 authorized Nmap CIDRs may be configured")
        for value in values:
            try:
                network = ipaddress.ip_network(value.strip(), strict=False)
            except ValueError as error:
                raise NmapConfigurationError("LAB_NMAP_ALLOWED_CIDRS contains an invalid CIDR") from error
            if not any(network.version == allowed.version and network.subnet_of(allowed) for allowed in _AUTHORIZED_RANGES):
                raise NmapConfigurationError("Authorized Nmap CIDRs must be private or loopback lab networks")
            if network not in networks:
                networks.append(network)

    configured_binary = os.getenv("LAB_NMAP_BINARY", "nmap").strip()
    if not configured_binary:
        raise NmapConfigurationError("LAB_NMAP_BINARY must not be empty")
    executable = shutil.which(configured_binary)
    return ScanConfiguration(executable, tuple(networks))


def authorize_target(target: str, networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise NmapConfigurationError("Target must be a single IPv4 or IPv6 address, not a hostname or range") from error
    if not any(address.version == network.version and address in network for network in networks):
        raise NmapConfigurationError("Target is not inside a configured authorized lab CIDR")
    if not (address.is_private or address.is_loopback):
        raise NmapConfigurationError("Only private or loopback lab targets are allowed")
    return str(address)


def _parse_xml(xml_output: str) -> dict:
    if len(xml_output.encode("utf-8")) > MAX_XML_BYTES:
        raise NmapExecutionError("Nmap XML output exceeded the configured limit")
    try:
        root = ET.fromstring(xml_output)
    except (ET.ParseError, RecursionError) as error:
        raise NmapExecutionError("Nmap returned invalid XML output") from error
    if root.tag != "nmaprun":
        raise NmapExecutionError("Nmap returned an unexpected XML document")

    host = root.find("host")
    host_state = "unknown"
    ports: list[dict[str, int | str | None]] = []
    if host is not None:
        status = host.find("status")
        if status is not None:
            host_state = status.attrib.get("state", "unknown")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            try:
                port_number = int(port.attrib["portid"])
            except (KeyError, ValueError) as error:
                raise NmapExecutionError("Nmap returned a port without a valid port number") from error
            service = port.find("service")
            ports.append(
                {
                    "protocol": port.attrib.get("protocol"),
                    "port": port_number,
                    "service": service.attrib.get("name") if service is not None else None,
                    "product": service.attrib.get("product") if service is not None else None,
                    "version": service.attrib.get("version") if service is not None else None,
                }
            )
    return {"host_status": host_state, "open_ports": ports}


def build_command(
    *,
    target: str,
    profile: str,
    scan_type: str,
    ports: list[int] | None,
    service_detection: bool,
    configuration: ScanConfiguration,
) -> list[str]:
    if not configuration.enabled or configuration.executable is None:
        raise NmapUnavailable("Nmap is unavailable or authorized lab CIDRs are not configured")
    normalized_target = authorize_target(target, configuration.authorized_networks)
    if profile == "host_discovery":
        if ports or service_detection:
            raise NmapConfigurationError("Host discovery does not accept ports or service detection")
    elif profile == "common_ports":
        if ports:
            raise NmapConfigurationError("Common-port scans do not accept a custom port list")
        ports = list(COMMON_PORTS)
    elif profile == "selected_ports":
        if not ports:
            raise NmapConfigurationError("Selected-port scans require at least one port")
        if len(ports) > MAX_SELECTED_PORTS or len(set(ports)) != len(ports):
            raise NmapConfigurationError("Selected-port list must contain 1 to 256 unique ports")
        if any(port < 1 or port > 65535 for port in ports):
            raise NmapConfigurationError("Ports must be between 1 and 65535")
    else:
        raise NmapConfigurationError("Unsupported Nmap scan profile")
    if scan_type not in {"tcp_connect", "syn"}:
        raise NmapConfigurationError("Unsupported Nmap scan type")
    if profile == "host_discovery" and scan_type != "tcp_connect":
        raise NmapConfigurationError("Host discovery does not accept a TCP scan type")

    arguments = [configuration.executable, "-n", "-T3", "--reason", "-oX", "-"]
    if profile == "host_discovery":
        arguments.append("-sn")
    else:
        arguments.append("-sT" if scan_type == "tcp_connect" else "-sS")
        arguments.extend(["-p", ",".join(str(port) for port in sorted(ports or []))])
        if service_detection:
            arguments.append("-sV")
    arguments.append(normalized_target)
    return arguments


def execute_command(arguments: list[str], timeout_seconds: int) -> dict:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise NmapExecutionError("Nmap scan exceeded its configured timeout") from error
    except OSError as error:
        raise NmapUnavailable("Nmap could not be started") from error
    if completed.returncode != 0:
        raise NmapExecutionError(f"Nmap exited with status {completed.returncode}")
    return _parse_xml(completed.stdout)
