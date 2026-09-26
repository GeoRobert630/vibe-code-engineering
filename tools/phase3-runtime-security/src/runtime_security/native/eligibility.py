import socket
import ipaddress
from dataclasses import dataclass
from typing import List

from ..config import Config
from ..utils.safety import evaluate as safety_gate_evaluate


@dataclass
class NativeEligibilityDecision:
    allowed: bool
    reason: str
    resolved_ips: List[str]
    safety_gate_passed: bool = False


def _classify_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify an IP address into a category for the native eligibility policy.

    Returns one of: 'loopback', 'unspecified', 'multicast', 'link_local',
    'private', 'public'.  The order of checks matters: unspecified, multicast
    and link-local are tested before private because Python's ipaddress.is_private
    returns True for some of them (e.g. 0.0.0.0 on Python 3.13).
    """
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link_local"
    if addr.is_private:
        return "private"
    return "public"


def evaluate_native(cfg: Config) -> NativeEligibilityDecision:
    if not cfg.runtime_verification:
        return NativeEligibilityDecision(False, "runtime_verification is not configured", [])

    # ── BLOCKER 3: Run the existing Phase 3 safety gate first ──────────
    # Design §5: "The existing Phase 3 safety gate runs first and keeps its rules."
    # Production is refused here absolutely (Blocker 1), along with forbidden
    # environments and unauthorized remote targets.
    gate = safety_gate_evaluate(cfg)
    if not gate.allowed:
        return NativeEligibilityDecision(
            False,
            f"existing safety gate refused: {gate.reason}",
            [],
            safety_gate_passed=False,
        )

    # ── Native-specific eligibility (stricter, never looser) ───────────
    mode = cfg.runtime_verification.mode
    if mode not in ("fixture", "local-app"):
        return NativeEligibilityDecision(False, f"unknown mode {mode}", [], safety_gate_passed=True)

    if cfg.base_url not in cfg.runtime_verification.allowed_targets:
        return NativeEligibilityDecision(
            False,
            f"target {cfg.base_url} is not in allowed_targets",
            [],
            safety_gate_passed=True,
        )

    if mode == "local-app":
        if not (cfg.authorized and cfg.authorized_by):
            return NativeEligibilityDecision(
                False,
                "local-app mode requires authorized: true and authorized_by",
                [],
                safety_gate_passed=True,
            )
        if cfg.environment not in ("local", "test"):
            return NativeEligibilityDecision(
                False,
                f"local-app mode requires environment local or test, got {cfg.environment}",
                [],
                safety_gate_passed=True,
            )

    # ── Resolve hostname exactly once (Design §5, DNS rule) ────────────
    try:
        res = socket.getaddrinfo(cfg.host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(r[4][0] for r in res))
    except socket.gaierror:
        return NativeEligibilityDecision(
            False, f"could not resolve host {cfg.host}", [], safety_gate_passed=True
        )

    if not ips:
        return NativeEligibilityDecision(
            False, f"host {cfg.host} resolved to no addresses", [], safety_gate_passed=True
        )

    # ── Validate every resolved address (Design §5) ───────────────────
    # BLOCKER 2: explicit classification — never rely on is_private alone.
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return NativeEligibilityDecision(
                False, f"resolved invalid IP {ip}", [], safety_gate_passed=True
            )

        category = _classify_ip(addr)

        if category == "loopback":
            continue

        if category == "unspecified":
            return NativeEligibilityDecision(
                False,
                f"unspecified address {ip} is refused",
                [],
                safety_gate_passed=True,
            )

        if category == "multicast":
            return NativeEligibilityDecision(
                False,
                f"multicast address {ip} is refused",
                [],
                safety_gate_passed=True,
            )

        if category == "link_local":
            return NativeEligibilityDecision(
                False,
                f"link-local address {ip} is refused",
                [],
                safety_gate_passed=True,
            )

        if category == "private":
            # Private IPs (RFC1918 IPv4 + fc00::/7 IPv6) are allowed only in
            # local-app mode with local/test environment.
            if mode != "local-app" or cfg.environment not in ("local", "test"):
                return NativeEligibilityDecision(
                    False,
                    f"private IP {ip} is only allowed in local-app mode with local/test environment",
                    [],
                    safety_gate_passed=True,
                )
            continue

        # category == "public"
        return NativeEligibilityDecision(
            False,
            f"public address {ip} is not allowed for native verification",
            [],
            safety_gate_passed=True,
        )

    return NativeEligibilityDecision(
        True, "target is eligible for native verification", ips, safety_gate_passed=True
    )
