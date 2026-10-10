"""Deterministic domain tags shared by KB build and retrieval reranking.

The same keyword rules label (a) KB patterns at build time and (b) assets at
query time, so tag overlap is a like-for-like signal.  No model is involved.
Tags are a heuristic aid for ranking, not ground truth.
"""

from __future__ import annotations

TAG_RULES: dict[str, tuple[str, ...]] = {
    "hardware": (
        "hardware", "silicon", " chip", "secure element", "tpm", "hsm", "side-channel",
        "side channel", "fault injection", "glitch", "power analysis", "jtag",
        "debug interface", "on-chip", " soc", "fabric", " rtl", "trojan",
    ),
    "firmware": (
        "firmware", "bootloader", "boot loader", " ota", "over-the-air", "flash",
        "update package", "signed image", "secure boot",
    ),
    "physical": (
        "physical access", "tamper", "physically", "jtag", "debug port", "obd", "usb port",
    ),
    "wireless": (
        "ble", "bluetooth", "wi-fi", "wifi", "zigbee", "lte", "cellular", "radio", "nfc",
        "gatt", "wireless",
    ),
    "network": (
        "network", "ethernet", "tcp", "udp", "modbus", "can bus", "mqtt", "packet",
        "protocol", "vlan", "man-in-the-middle", "adversary in the middle", "sniff",
    ),
    "web": (
        "http", "web ", "rest", " api", "oauth", "jwt", "cookie", "session", "browser",
        "xss", "csrf", "sql injection", "url",
    ),
    "cloud": ("cloud", "backend", "saas", "server", "database", "tenant", "container"),
    "mobile": ("mobile", "android", " ios", "smartphone", " app "),
    "ics": (
        "plc", "scada", " hmi", "industrial control", "modbus", "dnp3", "opc",
        "fieldbus", "controller",
    ),
    "automotive": ("can bus", "obd", " uds", " ecu", "vehicle", "automotive", "can fd"),
    "crypto": (
        "cryptograph", " key", "certificate", "signature", "tls", "encryption",
        "cipher", "entropy", "random",
    ),
    "credentials": (
        "credential", "password", "token", "authenticat", "session id", "login", "account",
        "brute force", "e-key", "api key", "api-key",
    ),
}


def tags_for_text(text: str) -> frozenset[str]:
    """Return the tags whose keywords appear in ``text`` (case-insensitive)."""
    padded = f" {text.lower()} "
    return frozenset(
        tag for tag, words in TAG_RULES.items() if any(w in padded for w in words)
    )
