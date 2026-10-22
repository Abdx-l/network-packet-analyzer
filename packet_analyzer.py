"""Classic pcap reader and Ethernet/IPv4 flow accounting."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import socket
import struct


MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
         b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}


def packets(path: Path):
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError("Invalid classic pcap header")
        endian, resolution = MAGIC[header[:4]]
        _, _, _, _, _, linktype = struct.unpack(endian + "HHIIII", header[4:])
        if linktype != 1:
            raise ValueError("Only Ethernet captures are supported")
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("Truncated pcap record header")
            sec, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > 16 * 1024 * 1024 or captured > original:
                raise ValueError("Invalid capture length")
            frame = stream.read(captured)
            if len(frame) != captured:
                raise ValueError("Truncated pcap frame")
            yield sec + fraction / resolution, frame


def decode(frame: bytes):
    if len(frame) < 14:
        return None, "truncated"
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    if ethertype == 0x8100:
        if len(frame) < 18:
            return None, "truncated"
        ethertype = struct.unpack_from("!H", frame, 16)[0]
        offset = 18
    if ethertype != 0x0800:
        return None, "other_ethertype"
    if len(frame) < offset + 20:
        return None, "truncated"
    version_ihl = frame[offset]
    ihl = (version_ihl & 15) * 4
    if version_ihl >> 4 != 4 or ihl < 20 or len(frame) < offset + ihl:
        return None, "truncated"
    total = struct.unpack_from("!H", frame, offset + 2)[0]
    if total < ihl or len(frame) < offset + total:
        return None, "truncated"
    flags_fragment = struct.unpack_from("!H", frame, offset + 6)[0]
    proto = frame[offset + 9]
    src = socket.inet_ntoa(frame[offset + 12:offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
    transport = offset + ihl
    sport = dport = 0
    seq = None
    if flags_fragment & 0x1fff:
        return {"protocol": "fragment", "src": src, "dst": dst, "sport": 0, "dport": 0, "bytes": total, "seq": None, "payload": 0}, None
    if proto in (6, 17):
        if total < ihl + (20 if proto == 6 else 8):
            return None, "truncated"
        sport, dport = struct.unpack_from("!HH", frame, transport)
        if proto == 6:
            seq = struct.unpack_from("!I", frame, transport + 4)[0]
            data_offset = (frame[transport + 12] >> 4) * 4
            if data_offset < 20 or total < ihl + data_offset:
                return None, "truncated"
            payload = total - ihl - data_offset
        else:
            payload = total - ihl - 8
    else:
        payload = total - ihl
    return {"protocol": {6: "TCP", 17: "UDP"}.get(proto, f"IP-{proto}"), "src": src, "dst": dst,
            "sport": sport, "dport": dport, "bytes": total, "seq": seq, "payload": payload}, None


def analyze(path: Path, top: int = 10) -> dict:
    protocols = Counter()
    flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "retransmissions": 0})
    seen = defaultdict(set)
    skipped = Counter()
    for _, frame in packets(path):
        packet, reason = decode(frame)
        if reason:
            skipped[reason] += 1
            continue
        key = (packet["src"], packet["sport"], packet["dst"], packet["dport"], packet["protocol"])
        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += packet["bytes"]
        protocols[packet["protocol"]] += 1
        if packet["protocol"] == "TCP" and packet["payload"] > 0:
            pair = (packet["seq"], packet["payload"])
            if pair in seen[key]:
                flow["retransmissions"] += 1
            seen[key].add(pair)
    ranked = sorted(flows.items(), key=lambda x: (-x[1]["bytes"], x[0]))[:top]
    return {"protocols": dict(protocols), "skipped": dict(skipped),
            "top_flows": [{"src": k[0], "src_port": k[1], "dst": k[2], "dst_port": k[3], "protocol": k[4], **v} for k, v in ranked]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be positive")
    report = analyze(args.capture, args.top)
    content = json.dumps(report, indent=2)
    if args.json:
        args.json.write_text(content + "\n", encoding="utf-8")
    print(content)

