from __future__ import annotations

import math
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FlowState:
    key: tuple[str, str, int, int, int]
    started_at: float
    last_seen: float
    packets: list[tuple[float, float, bool, int, int, int]] = field(default_factory=list)
    first_src: str = ""
    first_dst: str = ""
    dst_port: int = 0
    protocol: int = 0

    def add_packet(
        self,
        timestamp: float,
        length: float,
        forward: bool,
        syn: int,
        rst: int,
        ack: int,
    ) -> None:
        self.packets.append((timestamp, length, forward, syn, rst, ack))
        self.last_seen = timestamp

    def features(self) -> list[float]:
        duration = max(self.last_seen - self.started_at, 0.0)
        fwd = [p for p in self.packets if p[2]]
        bwd = [p for p in self.packets if not p[2]]

        lengths = [p[1] for p in self.packets]
        fwd_lengths = [p[1] for p in fwd]

        iats = [
            self.packets[i][0] - self.packets[i - 1][0]
            for i in range(1, len(self.packets))
        ]

        total_bytes = float(sum(lengths))
        total_packets = len(self.packets)

        flow_bytes_per_s = total_bytes / duration if duration > 0 else 0.0
        flow_packets_per_s = total_packets / duration if duration > 0 else 0.0

        return [
            float(self.dst_port),
            float(self.protocol),
            float(duration),
            float(len(fwd)),
            float(len(bwd)),
            float(sum(p[1] for p in fwd)),
            float(sum(p[1] for p in bwd)),
            float(max(fwd_lengths) if fwd_lengths else 0.0),
            float(min(fwd_lengths) if fwd_lengths else 0.0),
            float(flow_bytes_per_s),
            float(flow_packets_per_s),
            float(statistics.mean(iats) if iats else 0.0),
            float(statistics.pstdev(iats) if len(iats) > 1 else 0.0),
            float(sum(p[3] for p in self.packets)),
            float(sum(p[4] for p in self.packets)),
            float(sum(p[5] for p in self.packets)),
        ]


class FlowEngine:
    def __init__(self, idle_timeout: float = 5.0, active_timeout: float = 30.0, sequence_length: int = 5):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.flows: dict[tuple[str, str, int, int, int], FlowState] = {}
        self.sequence = deque(maxlen=sequence_length)
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: dict[str, int] = {}

    @staticmethod
    def _packet_time(packet: Any) -> float:
        try:
            return float(packet.sniff_timestamp)
        except Exception:
            return time.time()

    @staticmethod
    def _ip_pair(packet: Any) -> tuple[str, str] | None:
        if hasattr(packet, "ip"):
            return str(packet.ip.src), str(packet.ip.dst)
        if hasattr(packet, "ipv6"):
            return str(packet.ipv6.src), str(packet.ipv6.dst)
        return None

    @staticmethod
    def _transport(packet: Any) -> tuple[int, int, int, int, int]:
        if hasattr(packet, "tcp"):
            tcp = packet.tcp
            flags = str(getattr(tcp, "flags", ""))
            src = int(getattr(tcp, "srcport", 0) or 0)
            dst = int(getattr(tcp, "dstport", 0) or 0)
            syn = 1 if ("0x0002" in flags or "S" in flags) else 0
            rst = 1 if ("0x0004" in flags or "R" in flags) else 0
            ack = 1 if ("0x0010" in flags or "A" in flags) else 0
            return src, dst, 6, syn, rst, ack
        if hasattr(packet, "udp"):
            udp = packet.udp
            return (
                int(getattr(udp, "srcport", 0) or 0),
                int(getattr(udp, "dstport", 0) or 0),
                17,
                0,
                0,
                0,
            )
        proto = 0
        if hasattr(packet, "icmp"):
            proto = 1
        elif hasattr(packet, "icmpv6"):
            proto = 58
        return 0, 0, proto, 0, 0, 0

    @staticmethod
    def _length(packet: Any) -> float:
        try:
            return float(getattr(packet, "length", 0) or 0)
        except Exception:
            return 0.0

    def _flow_key(self, src: str, dst: str, src_port: int, dst_port: int, proto: int):
        a = (src, src_port)
        b = (dst, dst_port)
        return (src, dst, src_port, dst_port, proto) if a <= b else (dst, src, dst_port, src_port, proto)

    def ingest(self, packet: Any) -> list[list[float]]:
        pair = self._ip_pair(packet)
        if pair is None:
            return []

        src, dst = pair
        src_port, dst_port, proto, syn, rst, ack = self._transport(packet)
        timestamp = self._packet_time(packet)
        length = self._length(packet)

        key = self._flow_key(src, dst, src_port, dst_port, proto)

        flow = self.flows.get(key)
        emitted: list[list[float]] = []

        if flow is None:
            flow = FlowState(
                key=key,
                started_at=timestamp,
                last_seen=timestamp,
                first_src=src,
                first_dst=dst,
                dst_port=dst_port,
                protocol=proto,
            )
            self.flows[key] = flow
            forward = True
        else:
            forward = src == flow.first_src and dst == flow.first_dst and src_port == key[2] and dst_port == key[3]

        flow.add_packet(timestamp, length, forward, syn, rst, ack)
        self.total_packets += 1
        self.total_bytes += int(length)
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto, "OTHER")
        self.protocol_counts[proto_name] = self.protocol_counts.get(proto_name, 0) + 1

        now = timestamp
        expired = []
        for fkey, state in self.flows.items():
            if (now - state.last_seen) >= self.idle_timeout or (now - state.started_at) >= self.active_timeout:
                expired.append(fkey)

        for fkey in expired:
            state = self.flows.pop(fkey)
            if state.packets:
                vector = state.features()
                self.sequence.append(vector)
                emitted.append(vector)

        return emitted

    def flush(self) -> list[list[float]]:
        emitted = []
        for key in list(self.flows):
            state = self.flows.pop(key)
            if state.packets:
                vector = state.features()
                self.sequence.append(vector)
                emitted.append(vector)
        return emitted

    def sequence_window(self) -> list[list[float]] | None:
        if len(self.sequence) < 5:
            return None
        return list(self.sequence)

    @property
    def active_flows(self) -> int:
        return len(self.flows)

    def stats(self) -> dict[str, Any]:
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "active_flows": self.active_flows,
            "protocols": dict(self.protocol_counts),
            "sequence_ready": len(self.sequence) == 5,
        }
