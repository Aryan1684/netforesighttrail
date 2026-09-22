from __future__ import annotations

import statistics
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

from constants import FEATURE_NAMES, PROTOCOL_MAP, encode_proto, encode_service, encode_state


@dataclass
class PacketRecord:
    timestamp: float
    length: float
    forward: bool
    ttl: int
    window: int
    seq: int
    ack_num: int
    syn: int
    ack: int
    fin: int
    rst: int
    http_method: str = ""
    http_depth: int = 0
    http_body_len: int = 0
    ftp_command: str = ""


@dataclass
class FlowState:
    key: tuple[str, str, int, int, int]
    started_at: float
    last_seen: float
    first_src: str
    first_dst: str
    src_port: int
    dst_port: int
    protocol: int
    packets: list[PacketRecord] = field(default_factory=list)
    service_name: str = "-"

    def add(self, packet: PacketRecord) -> None:
        self.packets.append(packet)
        self.last_seen = packet.timestamp

    def _direction(self, forward: bool) -> list[PacketRecord]:
        return [p for p in self.packets if p.forward == forward]

    def _inter_arrivals(self, records: list[PacketRecord]) -> list[float]:
        if len(records) < 2:
            return []
        ordered = sorted(records, key=lambda x: x.timestamp)
        return [(ordered[i].timestamp - ordered[i - 1].timestamp) * 1000.0 for i in range(1, len(ordered))]

    def _jit(self, iats: list[float]) -> float:
        if len(iats) < 2:
            return 0.0
        return statistics.mean(abs(iats[i] - iats[i - 1]) for i in range(1, len(iats)))

    def feature_row(self, context: dict[str, int]) -> list[float]:
        fwd = self._direction(True)
        bwd = self._direction(False)
        duration = max(self.last_seen - self.started_at, 0.000001)
        all_lengths = [p.length for p in self.packets]
        fwd_bytes = sum(p.length for p in fwd)
        bwd_bytes = sum(p.length for p in bwd)
        total_packets = len(self.packets)
        fwd_iats = self._inter_arrivals(fwd)
        bwd_iats = self._inter_arrivals(bwd)
        fwd_ttl = fwd[-1].ttl if fwd else 0
        bwd_ttl = bwd[-1].ttl if bwd else 0
        fwd_loss = self._loss_count(fwd)
        bwd_loss = self._loss_count(bwd)
        syn_time = None
        syn_ack_time = None
        first_ack_time = None
        for p in self.packets:
            if p.syn and not p.ack and syn_time is None:
                syn_time = p.timestamp
            if p.syn and p.ack and syn_ack_time is None:
                syn_ack_time = p.timestamp
            if p.ack and not p.syn and first_ack_time is None:
                first_ack_time = p.timestamp
        synack = max(0.0, syn_ack_time - syn_time) if syn_time is not None and syn_ack_time is not None else 0.0
        ackdat = max(0.0, first_ack_time - syn_ack_time) if syn_ack_time is not None and first_ack_time is not None else 0.0
        http_depth = max((p.http_depth for p in self.packets), default=0)
        response_body_len = sum(p.http_body_len for p in self.packets)
        ftp_login = 1 if any(p.ftp_command.upper() in {"USER", "PASS"} for p in self.packets) else 0
        ftp_cmd_count = sum(1 for p in self.packets if p.ftp_command)
        http_methods = sum(1 for p in self.packets if p.http_method)
        state_code = encode_state(
            self.protocol,
            max((p.syn for p in self.packets), default=0),
            max((p.ack for p in self.packets), default=0),
            max((p.fin for p in self.packets), default=0),
            max((p.rst for p in self.packets), default=0),
        )
        proto_code = encode_proto(PROTOCOL_MAP.get(self.protocol, "unas"))
        service_code = encode_service(self.dst_port, self.service_name)

        row = {
            "dur": duration,
            "proto": proto_code,
            "service": service_code,
            "state": state_code,
            "spkts": len(fwd),
            "dpkts": len(bwd),
            "sbytes": fwd_bytes,
            "dbytes": bwd_bytes,
            "rate": total_packets / duration,
            "sttl": fwd_ttl,
            "dttl": bwd_ttl,
            "sload": (fwd_bytes * 8.0) / duration,
            "dload": (bwd_bytes * 8.0) / duration,
            "sloss": fwd_loss,
            "dloss": bwd_loss,
            "sinpkt": statistics.mean(fwd_iats) if fwd_iats else 0.0,
            "dinpkt": statistics.mean(bwd_iats) if bwd_iats else 0.0,
            "sjit": self._jit(fwd_iats),
            "djit": self._jit(bwd_iats),
            "swin": next((p.window for p in fwd if p.window), 0),
            "stcpb": next((p.seq for p in fwd if p.seq), 0),
            "dtcpb": next((p.seq for p in bwd if p.seq), 0),
            "synack": synack,
            "ackdat": ackdat,
            "smean": statistics.mean([p.length for p in fwd]) if fwd else 0.0,
            "dmean": statistics.mean([p.length for p in bwd]) if bwd else 0.0,
            "trans_depth": http_depth,
            "response_body_len": response_body_len,
            "ct_srv_src": context["ct_srv_src"],
            "ct_state_ttl": context["ct_state_ttl"],
            "ct_dst_ltm": context["ct_dst_ltm"],
            "ct_src_dport_ltm": context["ct_src_dport_ltm"],
            "ct_dst_sport_ltm": context["ct_dst_sport_ltm"],
            "ct_dst_src_ltm": context["ct_dst_src_ltm"],
            "is_ftp_login": ftp_login,
            "ct_ftp_cmd": ftp_cmd_count,
            "ct_flw_http_mthd": http_methods,
            "ct_src_ltm": context["ct_src_ltm"],
            "ct_srv_dst": context["ct_srv_dst"],
            "is_sm_ips_ports": int(self.first_src == self.first_dst and self.src_port == self.dst_port),
        }
        return [float(row[name]) for name in FEATURE_NAMES]

    def _loss_count(self, records: list[PacketRecord]) -> int:
        seen = set()
        loss = 0
        for packet in records:
            if self.protocol != 6 or packet.seq == 0:
                continue
            if packet.seq in seen:
                loss += 1
            seen.add(packet.seq)
        return loss

    def summary(self, vector: list[float]) -> dict[str, Any]:
        return {
            "src": self.first_src,
            "dst": self.first_dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "service": self.service_name,
            "started_at": self.started_at,
            "ended_at": self.last_seen,
            "features": dict(zip(FEATURE_NAMES, vector)),
        }


class FlowEngine:
    def __init__(self, idle_timeout: float = 5.0, active_timeout: float = 30.0, sequence_length: int = 5, context_seconds: float = 60.0):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.sequence_length = sequence_length
        self.context_seconds = context_seconds
        self.flows: dict[tuple[str, str, int, int, int], FlowState] = {}
        self.sequence = deque(maxlen=sequence_length)
        self.completed = deque(maxlen=1000)
        self.recent = deque(maxlen=5000)
        self.total_packets = 0
        self.total_bytes = 0
        self.incoming_packets = 0
        self.outgoing_packets = 0
        self.protocol_counts = Counter()
        self.completed_flow_count = 0

    @staticmethod
    def packet_time(packet: Any) -> float:
        try:
            return float(packet.sniff_timestamp)
        except Exception:
            return time.time()

    @staticmethod
    def packet_length(packet: Any) -> float:
        try:
            return float(getattr(packet, "length", 0) or 0)
        except Exception:
            return 0.0

    @staticmethod
    def ip_pair(packet: Any) -> tuple[str, str] | None:
        if hasattr(packet, "ip"):
            return str(packet.ip.src), str(packet.ip.dst)
        if hasattr(packet, "ipv6"):
            return str(packet.ipv6.src), str(packet.ipv6.dst)
        return None

    @staticmethod
    def transport(packet: Any) -> tuple[int, int, int, int, int, int, int]:
        if hasattr(packet, "tcp"):
            tcp = packet.tcp
            flags = str(getattr(tcp, "flags", ""))
            return (
                int(getattr(tcp, "srcport", 0) or 0),
                int(getattr(tcp, "dstport", 0) or 0),
                6,
                int("0x0002" in flags or "S" in flags),
                int("0x0010" in flags or "A" in flags),
                int("0x0001" in flags or "F" in flags),
                int("0x0004" in flags or "R" in flags),
            )
        if hasattr(packet, "udp"):
            udp = packet.udp
            return (
                int(getattr(udp, "srcport", 0) or 0),
                int(getattr(udp, "dstport", 0) or 0),
                17,
                0,
                0,
                0,
                0,
            )
        proto = 1 if hasattr(packet, "icmp") else (58 if hasattr(packet, "icmpv6") else 0)
        return 0, 0, proto, 0, 0, 0, 0

    @staticmethod
    def ttl(packet: Any) -> int:
        for layer_name in ("ip", "ipv6"):
            if hasattr(packet, layer_name):
                layer = getattr(packet, layer_name)
                value = getattr(layer, "ttl", None)
                if value is None:
                    value = getattr(layer, "hopl", 0)
                try:
                    return int(value or 0)
                except Exception:
                    return 0
        return 0

    @staticmethod
    def tcp_values(packet: Any) -> tuple[int, int, int]:
        if not hasattr(packet, "tcp"):
            return 0, 0, 0
        tcp = packet.tcp
        try:
            window = int(getattr(tcp, "window_size_value", getattr(tcp, "window_size", 0)) or 0)
        except Exception:
            window = 0
        try:
            seq = int(getattr(tcp, "seq_raw", getattr(tcp, "seq", 0)) or 0)
        except Exception:
            seq = 0
        try:
            ack_num = int(getattr(tcp, "ack_raw", getattr(tcp, "ack", 0)) or 0)
        except Exception:
            ack_num = 0
        return window, seq, ack_num

    @staticmethod
    def service_name(packet: Any, dst_port: int) -> str:
        layer = str(getattr(packet, "highest_layer", "") or "")
        return next((name for port, name in [(20,"ftp-data"),(21,"ftp"),(22,"ssh"),(25,"smtp"),(53,"dns"),(67,"dhcp"),(68,"dhcp"),(80,"http"),(110,"pop3"),(161,"snmp"),(162,"snmp"),(443,"ssl"),(1812,"radius"),(1813,"radius"),(6667,"irc")] if dst_port == port), layer.lower())

    @staticmethod
    def http_metadata(packet: Any) -> tuple[str, int, int]:
        if not hasattr(packet, "http"):
            return "", 0, 0
        http = packet.http
        method = str(getattr(http, "request_method", "") or "")
        try:
            depth = int(getattr(http, "trans_depth", 0) or 0)
        except Exception:
            depth = 0
        try:
            body = int(getattr(http, "file_data", 0) or 0)
        except Exception:
            body = 0
        return method, depth, body

    @staticmethod
    def ftp_metadata(packet: Any) -> str:
        if not hasattr(packet, "ftp"):
            return ""
        ftp = packet.ftp
        for attr in ("request_command", "request"):
            value = str(getattr(ftp, attr, "") or "")
            if value:
                return value.split()[0]
        return ""

    def _flow_key(self, src: str, dst: str, src_port: int, dst_port: int, proto: int) -> tuple[str, str, int, int, int]:
        a = (src, src_port)
        b = (dst, dst_port)
        if a <= b:
            return src, dst, src_port, dst_port, proto
        return dst, src, dst_port, src_port, proto

    def _context(self, flow: FlowState, now: float) -> dict[str, int]:
        while self.recent and now - self.recent[0]["ended_at"] > self.context_seconds:
            self.recent.popleft()
        src = flow.first_src
        dst = flow.first_dst
        dport = flow.dst_port
        sport = flow.src_port
        state = flow.feature_row({k: 0 for k in ("ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","ct_src_ltm","ct_srv_dst")})[3]
        ttl = flow.feature_row({k: 0 for k in ("ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","ct_src_ltm","ct_srv_dst")})[9]
        service = flow.service_name
        rows = list(self.recent)
        return {
            "ct_srv_src": 1 + sum(int(r["service"] == service and r["src"] == src) for r in rows),
            "ct_state_ttl": 1 + sum(int(r["state"] == state and r["sttl"] == ttl) for r in rows),
            "ct_dst_ltm": 1 + sum(int(r["dst"] == dst) for r in rows),
            "ct_src_dport_ltm": 1 + sum(int(r["src"] == src and r["dst_port"] == dport) for r in rows),
            "ct_dst_sport_ltm": 1 + sum(int(r["dst"] == dst and r["src_port"] == sport) for r in rows),
            "ct_dst_src_ltm": 1 + sum(int(r["dst"] == dst and r["src"] == src) for r in rows),
            "ct_src_ltm": 1 + sum(int(r["src"] == src) for r in rows),
            "ct_srv_dst": 1 + sum(int(r["service"] == service and r["dst"] == dst) for r in rows),
        }

    def ingest(self, packet: Any, local_ips: set[str] | None = None) -> list[dict[str, Any]]:
        pair = self.ip_pair(packet)
        if pair is None:
            return []
        src, dst = pair
        src_port, dst_port, proto, syn, ack, fin, rst = self.transport(packet)
        timestamp = self.packet_time(packet)
        length = self.packet_length(packet)
        key = self._flow_key(src, dst, src_port, dst_port, proto)
        flow = self.flows.get(key)
        if flow is None:
            flow = FlowState(
                key=key,
                started_at=timestamp,
                last_seen=timestamp,
                first_src=src,
                first_dst=dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                service_name=self.service_name(packet, dst_port),
            )
            self.flows[key] = flow
            forward = True
        else:
            forward = src == flow.first_src and dst == flow.first_dst and src_port == flow.src_port and dst_port == flow.dst_port

        window, seq, ack_num = self.tcp_values(packet)
        method, depth, body = self.http_metadata(packet)
        ftp_command = self.ftp_metadata(packet)
        flow.add(
            PacketRecord(
                timestamp=timestamp,
                length=length,
                forward=forward,
                ttl=self.ttl(packet),
                window=window,
                seq=seq,
                ack_num=ack_num,
                syn=syn,
                ack=ack,
                fin=fin,
                rst=rst,
                http_method=method,
                http_depth=depth,
                http_body_len=body,
                ftp_command=ftp_command,
            )
        )

        self.total_packets += 1
        self.total_bytes += int(length)
        if local_ips and src in local_ips:
            self.outgoing_packets += 1
        elif local_ips and dst in local_ips:
            self.incoming_packets += 1
        self.protocol_counts[proto] += 1

        now = timestamp
        completed = []
        for fkey, state in list(self.flows.items()):
            if now - state.last_seen >= self.idle_timeout or now - state.started_at >= self.active_timeout or (state.protocol == 6 and any(p.fin or p.rst for p in state.packets)):
                self.flows.pop(fkey, None)
                context = self._context(state, now)
                vector = state.feature_row(context)
                summary = state.summary(vector)
                summary["state"] = vector[3]
                summary["sttl"] = vector[9]
                self.sequence.append(vector)
                self.recent.append(summary)
                self.completed.append(summary)
                self.completed_flow_count += 1
                completed.append(summary)
        return completed

    def flush(self) -> list[dict[str, Any]]:
        completed = []
        now = time.time()
        for key in list(self.flows):
            state = self.flows.pop(key)
            context = self._context(state, now)
            vector = state.feature_row(context)
            summary = state.summary(vector)
            summary["state"] = vector[3]
            summary["sttl"] = vector[9]
            self.sequence.append(vector)
            self.recent.append(summary)
            self.completed.append(summary)
            self.completed_flow_count += 1
            completed.append(summary)
        return completed

    def sequence_window(self) -> list[list[float]] | None:
        if len(self.sequence) < self.sequence_length:
            return None
        return list(self.sequence)

    def stats(self) -> dict[str, Any]:
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "active_flows": len(self.flows),
            "completed_flows": self.completed_flow_count,
            "protocols": dict(self.protocol_counts),
            "sequence_ready": len(self.sequence) == self.sequence_length,
            "incoming_packets": self.incoming_packets,
            "outgoing_packets": self.outgoing_packets,
        }
