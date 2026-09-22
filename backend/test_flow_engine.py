from pathlib import Path
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))

from flow_engine import FlowEngine

def packet(src,dst,sport,dport,t,flags="0x0010",length=100):
    tcp=SimpleNamespace(
        srcport=str(sport),
        dstport=str(dport),
        flags=flags,
        window_size_value="65535",
        seq_raw="1",
        ack_raw="1"
    )
    ip=SimpleNamespace(src=src,dst=dst,ttl="64")
    return SimpleNamespace(
        sniff_timestamp=str(t),
        length=str(length),
        ip=ip,
        tcp=tcp
    )

e=FlowEngine(idle_timeout=1,active_timeout=30,sequence_length=5)

for i in range(5):
    e.ingest(packet("10.0.0.2","1.1.1.1",5000+i,443,i*3,flags="0x0002"))
    e.ingest(packet("1.1.1.1","10.0.0.2",443,5000+i,i*3+0.1,flags="0x0012"))
    e.ingest(packet("10.0.0.2","1.1.1.1",5000+i,443,i*3+0.2,flags="0x0010"))
    e.flush()

assert e.stats()["completed_flows"]==5
assert e.sequence_window() is not None
assert len(e.sequence_window())==5
assert len(e.sequence_window()[0])==42

print("Bidirectional flow aggregation: PASS")
print("Five-flow sequence: PASS")
print("42-feature vector: PASS")
