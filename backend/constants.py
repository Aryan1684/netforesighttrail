FEATURE_NAMES = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt",
    "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src",
    "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
]

LABELS = [
    "Analysis", "Backdoor", "DoS", "Exploits", "Fuzzers",
    "Generic", "Normal", "Reconnaissance", "Shellcode", "Worms"
]

PROTO_VALUES = [
    "udp","arp","tcp","icmp","igmp","ospf","sctp","gre","ggp","ip","ipnip","st2",
    "argus","chaos","egp","emcon","nvp","pup","xnet","mux","dcn","hmp","prm",
    "trunk-1","trunk-2","xns-idp","leaf-1","leaf-2","irtp","rdp","netblt",
    "mfe-nsp","merit-inp","3pc","idpr","ddp","idpr-cmtp","tp++","ipv6","sdrp",
    "ipv6-frag","ipv6-route","idrp","mhrp","i-nlsp","rvd","mobile","narp","skip",
    "tlsp","ipv6-no","any","ipv6-opts","cftp","sat-expak","ippc","kryptolan",
    "sat-mon","cpnx","wsn","pvp","br-sat-mon","sun-nd","wb-mon","vmtp","ttp",
    "vines","nsfnet-igp","dgp","eigrp","tcf","sprite-rpc","larp","mtp","ax.25",
    "ipip","aes-sp3-d","micp","encap","pri-enc","gmtp","ifmp","pnni","qnx",
    "scps","cbt","bbn-rcc","igp","bna","swipe","visa","ipcv","cphb","iso-tp4",
    "wb-expak","sep","secure-vmtp","xtp","il","rsvp","unas","fc","iso-ip",
    "etherip","pim","aris","a/n","ipcomp","snp","compaq-peer","ipx-n-ip","pgm",
    "vrrp","l2tp","zero","ddx","iatp","stp","srp","uti","sm","smp","isis","ptp",
    "fire","crtp","crudp","sccopmce","iplt","pipe","sps","ib"
]

SERVICE_VALUES = [
    "-", "dhcp", "dns", "ftp", "ftp-data", "http", "irc", "pop3",
    "radius", "smtp", "snmp", "ssh", "ssl"
]

STATE_VALUES = ["INT", "FIN", "REQ", "ACC", "CON", "RST", "CLO", "ECO", "PAR", "URN", "no"]

PROTO_TO_CODE = {name: idx for idx, name in enumerate(sorted(PROTO_VALUES))}
SERVICE_TO_CODE = {name: idx for idx, name in enumerate(sorted(SERVICE_VALUES))}
STATE_TO_CODE = {name: idx for idx, name in enumerate(sorted(STATE_VALUES))}

PORT_SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 110: "pop3", 161: "snmp", 162: "snmp",
    443: "ssl", 465: "ssl", 587: "smtp", 1812: "radius", 1813: "radius",
    8000: "http", 8080: "http", 80: "http", 6667: "irc"
}

PROTOCOL_MAP = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    41: "ipv6",
    47: "gre",
    50: "encap",
    51: "ipcomp",
    58: "ipv6-opts"
}

def encode_proto(name: str) -> int:
    value = str(name).lower()
    if value in PROTO_TO_CODE:
        return PROTO_TO_CODE[value]
    return PROTO_TO_CODE["unas"]

def encode_service(port: int, layer: str = "") -> int:
    layer = str(layer).lower()
    for key, service in PORT_SERVICE.items():
        if port == key:
            return SERVICE_TO_CODE[service]
    if "http" in layer:
        return SERVICE_TO_CODE["http"]
    if "dns" in layer:
        return SERVICE_TO_CODE["dns"]
    if "ftp" in layer:
        return SERVICE_TO_CODE["ftp"]
    if "ssh" in layer:
        return SERVICE_TO_CODE["ssh"]
    if "smtp" in layer:
        return SERVICE_TO_CODE["smtp"]
    if "tls" in layer or "ssl" in layer:
        return SERVICE_TO_CODE["ssl"]
    return SERVICE_TO_CODE["-"]

def encode_state(protocol: int, syn: int, ack: int, fin: int, rst: int) -> int:
    if rst:
        return STATE_TO_CODE["RST"]
    if fin:
        return STATE_TO_CODE["FIN"]
    if protocol == 6 and syn and not ack:
        return STATE_TO_CODE["REQ"]
    if protocol == 6 and syn and ack:
        return STATE_TO_CODE["ACC"]
    if protocol == 6 and ack:
        return STATE_TO_CODE["CON"]
    return STATE_TO_CODE["INT"]
