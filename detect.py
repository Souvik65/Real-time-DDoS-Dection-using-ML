import time
import threading
import logging
import warnings
from threading import Lock
from collections import defaultdict, Counter
import numpy as np
import pandas as pd
import joblib
import scapy.all as scapy

# Suppress sklearn warnings about feature names (improvement)
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# ======================================
# CONFIG
# ======================================

MODEL_PATH = "ddos_model-latest-1.pkl"  # Fixed: Match the training save path
TIME_WINDOW = 5
FLOW_TIMEOUT = 15
ALERT_THRESHOLD = 0.80
ALERT_COOLDOWN = 60  # Cooldown between alerts in seconds
LOG_FILE = "ddos_attack_log.txt"  # New: Log file for attacks

# ======================================
# GLOBALS
# ======================================

flow_lock = Lock()
flows = {}
last_alert_time = 0  # Track last alert time for cooldown
scanning = True
packet_count = 0  # Count packets
alerted_flows = []  # Track alerted flows for summary
source_counter = Counter()  # New: Track top sources
alert_count = 0  # New: Count alerts per window

# ======================================
# CUSTOM LOGGING WITH COLORS (For alerts only)
# ======================================

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'WARNING': '\033[91m',  # Red
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[91m', # Red
        'INFO': '\033[0m',      # Reset
        'DEBUG': '\033[0m',     # Reset
    }
    RESET = '\033[0m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        message = super().format(record)
        return f"{color}{message}{self.RESET}"

# Setup logging for file and alerts (console for alerts)
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

logging.basicConfig(level=logging.INFO, handlers=[file_handler])

console_logger = logging.getLogger('console')
console_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter(
    '%(message)s'  # Simplified for alerts
))
console_logger.addHandler(console_handler)

# ======================================
# LOAD TRAINED MODEL PIPELINE
# ======================================

try:
    model = joblib.load(MODEL_PATH)
    console_logger.info("✅ ML pipeline loaded successfully")

    # Fixed: Access feature_names_in_ safely; it's on the pipeline (inherited from scaler)
    if hasattr(model, "feature_names_in_"):
        required_features = list(model.feature_names_in_)
        console_logger.info(f"Model expects {len(required_features)} features: {required_features[:5]}...")
    else:
        console_logger.error("Model does not contain feature names. Falling back to ML disabled.")
        required_features = []
        raise Exception("Missing feature names")

    ml_enabled = True

except Exception as e:
    console_logger.warning(f"⚠ Failed to load ML model: {e}. Running without ML.")
    ml_enabled = False
    required_features = []

# ======================================
# USER INPUT
# ======================================

target_ip = input("Enter Target IP: ").strip()

interfaces = scapy.get_if_list()
print("\nAvailable Interfaces:")
for i, iface in enumerate(interfaces):
    print(f"{i}: {iface}")

iface_index = int(input("Select interface number: "))
MONITOR_INTERFACE = interfaces[iface_index]

console_logger.info(f"🚀 Monitoring {target_ip} on {MONITOR_INTERFACE}")

# ======================================
# FLOW ENGINE
# ======================================

def new_flow():
    return {
        "start_time": time.time(),
        "last_seen": time.time(),
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "fwd_pkt_len": [],
        "bwd_pkt_len": [],
        "fwd_iat": [],
        "bwd_iat": [],
        "last_fwd_time": None,
        "last_bwd_time": None,
        "syn": 0,
        "ack": 0,
        "fin": 0,
        "rst": 0,
        "psh": 0,
        "urg": 0,
        "proto": 6  # Default TCP
    }

def get_flow_key(pkt):
    ip = pkt[scapy.IP]

    if pkt.haslayer(scapy.TCP):
        proto = 6
        sport = pkt[scapy.TCP].sport
        dport = pkt[scapy.TCP].dport
    elif pkt.haslayer(scapy.UDP):
        proto = 17
        sport = pkt[scapy.UDP].sport
        dport = pkt[scapy.UDP].dport
    else:
        proto = 1
        sport = 0
        dport = 0

    return (ip.src, ip.dst, sport, dport, proto)

def reverse_key(key):
    src, dst, sport, dport, proto = key
    return (dst, src, dport, sport, proto)

# ======================================
# PACKET HANDLER (THREAD SAFE)
# ======================================

def packet_callback(pkt):
    global packet_count

    if not pkt.haslayer(scapy.IP):
        return

    ip = pkt[scapy.IP]

    if ip.dst != target_ip and ip.src != target_ip:
        return

    packet_count += 1  # Count packets
    source_counter[ip.src] += 1  # Track sources

    key = get_flow_key(pkt)
    rev = reverse_key(key)
    now = time.time()

    with flow_lock:

        if key in flows:
            flow = flows[key]
            direction = "fwd"
        elif rev in flows:
            flow = flows[rev]
            direction = "bwd"
        else:
            flows[key] = new_flow()
            flow = flows[key]
            flow["proto"] = key[4]  # Set protocol
            direction = "fwd"

        flow["last_seen"] = now
        pkt_len = len(pkt)

        if direction == "fwd":
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt_len
            flow["fwd_pkt_len"].append(pkt_len)

            if flow["last_fwd_time"]:
                flow["fwd_iat"].append(now - flow["last_fwd_time"])
            flow["last_fwd_time"] = now

        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt_len
            flow["bwd_pkt_len"].append(pkt_len)

            if flow["last_bwd_time"]:
                flow["bwd_iat"].append(now - flow["last_bwd_time"])
            flow["last_bwd_time"] = now

        if pkt.haslayer(scapy.TCP):
            tcp = pkt[scapy.TCP]
            if tcp.flags & 0x02: flow["syn"] += 1
            if tcp.flags & 0x10: flow["ack"] += 1
            if tcp.flags & 0x01: flow["fin"] += 1
            if tcp.flags & 0x04: flow["rst"] += 1
            if tcp.flags & 0x08: flow["psh"] += 1
            if tcp.flags & 0x20: flow["urg"] += 1

# ======================================
# FEATURE COMPUTATION
# ======================================

def safe_stats(arr):
    if len(arr) == 0:
        return 0, 0
    return np.mean(arr), np.std(arr)

def compute_feature_dict(flow):
    # Improvement: Added checks for infinite values and more robust stats
    duration = max(flow["last_seen"] - flow["start_time"], 1e-6)
    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

    fwd_len_mean, fwd_len_std = safe_stats(flow["fwd_pkt_len"])
    bwd_len_mean, bwd_len_std = safe_stats(flow["bwd_pkt_len"])
    fwd_iat_mean, fwd_iat_std = safe_stats(flow["fwd_iat"])
    bwd_iat_mean, bwd_iat_std = safe_stats(flow["bwd_iat"])

    # Handle potential inf/NaN (improvement)
    flow_bytes_per_sec = total_bytes / duration if duration > 0 else 0
    flow_packets_per_sec = total_packets / duration if duration > 0 else 0

    return {
        "Flow Duration": duration,
        "Total Fwd Packets": flow["fwd_packets"],
        "Total Backward Packets": flow["bwd_packets"],
        "Total Length of Fwd Packets": flow["fwd_bytes"],
        "Total Length of Bwd Packets": flow["bwd_bytes"],
        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_packets_per_sec,
        "Fwd Packet Length Mean": fwd_len_mean,
        "Fwd Packet Length Std": fwd_len_std,
        "Bwd Packet Length Mean": bwd_len_mean,
        "Bwd Packet Length Std": bwd_len_std,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "SYN Flag Count": flow["syn"],
        "ACK Flag Count": flow["ack"],
        "FIN Flag Count": flow["fin"],
        "RST Flag Count": flow["rst"],
        "PSH Flag Count": flow["psh"],
        "URG Flag Count": flow["urg"],
    }

# ======================================
# CLASSIFY ATTACK TYPE (Improved Heuristics)
# ======================================

def classify_attack(flow, packets_per_sec):
    # Improved: Based on packets/s, flags, protocol
    syn = flow["syn"]
    ack = flow["ack"]
    rst = flow["rst"]
    fwd_packets = flow["fwd_packets"]
    total_packets = fwd_packets + flow["bwd_packets"]
    proto = flow.get("proto", 6)

    if proto == 17 and packets_per_sec > 1000:  # UDP high rate
        return "UDP Flood"
    elif syn > ack * 2 and fwd_packets > 50:  # High SYN, low ACK
        return "SYN Flood"
    elif rst > syn and fwd_packets > 50:  # High RST
        return "RST Flood"
    elif packets_per_sec > 500:  # Generic high rate
        return "Generic Flood"
    else:
        return "Potential Attack"  # Instead of Unknown

# ======================================
# ALERT (Improved: Aggregate, with Emphasis, Detailed Logging, Cooldown Applied)
# ======================================

def trigger_alert(attack_type, avg_confidence, alerted_count, top_sources, confidences, flows_data):
    global last_alert_time

    now = time.time()
    if now - last_alert_time < ALERT_COOLDOWN:
        return  # Skip if within cooldown

    last_alert_time = now  # Update last alert time

    # Make it prominent with bold and larger
    large_alert = "🚨🚨🚨   D D O S   D E T E C T E D   🚨🚨🚨"

    console_logger.warning(large_alert)
    console_logger.warning(f"Attack Type: {attack_type}")
    console_logger.warning(f"Avg Confidence: {avg_confidence:.3f}")
    console_logger.warning(f"Alerted Flows: {alerted_count}")

    # Detailed logging to file
    logging.info(f"DDoS Detected - Type: {attack_type}, Avg Confidence: {avg_confidence:.3f}, Alerted Flows: {alerted_count}")
    logging.info(f"Top Sources: {top_sources}")
    logging.info(f"Confidence Details: {confidences}")
    logging.info(f"Flows Data: {flows_data}")  # Detailed flow info

# ======================================
# DETECTION LOOP (THREAD SAFE, Summary on New Lines)
# ======================================

def detection_loop():
    global flows, alerted_flows, packet_count, source_counter, alert_count

    while scanning:
        time.sleep(TIME_WINDOW)
        current_time = time.time()

        with flow_lock:
            flow_items = list(flows.items())

        expired = []
        new_alerts = []
        confidences = []
        flows_data = []

        for key, flow in flow_items:

            if current_time - flow["last_seen"] > FLOW_TIMEOUT:

                if ml_enabled:
                    try:
                        feature_dict = compute_feature_dict(flow)
                        packets_per_sec = feature_dict["Flow Packets/s"]
                        aligned = {col: feature_dict.get(col, 0) for col in required_features}
                        df = pd.DataFrame([aligned])
                        df = df[required_features]

                        # Fixed: Use .values to pass numpy array, avoiding feature name warnings
                        probs = model.predict_proba(df.values)[0]
                        score = np.max(probs)

                        if score > ALERT_THRESHOLD:
                            attack_type = classify_attack(flow, packets_per_sec)
                            new_alerts.append((attack_type, score))
                            confidences.append(score)
                            alerted_flows.append(key)
                            alert_count += 1
                            flows_data.append({"key": key, "features": feature_dict, "score": score})

                    except Exception as e:
                        console_logger.error(f"Prediction error for flow {key}: {e}")

                expired.append(key)

        if expired:
            with flow_lock:
                for key in expired:
                    flows.pop(key, None)

        # Summary on new lines
        console_logger.info(f"📊 Summary: Packets: {packet_count}, Flows: {len(flows)}, Alerts: {len(new_alerts)}")
        if source_counter:
            top_sources = source_counter.most_common(3)
            console_logger.info(f"Top Sources: {top_sources}")

        if len(new_alerts) > 0:
            attack_types = Counter([a[0] for a in new_alerts])
            avg_conf = np.mean(confidences) if confidences else 0
            top_attack = attack_types.most_common(1)[0][0]
            top_sources = source_counter.most_common(3)
            trigger_alert(top_attack, avg_conf, len(new_alerts), top_sources, confidences, flows_data)

        # Reset counters
        packet_count = 0
        alert_count = 0
        source_counter.clear()
        alerted_flows = []

# ======================================
# START
# ======================================

if __name__ == "__main__":

    sniff_thread = threading.Thread(
        target=lambda: scapy.sniff(
            iface=MONITOR_INTERFACE,
            prn=packet_callback,
            store=False,
            filter=f"ip and host {target_ip}",
            stop_filter=lambda x: not scanning
        )
    )

    detect_thread = threading.Thread(target=detection_loop)

    sniff_thread.start()
    detect_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping detector...")
        scanning = False
        try:
            sniff_thread.join(timeout=5)  # Timeout to avoid hang
        except:
            pass
        try:
            detect_thread.join(timeout=5)
        except:
            pass
        print("✅ Detector stopped cleanly.")
