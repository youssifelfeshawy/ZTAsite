import joblib
import pandas as pd
import numpy as np
from river.linear_model import LogisticRegression as RiverLR
from scapy.all import rdpcap  # Fallback if needed
import subprocess
import time
import os
import sys
from keycloak import KeycloakAdmin

# from keycloak.connection import KeycloakConnection
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import shutil

# Load saved components
meta_model = joblib.load("/opt/ml-models/meta_model.pkl")
base_models = joblib.load("/opt/ml-models/base_models.pkl")
scaler = joblib.load("/opt/ml-models/scaler.pkl")

# Initialize KeycloakAdmin
admin = KeycloakAdmin(
    server_url="http://192.168.1.134:8080",  # Auth VM IP
    username="keycloak",  # Keycloak admin user
    password="keycloak",  # Change this!
    realm_name="master",  # Your realm
    verify=False,  # Set False if self-signed cert
)

# Model's expected columns (from training: adjust if needed)
EXPECTED_COLUMNS = [
    "srcip",
    "sport",
    "dstip",
    "dsport",
    "proto",
    "state",
    "dur",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "sloss",
    "dloss",
    "service",
    "Sload",
    "Dload",
    "Spkts",
    "Dpkts",
    "swin",
    "dwin",
    "stcpb",
    "dtcpb",
    "smeansz",
    "dmeansz",
    "trans_depth",
    "res_bdy_len",
    "Sjit",
    "Djit",
    "Stime",
    "Ltime",
    "Sintpkt",
    "Dintpkt",
    "tcprtt",
    "synack",
    "ackdat",
    "is_sm_ips_ports",
    "ct_state_ttl",
    "ct_flw_http_mthd",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_srv_src",
    "ct_srv_dst",
    "ct_dst_ltm",
    "ct_src_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "attack_cat",
    "label",
]


def extract_features_from_pcap(pcap_file):
    pcap_dir = "/tmp/pcap_dir"
    csv_dir = "/tmp/csv_out"
    # Create fresh directories
    if os.path.exists(pcap_dir):
        shutil.rmtree(pcap_dir)
    if os.path.exists(csv_dir):
        shutil.rmtree(csv_dir)
    os.makedirs(pcap_dir)
    os.makedirs(csv_dir)
    # Move the captured pcap into the processing directory
    shutil.move(pcap_file, os.path.join(pcap_dir, "live_capture.pcap"))
    # Run CICFlowMeter CLI to extract features
    pcap_path = os.path.join(pcap_dir, "live_capture.pcap")
    csv_file_path = os.path.join(csv_dir, "live_capture_Flow.csv")
    bin_dir = os.path.dirname(sys.executable)
    cic_path = os.path.join(bin_dir, "cicflowmeter")
    subprocess.run([cic_path, "-f", pcap_path, "-c", csv_file_path])
    if os.path.exists(csv_file_path) and os.path.getsize(csv_file_path) > 0:
        df = pd.read_csv(csv_file_path)
        # CICFlowMeter column mappings (title-case to your mixed-case; added approximations)
        column_mapping = {
            "Src IP": "srcip",
            "Dst IP": "dstip",
            "Protocol": "proto",
            "Src Port": "sport",
            "Dst Port": "dsport",
            "Flow Duration": "dur",
            "TotLen Fwd Pkts": "sbytes",
            "TotLen Bwd Pkts": "dbytes",
            "Tot Fwd Pkts": "Spkts",
            "Tot Bwd Pkts": "Dpkts",
            "Fwd Pkt Len Mean": "smeansz",
            "Bwd Pkt Len Mean": "dmeansz",
            "Flow Bytes/s": "Sload",  # Approx; duplicate for Dload
            "Flow Bytes/s": "Dload",
            "Fwd IAT Mean": "Sjit",
            "Bwd IAT Mean": "Djit",
            "Fwd IAT Tot": "Sintpkt",
            "Bwd IAT Tot": "Dintpkt",
            "Init Fwd Win Byts": "swin",
            "Init Bwd Win Byts": "dwin",
            "Fwd Seg Size Min": "stcpb",  # Approx
            "Bwd Seg Size Min": "dtcpb",
            "Timestamp": "Stime",
            "Last Time": "Ltime",
            "PSH Flag Cnt": "trans_depth",  # Approx
            "Fwd PSH Flags": "ct_flw_http_mthd",  # Approx HTTP/flag
            "Response Body Len": "res_bdy_len",
            "Flow IAT Mean": "tcprtt",  # Approx
            "Fwd Header Len": "synack",  # Approx
            "Bwd Header Len": "ackdat",
            # Approx loss if CIC has it (some versions do)
            "Fwd Pkts Lost": "sloss",
            "Bwd Pkts Lost": "dloss",
            # No direct for ct_*, sttl/dttl; fill 0
        }
        df.rename(columns=column_mapping, inplace=True)
        # Align to expected columns
        df = df.reindex(columns=EXPECTED_COLUMNS, fill_value=0)
        df = df.dropna(subset=["srcip", "dstip"])
        # Handle categoricals (include srcip/dstip as in training)
        cat_cols = ["srcip", "dstip", "proto", "state", "service", "attack_cat"]
        le_dict = {}
        for col in cat_cols:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str).fillna("unknown"))
                le_dict[col] = le
        # Drop columns dropped in training (updated list to fix unseen features)
        dropped_in_training = [
            "sloss",
            "dloss",
            "Dpkts",
            "dwin",
            "Ltime",
            "ct_srv_dst",
            "ct_src_dport_ltm",
            "ct_dst_src_ltm",
            "is_ftp_login",
            "ct_flw_http_mthd",
            "ct_ftp_cmd",  # Added to resolve current error
        ]
        # Scale features (exclude labels)
        features = df.drop(columns=["label", "attack_cat"], errors="ignore")
        features = features.drop(columns=dropped_in_training, errors="ignore")
        features[features.columns] = scaler.transform(features)
        df[features.columns] = features  # Merge scaled back
        df["srcip"] = df["srcip"].astype(str)
        return df
    return pd.DataFrame()


def get_trust_metrics(data):
    """
    Generate trust metrics from base models for each attack type.
    """
    metrics = []
    for attack, info in base_models.items():
        # Check if all required features are present (updated check)
        if not all(feature in data.columns for feature in info["features"]):
            continue  # Skip if any features missing
        X_sel = data[info["features"]]
        if "Sequential" in str(type(info["model"])):
            pred = info["model"].predict(X_sel.values).flatten()  # For ANN/TF models
        else:
            pred = info["model"].predict(X_sel.values)  # For sklearn models like RF
        metrics.append((pred > info["threshold"]).astype(int))
    return np.column_stack(metrics) if metrics else np.array([])


def predict(flow_data):
    """
    Run prediction on flow data and collect bad IPs for alerting.
    """
    metrics = get_trust_metrics(flow_data)
    if metrics.size == 0:
        return []

    predictions = []
    bad_ips = []  # Collect unique bad IPs
    for idx, x in enumerate(metrics):
        x_dict = {f"feat_{i}": float(val) for i, val in enumerate(x)}
        pred = meta_model.predict_one(x_dict)  # 0/1 (normal/attack)
        predictions.append(pred)
        if pred == 1:
            bad_ip = flow_data.iloc[idx]["srcip"]
            if bad_ip not in bad_ips:
                bad_ips.append(bad_ip)
            print(f"Alert: Attack detected from IP {bad_ip}")

    # Revoke sessions for bad IPs
    revoke_sessions_for_ips(bad_ips)

    return predictions


def revoke_sessions_for_ips(bad_ips):
    """
    Revoke Keycloak sessions for users from bad IPs.
    """
    if not bad_ips:
        return

    try:
        users = admin.get_users({"realm": "ZTAsite"})
        for user in users:
            user_id = user["id"]
            sessions = admin.get_user_sessions(user_id=user_id)
            for session in sessions:
                if "ipAddress" in session and session["ipAddress"] in bad_ips:
                    admin.delete_session(session_id=session["id"])
                    print(
                        f"Revoked session {session['id']} for user {user['username']} from IP {session['ipAddress']}"
                    )
                    # Optional: Revoke all for user - admin.logout_user(user_id)
    except Exception as e:
        print(f"Error revoking sessions: {e}")


# Real-time loop: Capture PCAP every 10s, process
if __name__ == "__main__":
    while True:
        pcap_file = "/tmp/live_capture.pcap"
        # Capture on users interface (any), 1000 packets
        subprocess.run(["sudo", "tcpdump", "-i", "any", "-w", pcap_file, "-c", "30"])

        flow_df = extract_features_from_pcap(pcap_file)
        if not flow_df.empty:
            preds = predict(flow_df)
            for idx, pred in enumerate(preds):
                if pred == 1:
                    print(f"Potential attack in flow {idx}")

        time.sleep(10)  # Adjust interval
        if os.path.exists(pcap_file):
            os.remove(pcap_file)  # Clean up
