import joblib
import pandas as pd
import numpy as np
from river.linear_model import LogisticRegression as RiverLR
from scapy.all import rdpcap  # Fallback if needed
import subprocess
import time
import os
from keycloak import KeycloakAdmin
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Load saved components
meta_model = joblib.load("/opt/ml-models/meta_model.pkl")
base_models = joblib.load("/opt/ml-models/base_models.pkl")
scaler = joblib.load("/opt/ml-models/scaler.pkl")

# Initialize KeycloakAdmin
KEYCLOAK_URL = "http://192.168.1.134:8080"  # Auth VM IP
admin = KeycloakAdmin(
    server_url=KEYCLOAK_URL + "/auth/",
    username="admin",  # Keycloak admin user
    password="admin",  # Change this!
    realm_name="ZTAsite",  # Your realm
    verify=True,  # Set False if self-signed cert
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
    """
    Extract flow features from PCAP using CICFlowMeter.
    Preprocess to match model's expected format.
    """
    # Run CICFlowMeter via subprocess
    subprocess.run(
        [
            "java",
            "-jar",
            "/opt/cicflowmeter/CICFlowMeter.jar",
            pcap_file,
            "/tmp/features.csv",
        ]
    )

    if os.path.exists("/tmp/features.csv") and os.path.getsize("/tmp/features.csv") > 0:
        df = pd.read_csv("/tmp/features.csv")

        # CICFlowMeter column mappings (common ones; adjust based on exact output)
        column_mapping = {
            "Src IP": "srcip",
            "Dst IP": "dstip",
            "Protocol": "proto",
            "Source Port": "sport",
            "Destination Port": "dsport",
            "Flow Duration": "dur",
            "Total Source Bytes": "sbytes",
            "Total Destination Bytes": "dbytes",
            "Source TTL": "sttl",
            "Destination TTL": "dttl",
            # Add more mappings as needed (e.g., 'Packet Length Mean' -> 'smeansz'/'dmeansz')
            # For missing: fill with defaults or drop rows
        }
        df.rename(columns=column_mapping, inplace=True)

        # Select and align to expected columns (drop extras, fill missing)
        df = df.reindex(
            columns=EXPECTED_COLUMNS, fill_value=0
        )  # Fill NaN with 0 for numerics
        df = df.dropna(subset=["srcip", "dstip"])  # Drop invalid flows

        # Handle categoricals (e.g., proto, state, service)
        cat_cols = ["proto", "state", "service", "attack_cat"]  # Adjust
        le_dict = {}  # Store encoders for consistency
        for col in cat_cols:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str).fillna("unknown"))
                le_dict[col] = le

        # Scale features (exclude labels)
        features = df.drop(columns=["label", "attack_cat"], errors="ignore")
        df[features.columns] = scaler.transform(features)

        # Ensure 'srcip' is string for later use
        df["srcip"] = df["srcip"].astype(str)

        return df
    return pd.DataFrame()  # Empty if failed


def get_trust_metrics(data):
    """
    Generate trust metrics from base models for each attack type.
    """
    metrics = []
    for attack, info in base_models.items():
        if info["features"] not in data.columns.tolist():
            continue  # Skip if features missing
        X_sel = data[info["features"]]
        X_sel_scaled = scaler.transform(X_sel)
        if "Sequential" in str(type(info["model"])):
            pred = info["model"].predict(X_sel_scaled).flatten()
        else:
            pred = info["model"].predict(X_sel_scaled)
        metrics.append((pred > info["threshold"]).astype(int))  # Binary decisions
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
        # Capture on users interface (enp0s10), 1000 packets
        subprocess.run(
            ["sudo", "tcpdump", "-i", "enp0s10", "-w", pcap_file, "-c", "1000"]
        )

        flow_df = extract_features_from_pcap(pcap_file)
        if not flow_df.empty:
            preds = predict(flow_df)
            for idx, pred in enumerate(preds):
                if pred == 1:
                    print(f"Potential attack in flow {idx}")

        time.sleep(10)  # Adjust interval
        if os.path.exists(pcap_file):
            os.remove(pcap_file)  # Clean up
