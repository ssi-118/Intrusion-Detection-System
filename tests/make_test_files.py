from pathlib import Path
import pandas as pd

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

normal_http = {
    "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
    "src_bytes": 181, "dst_bytes": 5450, "land": 0, "wrong_fragment": 0,
    "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
    "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
    "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
    "count": 8, "srv_count": 8, "serror_rate": 0.0, "srv_serror_rate": 0.0,
    "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 9,
    "dst_host_srv_count": 9, "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 0.11,
    "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0
}

malicious_syn_like = {
    "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
    "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
    "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
    "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
    "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
    "count": 250, "srv_count": 5, "serror_rate": 1.0, "srv_serror_rate": 1.0,
    "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 0.02,
    "diff_srv_rate": 0.08, "srv_diff_host_rate": 0.0, "dst_host_count": 255,
    "dst_host_srv_count": 5, "dst_host_same_srv_rate": 0.02,
    "dst_host_diff_srv_rate": 0.08, "dst_host_same_src_port_rate": 0.0,
    "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 1.0,
    "dst_host_srv_serror_rate": 1.0, "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0
}

malicious_probe_like = {
    "duration": 0, "protocol_type": "icmp", "service": "eco_i", "flag": "SF",
    "src_bytes": 1032, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
    "urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 0,
    "num_compromised": 0, "root_shell": 0, "su_attempted": 0, "num_root": 0,
    "num_file_creations": 0, "num_shells": 0, "num_access_files": 0,
    "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
    "count": 511, "srv_count": 511, "serror_rate": 0.0, "srv_serror_rate": 0.0,
    "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0, "dst_host_count": 255,
    "dst_host_srv_count": 255, "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0, "dst_host_same_src_port_rate": 1.0,
    "dst_host_srv_diff_host_rate": 0.0, "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0, "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0
}

out_dir = Path(__file__).resolve().parent
out_dir.mkdir(exist_ok=True)

normal_df = pd.DataFrame([normal_http], columns=FEATURE_COLUMNS)
malicious_df = pd.DataFrame([malicious_syn_like, malicious_probe_like], columns=FEATURE_COLUMNS)
mixed_df = pd.DataFrame(
    [normal_http, malicious_syn_like, normal_http, malicious_probe_like],
    columns=FEATURE_COLUMNS
)

normal_df.to_csv(out_dir / "test_normal.csv", index=False)
malicious_df.to_csv(out_dir / "test_malicious_like.csv", index=False)
mixed_df.to_csv(out_dir / "test_mixed.csv", index=False)

kdd_format = mixed_df.copy()
kdd_format["label"] = ["normal", "neptune", "normal", "smurf"]
kdd_format["difficulty"] = [21, 21, 21, 21]
kdd_format.to_csv(out_dir / "test_kdd_format.txt", index=False, header=False)

print("Created:")
for file in out_dir.iterdir():
    print(file)
