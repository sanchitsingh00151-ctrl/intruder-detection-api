import re
from collections import defaultdict
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

LOG_PATH = r"D:\Projects\Intruder Detection\server.log"



def extract_ip(line):
    m = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
    return m[0] if m else None


def extract_time(line):
    m = re.search(r"\[(.*?)\]", line)
    return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S") if m else None


def extract_status(line):
    m = re.search(r'" (\d{3}) ', line)
    return int(m.group(1)) if m else 200


def extract_url(line):
    m = re.search(r'"GET (.*?) HTTP', line)
    return m.group(1) if m else "/"


def build_features(file_path):
    ip_times = defaultdict(list)
    ip_errors = defaultdict(int)
    ip_urls = defaultdict(set)

    with open(file_path, "r") as f:
        for line in f:
            ip = extract_ip(line)
            t = extract_time(line)
            status = extract_status(line)
            url = extract_url(line)

            if not ip or not t:
                continue

            ip_times[ip].append(t)
            ip_urls[ip].add(url)
            if status >= 400:
                ip_errors[ip] += 1

    features, ip_list = [], []

    for ip in ip_times:
        times = sorted(ip_times[ip])
        req_count = len(times)

        gaps = [(times[i] - times[i-1]).total_seconds()
                for i in range(1, len(times))]
        avg_gap = np.mean(gaps) if gaps else 0

        error_rate = ip_errors[ip] / req_count
        unique_urls = len(ip_urls[ip])

        features.append([req_count, avg_gap, error_rate, unique_urls])
        ip_list.append(ip)

    return np.array(features), ip_list


# Behavior Fingerprint

def fingerprint(req, gap, err, urls, avg):
    labels = []

    if req > avg[0] * 2:
        labels.append("Flooder/Bot-like")

    if gap < avg[1] * 0.5:
        labels.append("Automated Script")

    if err > avg[2] * 2:
        labels.append("Brute-force/Probing")

    if urls > avg[3] * 2:
        labels.append("Scanner/Reconaissance")

    if not labels:
        labels.append("Normal Browsing Pattern")

    return ", ".join(labels)


#Detection

def detect_anomalies(features, ip_list):
    model = IsolationForest(n_estimators=200,
                            contamination='auto',
                            random_state=42)

    model.fit(features)
    scores = model.decision_function(features)

    THRESHOLD = -0.04
    avg = np.mean(features, axis=0)

    print("\n=== Anomalyze Behavioral Threat Report ===\n")

    for i, score in enumerate(scores):
        risk_score = int(abs(score) * 400)  # convert to /100 scale
        req, gap, err, urls = features[i]

        behavior = fingerprint(req, gap, err, urls, avg)

        print(f"IP: {ip_list[i]}")
        print(f"Anomaly Score : {score:.4f}")
        print(f"Risk Score    : {risk_score}/100")
        print(f"Behavior Type : {behavior}")

        if score < THRESHOLD:
            print("Action        : [Simulated] IP would be BLOCKED by firewall 🚫")
        else:
            print("Action        : Allowed ✅")

        print("-" * 60)

    #  Visualization(graphs)
    plt.figure()
    plt.title("Anomalyze — Anomaly Scores per IP")
    plt.plot(scores, marker='o')
    plt.xlabel("IP Index")
    plt.ylabel("Anomaly Score")
    plt.show()


#Main

if __name__ == "__main__":
    feats, ips = build_features(LOG_PATH)
    detect_anomalies(feats, ips)
