import pandas as pd
import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")


def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        return (
            f"Malicious: {stats['malicious']} | "
            f"Suspicious: {stats['suspicious']} | "
            f"Harmless: {stats['harmless']}"
        )

    return f"Lookup failed: HTTP {response.status_code}"
# Load Entra ID sign-in logs
logs = pd.read_csv("Data/entra_id_sample_signin_logs.csv")

print("\n=== Entra ID Attack Detector ===")

# Failed login attempts
failed_logins = logs[
    logs["status"].str.lower() == "failure"
]

print("\n=== Failed Logins by User ===")

failed_counts = failed_logins["userPrincipalName"].value_counts()

print(failed_counts)

# Brute-force detection
print("\n=== 🚨 Security Alerts ===")

for user, count in failed_counts.items():

    if count >= 5:
        print(
            f"🚨 BRUTE FORCE DETECTED: {user} "
            f"had {count} failed login attempts."
        )
# Suspicious IP detection
print("\n=== Suspicious IP Alerts ===")

ip_users = logs.groupby("ipAddress")["userPrincipalName"].nunique()

vt_results = {}

for ip, user_count in ip_users.items():
    if user_count >= 2:
        print(
            f"🚨 SUSPICIOUS IP: {ip} "
            f"attempted logins against {user_count} different users."
        )

        vt_result = check_ip_virustotal(ip)
        vt_results[ip] = vt_result

        print(f"   🔎 VirusTotal: {vt_result}")

oauth_alerts = logs[
    (logs["riskLevel"].astype(str).str.lower() == "high") &
    (logs["appDisplayName"].astype(str).str.lower().str.contains("oauth|unknown"))
]

for _, row in oauth_alerts.iterrows():
    print(
        f"🚨 SUSPICIOUS OAUTH APPLICATION: "
        f"{row['appDisplayName']} | "
        f"User: {row['userPrincipalName']} | "
        f"IP: {row['ipAddress']} | "
        f"Risk: {row['riskLevel']}"
    )
    # MFA failure detection
mfa_failures = logs[
    logs["failureReason"].astype(str).str.contains(
        "MFA", case=False, na=False
    )
]

print("\n=== MFA Failure Alerts ===")

for _, row in mfa_failures.iterrows():
    print(
        f"🚨 MFA FAILURE: User: {row['userPrincipalName']} | "
        f"IP: {row['ipAddress']} | "
        f"Reason: {row['failureReason']}"
    )
# Risky sign-ins
risky = logs[
    logs["riskLevel"].astype(str).str.lower().isin(["medium", "high"])
]

print("\n=== Risky Sign-ins ===")

print(
    risky[
        [
            "timestamp",
            "userPrincipalName",
            "ipAddress",
            "riskLevel",
            "appDisplayName"
        ]
    ].to_string(index=False)
)

print("\n=== Detection Complete ===")
# Generate CSV security alert report

alerts = []

# Brute-force alerts
for user, count in failed_counts.items():
    if count >= 5:
        alerts.append({
            "Severity": "High",
            "Detection": "Brute Force",
            "User": user,
            "IP": "",
            "Details": f"{count} failed login attempts"
        })

# Suspicious IP alerts
for ip, user_count in ip_users.items():
    if user_count >= 2:
        vt_result = vt_results.get(ip, "Not checked")

        alerts.append({
            "Severity": "High",
            "Detection": "Suspicious IP",
            "User": "",
            "IP": ip,
            "Details": f"Targeted {user_count} different users | VirusTotal: {vt_result}"
        })
# OAuth alerts
for _, row in oauth_alerts.iterrows():
    alerts.append({
        "Severity": "High",
        "Detection": "Suspicious OAuth",
        "User": row["userPrincipalName"],
        "IP": row["ipAddress"],
        "Details": row["appDisplayName"]
    })

# MFA alerts
for _, row in mfa_failures.iterrows():
    alerts.append({
        "Severity": "Medium",
        "Detection": "MFA Failure",
        "User": row["userPrincipalName"],
        "IP": row["ipAddress"],
        "Details": row["failureReason"]
    })
    # Save alerts
alerts_df = pd.DataFrame(alerts)

import os
os.makedirs("reports", exist_ok=True)

alerts_df.to_csv(
    "reports/security_alerts.csv",
    index=False
)

print("\n=== Alert Report Generated ===")
print("reports/security_alerts.csv")