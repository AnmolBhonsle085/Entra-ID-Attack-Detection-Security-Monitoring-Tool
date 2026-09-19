**Entra ID Attack Detection & Security Monitoring Tool**

A Python-based security monitoring tool that analyzes Microsoft Entra ID-style sign-in logs and detects common identity-based security threats. The project demonstrates SOC detection concepts such as brute-force detection, suspicious IP identification, OAuth application monitoring, and MFA failure detection.

**Note:** This project uses a simulated/sample Entra ID sign-in dataset for detection and testing. It does not retrieve live Microsoft Entra ID logs.

**Features**

Brute-Force Detection
Identifies users with multiple failed login attempts.
Threshold: 5 or more failed attempts.
Suspicious IP Detection
Detects IP addresses attempting authentication against multiple users.
Helps identify password spraying or credential attack activity.
Suspicious OAuth Application Detection
Identifies high-risk sign-ins involving suspicious/unknown OAuth applications.
MFA Failure Detection
Detects repeated MFA challenge failures.
Risky Sign-In Detection
Identifies sign-ins marked with medium or high risk levels.
Security Alert Report
Automatically exports detected alerts to a CSV file for investigation.

**Technologies Used**
Python
Pandas
Microsoft Entra ID concepts
Identity & Access Management (IAM)
Security Monitoring
Detection Engineering
CSV Log Analysis

**Project Structure**
entra-id-attack-detector/
│
├── Data/
│   └── entra_id_sample_signin_logs.csv
│
├── reports/
│   └── security_alerts.csv
│
├── detector.py
│
└── README.md

**How It Works**
Sample Entra ID Sign-In Logs
            ↓
       Python / Pandas
            ↓
      Detection Rules
            ↓
    Security Alert Output
            ↓
     security_alerts.csv

The Python script reads the sign-in logs, applies predefined detection rules, identifies suspicious authentication activity, and generates a structured security alert report.

**Detection Logic**
Detection	Logic	Severity
Brute Force	≥5 failed login attempts by a user	High
Suspicious IP	IP targets ≥2 different users	High
Suspicious OAuth	High-risk sign-in involving OAuth/unknown application	High
MFA Failure	MFA challenge failure detected	Medium
Risky Sign-In	Sign-in risk marked medium/high	Medium/High

**Installation & Usage**

Install the required Python library:

python -m pip install pandas

Run the detector:

python detector.py

The generated security alerts are saved to:

reports/security_alerts.csv

**Example Detection Output**

The tool can generate alerts such as:

High, Brute Force, rahul@contoso.onmicrosoft.com, 12 failed login attempts

High, Suspicious IP, 185.220.10.15, Targeted 4 different users

High, Suspicious OAuth, anmol@contoso.onmicrosoft.com, 91.198.174.10, Unknown OAuth Application

Medium, MFA Failure, priya@contoso.onmicrosoft.com, 51.89.22.71, MFA challenge denied

**Security Concepts Demonstrated**
Identity-based threat detection
Authentication monitoring
Brute-force detection
Password-spraying indicators
Suspicious IP analysis
OAuth security monitoring
MFA monitoring
Risk-based authentication
Security alert generation
Basic detection engineering

**Future Enhancements**
Microsoft Graph API integration for authorized live Entra ID data
Automated alert notifications
Additional identity attack detections
Dashboard/visualization
MITRE ATT&CK technique mapping
Automated incident response workflows

**Limitations**
This project currently analyzes a simulated/sample dataset rather than live Microsoft Entra ID telemetry. Detection thresholds are designed for demonstration and portfolio purposes and would require tuning for a production environment.

**Project Purpose**

This project was developed to demonstrate practical SOC monitoring, identity security, log analysis, and detection engineering skills using Python and Microsoft Entra ID concepts.
