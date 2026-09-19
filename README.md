# Microsoft Entra ID Attack Detection & Identity Security Monitoring Tool

A Python-based security monitoring tool that analyzes simulated Microsoft Entra ID sign-in logs to detect identity-based threats and enrich suspicious IP addresses using the VirusTotal API.

> **Note:** The Entra ID sign-in logs used in this project are simulated/sample data for detection and testing. The project does not retrieve live Entra ID telemetry.

## Features

- **Brute-Force Detection**
  - Detects users with 5 or more failed login attempts.

- **Suspicious IP Detection**
  - Identifies IP addresses attempting authentication against multiple users.
  - Helps identify potential password-spraying activity.

- **Suspicious OAuth Application Detection**
  - Detects high-risk sign-ins involving suspicious or unknown OAuth applications.

- **MFA Failure Detection**
  - Identifies failed MFA challenges.

- **Risky Sign-In Detection**
  - Identifies sign-ins with medium or high risk levels.

- **VirusTotal IP Reputation**
  - Automatically checks detected suspicious IP addresses against VirusTotal.
  - Retrieves malicious, suspicious, and harmless detection statistics.

- **Security Alert Reporting**
  - Generates a structured CSV security-alert report for investigation.

## Technologies Used

- Python
- Pandas
- Requests
- Microsoft Entra ID
- VirusTotal API
- Identity & Access Management (IAM)
- Security Monitoring
- Detection Engineering
- Threat Intelligence
- CSV Log Analysis

## Project Structure

    entra-id-attack-detector/
    ├── Data/
    │   └── entra_id_sample_signin_logs.csv
    ├── reports/
    │   └── security_alerts.csv
    ├── detector.py
    ├── README.md
    └── .gitignore

## How It Works

    Simulated Entra ID Sign-In Logs
                  ↓
            Python / Pandas
                  ↓
            Detection Rules
                  ↓
           Suspicious IP Found
                  ↓
            VirusTotal API
                  ↓
          IP Reputation Check
                  ↓
           Security Alert Report

The Python script reads the simulated Entra ID sign-in logs, applies predefined detection rules, identifies suspicious authentication activity, and performs VirusTotal reputation checks on detected suspicious IP addresses.

## Detection Logic

| Detection | Logic | Severity |
|---|---|---|
| Brute Force | ≥5 failed login attempts by a user | High |
| Suspicious IP | IP targets ≥2 different users | High |
| Suspicious OAuth | High-risk sign-in involving OAuth/unknown application | High |
| MFA Failure | MFA challenge failure detected | Medium |
| Risky Sign-In | Sign-in risk marked medium/high | Medium/High |

## VirusTotal Integration

When a suspicious IP is detected, the tool automatically queries the VirusTotal API to obtain IP reputation information.

Example workflow:

    Suspicious IP detected
            ↓
       VirusTotal API
            ↓
    IP Reputation Result

Example result:

    Malicious: 9 | Suspicious: 0 | Harmless: 53

The VirusTotal API key is stored as an environment variable and is not hard-coded in the source code.

## Installation

Install the required Python libraries:

    python -m pip install pandas requests

## VirusTotal API Configuration

Set the VirusTotal API key as an environment variable.

### Windows PowerShell

    $env:VT_API_KEY="YOUR_API_KEY"

The application reads the key using:

    os.getenv("VT_API_KEY")

**Never upload your API key to GitHub.**

## Usage

Run the detection tool:

    python detector.py

The tool analyzes the sign-in logs, detects suspicious activity, performs VirusTotal IP reputation checks, and generates the security alert report.

The generated report is saved to:

    reports/security_alerts.csv

## Security Alerts

The tool generates alerts containing:

- Severity
- Detection
- User
- IP
- Details

Example detections:

    High    Brute Force
    High    Suspicious IP
    High    Suspicious OAuth
    Medium  MFA Failure

## Security Concepts Demonstrated

- Identity-based threat detection
- Authentication monitoring
- Brute-force detection
- Password-spraying indicators
- Suspicious IP analysis
- OAuth security monitoring
- MFA monitoring
- Risk-based authentication
- Threat intelligence enrichment
- REST API integration
- Security alert generation
- Detection engineering
- Security automation

## Limitations

- The Entra ID sign-in dataset is simulated and does not represent live tenant telemetry.
- Detection thresholds are designed for demonstration and would require tuning in a production environment.
- VirusTotal results depend on the reputation data available through the API at the time of the lookup.

## Future Enhancements

- Microsoft Graph API integration for authorized live Entra ID telemetry
- Automated alert notifications
- MITRE ATT&CK technique mapping
- Security dashboard and visualization
- Additional identity attack detections
- Automated incident response workflows

## Project Purpose

This project demonstrates practical SOC skills in identity security, security log analysis, detection engineering, threat intelligence enrichment, and security automation using Python.
