# Security Log Analyzer

A Python-based cybersecurity project that analyzes authentication logs and detects suspicious login activity.

## Project Overview

The Security Log Analyzer reads authentication logs and identifies patterns that may indicate brute-force or password-guessing attacks.

The project was built as a practical application of cybersecurity concepts including:

- Log analysis
- Authentication monitoring
- Threat detection
- Python automation
- Incident reporting
- Basic security alerting

## Detection Rules

The analyzer uses the following rules:

1. Count successful and failed login attempts.
2. Track failed login attempts by IP address.
3. Track failed login attempts by username.
4. Correlate IP addresses with targeted usernames.
5. Flag an IP/username combination after 3 or more failed attempts.
6. Classify activity occurring within 30 seconds as a Rapid Login Attack.
7. Assign HIGH severity to rapid attacks.

The 30-second threshold is a project-defined detection rule used for demonstration purposes.

## Sample Findings

The sample authentication log produced the following results:

- Successful logins: 5
- Failed logins: 11
- `192.168.1.50` → 4 failed attempts against `admin`
- `203.0.113.45` → 5 failed attempts against `admin`
- `10.0.0.25` → 2 failed attempts against `guest`

Two IP addresses were classified as Rapid Login Attacks with HIGH severity.

## Technologies Used

- Python 3
- Linux / WSL
- Python `pathlib`
- Python `datetime`
- File handling
- Dictionaries
- Tuples
- String parsing

## Project Structure

```text
security-log-analyzer/
├── logs/
│   └── auth.log
├── reports/
│   └── security_report.txt
├── screenshots/
└── src/
    └── log_analyzer.py
