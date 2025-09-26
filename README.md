# Log-Analyzer-for-Suspicious-Activity
Log Analyzer for Suspicious Activity, detects brute-force login attempts by analyzing /var/log/auth.log. It uses regex to extract failed logins, counts attempts per IP, and flags suspicious ones crossing a threshold. Results can be exported for reporting, making it a beginner-friendly mini SIEM tool for cybersecurity practice.

# Objectives
- Parse `/var/log/auth.log` for failed login attempts.
- Detect repeated failures from the same IP.
- Flag IPs crossing a configurable threshold.
- Export suspicious IPs to **TXT** and **CSV**.
- Visualize attempts using Pandas/Matplotlib.
