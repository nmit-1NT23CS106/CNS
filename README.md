🛡️ CyberTwin — AI-Driven Digital Twin for Adaptive Cybersecurity

This project builds a behavioral anomaly detection system that learns each user's normal login patterns and dynamically adapts its security response in real time.

📌 Overview

Traditional login systems only check if you know the password. CyberTwin goes further — it learns how you normally behave (when you login, from where, on what device) and flags when something looks wrong. The ML model trained on your past logins is the "digital twin" — a virtual mirror of your behavior.

🧠 How It Works

User logs in → password verified using SHA-256 hashing
Isolation Forest ML model checks if behavior matches past patterns
Risk score computed from anomaly detection + time + location change
System responds: Allow (0–34%) → OTP (35–69%) → Block + Security Question (70%+)
Wrong password 3 times → account locked for 5 minutes

🎬 Demo Cases

alice / alice123 → Bengaluru history → ✅ Allow (patterns match)
bob / bob123 → Mumbai history → ⚠️ OTP required (location anomaly)
charlie / charlie123 → London history → 🚫 Blocked → Security question
Any user → wrong password × 3 → 🔒 Locked for 5 minutes

Security Question Answers (Demo)

alice → fluffy
bob → sharma
charlie → greenwood

⚙️ Features

Isolation Forest ML model trained on time, device, and location
0–100% risk scoring engine per session
SHA-256 password hashing
Brute force lockout after 3 failed attempts
OTP step-up authentication for medium risk
Emergency security question 2FA for high risk
Login history dashboard with risk scores

📚 CNS Concepts Covered

Authentication — SHA-256 hashed password verification
Multi-Factor Auth — OTP + security question
Intrusion Detection — Isolation Forest anomaly detection
Access Control — risk-based Allow / OTP / Block
Digital Twin — ML model mirrors user behavior
Network Security — IP tracking and geolocation

🛠️ Tech Stack

Backend — Python, Flask
Machine Learning — scikit-learn (Isolation Forest)
Database — SQLite
Security — hashlib SHA-256, Flask sessions
Frontend — HTML, CSS, JavaScript
