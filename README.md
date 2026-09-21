# Mini SOC Dashboard

A lightweight **Security Operations Center (SOC) dashboard** built with Python and Flask for monitoring, collecting, detecting, and visualizing security events from a web application.

The project demonstrates how security monitoring concepts can be combined into a small SOC-style environment, including **log collection, event detection, IP blocking, authentication monitoring, and security visualization**.

> **Educational Project:** This project is designed for cybersecurity learning, demonstrations, and university exhibitions. It should only be used in authorized environments.

---

## Features

* 🔐 **Authentication Monitoring**

  * Tracks login attempts
  * Records successful and failed authentication events
  * Helps identify suspicious login activity

* 📋 **Security Event Logging**

  * Centralized event logging
  * Stores security-related events in SQLite
  * Records timestamps, IP addresses, event types, and details

* 🚨 **Threat Detection**

  * Detects suspicious activity patterns
  * Identifies repeated failed login attempts
  * Generates security events for investigation

* 🛡️ **IP Blocking**

  * Blocks suspicious IP addresses
  * Maintains a list of blocked addresses
  * Demonstrates basic automated response

* 📊 **SOC Dashboard**

  * Displays security events
  * Shows authentication activity
  * Provides an overview of detected threats
  * Presents security information through a web interface

* 🗄️ **SQLite Database**

  * Stores users and security logs
  * Lightweight and easy to deploy
  * No external database server required

---

## Architecture

```text
                ┌─────────────────────┐
                │      Web User       │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    Flask Web App    │
                │ Login / Register    │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    Event Logger     │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │   SQLite Database   │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Detection Engine    │
                └──────────┬──────────┘
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
        ┌─────────────────┐  ┌─────────────────┐
        │ SOC Dashboard   │  │  IP Blocker     │
        └─────────────────┘  └─────────────────┘
```

---

## Project Structure

```text
Mini-SOC-Dashboard/
│
├── app.py
├── config.py
├── database.py
├── cyberlab.db
│
├── collector/
│   └── ...
│
├── detection/
│   └── ...
│
├── ip_blocker/
│   └── ...
│
├── logs/
│   └── ...
│
├── response/
│   └── ...
│
├── static/
│   └── ...
│
├── templates/
│   └── ...
│
├── demo.txt
├── login_request.txt
├── test.txt
├── pentest-demo-runbook.md
└── requirements.txt
```

---

## Technologies Used

| Technology              | Purpose                      |
| ----------------------- | ---------------------------- |
| **Python**              | Core programming language    |
| **Flask**               | Web application framework    |
| **SQLite**              | Database and event storage   |
| **HTML/CSS/JavaScript** | Dashboard interface          |
| **Linux**               | Security testing environment |
| **Burp Suite**          | Web security testing         |
| **Nmap**                | Network reconnaissance       |
| **Hydra**               | Authentication testing       |
| **SQLMap**              | SQL injection testing        |

---

## Security Monitoring Flow

The application follows a simplified SOC workflow:

```text
        Activity
           │
           ▼
     Event Generated
           │
           ▼
      Log Collection
           │
           ▼
      Event Detection
           │
           ▼
     Threat Identified
           │
           ▼
    Analyst / Response
           │
           ▼
       IP Blocking
```

This represents the basic SOC cycle:

**Collect → Detect → Analyze → Respond**

---

## Demonstration Scenarios

The project can be used to demonstrate common web-security monitoring scenarios.

### 1. Failed Login Attempts

Multiple incorrect login attempts generate authentication events.

```text
User
 │
 ├── Failed Login
 ├── Failed Login
 ├── Failed Login
 └── Failed Login
          │
          ▼
   Detection Rule
          │
          ▼
   Suspicious Activity
```

The dashboard can then display the corresponding security events.

---

### 2. Brute-Force Simulation

A controlled authentication-testing scenario can be performed against the local demonstration application.

Example:

```bash
hydra -l alex -P demo.txt <LAB-IP> -s 5000 \
http-post-form \
"/login:username=^USER^&password=^PASS^:F=Invalid username or password"
```

Only use this against systems you own or have explicit authorization to test.

---

### 3. SQL Injection Detection

The vulnerable demonstration application contains an intentionally insecure search functionality for security testing.

A controlled test can be performed using SQLMap:

```bash
sqlmap -u "http://<LAB-IP>:5000/search?q=Network" \
-p q --batch
```

The purpose is to demonstrate how suspicious application activity can be detected and logged.

---

## Demo Account

For local demonstration:

```text
Username: alex
Password: alex123
```

> Change or remove demonstration credentials before deploying the project outside a controlled lab environment.

---

## Installation

### 1. Clone the repository

```bash
git clone <YOUR-REPOSITORY-URL>
cd Mini-SOC-Dashboard
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

Activate it:

**Linux/macOS**

```bash
source venv/bin/activate
```

**Windows**

```powershell
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

```bash
python app.py
```

The application should then be available at:

```text
http://127.0.0.1:5000
```

---

## Learning Objectives

This project was created to understand how a small SOC environment can be built from the ground up.

Key concepts demonstrated:

* Security event collection
* Log management
* Authentication monitoring
* Threat detection
* Incident response
* IP-based blocking
* Web application security
* SQL injection
* Brute-force detection
* SOC dashboards
* Security automation
* Defensive security monitoring

---

## OWASP Security Concepts

The vulnerable web application is designed to provide practical demonstrations of web-security concepts associated with the **OWASP Top 10**.

The project focuses particularly on:

* Authentication-related weaknesses
* Injection vulnerabilities
* Security monitoring
* Detection and response

The vulnerabilities are intentional and exist for educational demonstration.

---

## Future Improvements

Planned improvements include:

* [ ] Real-time log streaming
* [ ] WebSocket-based dashboard updates
* [ ] Advanced detection rules
* [ ] User behavior analysis
* [ ] Automated alert generation
* [ ] Email/Telegram notifications
* [ ] GeoIP visualization
* [ ] MITRE ATT&CK mapping
* [ ] SIEM integration
* [ ] Role-based dashboard access
* [ ] Improved incident-response automation
* [ ] Docker deployment
* [ ] Elasticsearch integration

---

## Disclaimer

This project is intended **strictly for educational and authorized security testing**.

The intentionally vulnerable components should only be deployed in isolated laboratory environments.

Do not use the tools, attack techniques, or vulnerabilities demonstrated by this project against systems without explicit authorization.

---

## Author

**Sardhon Kramsa**

`Cybersecurity • Penetration Testing • Web Security`

---

## License

This project is intended for educational and research purposes.
