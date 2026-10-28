 # Security Log Analyzer & Threat Detection Dashboard

## About the Project

The Security Log Analyzer & Threat Detection Dashboard is a Python-based cybersecurity project that analyzes security log files and identifies suspicious login activity.

The application uses Flask to provide a web dashboard where users can upload log files and view analysis results.

## Features

* Security log file analysis
* Detection of repeated failed login attempts
* Rule-based threat alert generation
* High-severity alerts for suspicious login patterns
* Statistics for total events, failed logins, and successful logins
* Invalid log entry counting
* Web-based dashboard using Flask
* Log file upload with a 1 MB size limit

## Technologies Used

* Python
* Flask
* HTML
* CSS
* Regular Expressions
* Git and GitHub

## Detection Rule

The analyzer generates an alert when it detects at least five failed login attempts from the same IP address within a five-minute window.

This pattern may indicate a brute-force attack. Alerts require human investigation and do not independently confirm malicious activity.

## Project Structure

```text
project/
├── app.py
├── log_analyzer.py
├── test_analyzer.py
├── sample_security.log
├── README.md
└── templates/
    └── dashboard.html
```

## Installation and Usage

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the project directory

```bash
cd YOUR_REPOSITORY_NAME
```

### 3. Install dependencies

```bash
py -m pip install Flask
```

### 4. Run the application

```bash
py app.py
```

### 5. Open the dashboard

Visit:

http://127.0.0.1:5000

## Testing

The project includes simulated security log entries for testing the detection logic.

The sample data contains successful logins and repeated failed login attempts that trigger a threat alert.

## Security and Ethical Use

This project is intended for educational and defensive cybersecurity purposes.

Analyze only log files you own or are explicitly authorized to access. The sample IP addresses and log entries are simulated.

## Limitations

* Detection relies on predefined rules.
* Alerts may require additional investigation.
* The project is not a complete Security Information and Event Management (SIEM) platform.
* The current application is intended for local demonstration and requires additional security hardening before public deployment.

## Author

Cybersecurity Student
