# CyberGuard AI Web Application 🛡️

## 🚀 Live Demo

https://cyberguardai-acn5.onrender.com


CyberGuard AI is a modern, AI-powered cybersecurity dashboard and assistant built in Python (using FastAPI) and Google Gemini (using the official `google-genai` SDK). It allows users to scan URLs for safety, analyze emails for phishing signs, generate security tips checklists, and keep track of scan records in a sleek dark mode dashboard.

## Features

- **📊 Modern Dashboard**: View aggregated metrics (Total Scans, Safe Assets, Threats, Average Risk Score) alongside dynamic chart distributions and recent logs.
- **🌐 URL Scanner Page**: Audit URLs for redirects, suspicious Top-Level Domains (TLDs), spoofing hostname characters, and malicious payload distribution.
- **📧 Phishing Detector Page**: Analyze email bodies and subject lines for social engineering cues, harvesting attempts, and spoofing headers. Includes an indicator checklist.
- **💡 Security Tips Page**: Get custom checklists and safety guidelines on passwords, MFA, Wi-Fi safety, and other user-typed topics.
- **📋 Scan History Ledger Table**: Browse all past activities in a paginated tabular ledger. Filter entries by text and export logs as CSV files.
- **🎨 Glassmorphism Dark Mode UI**: Vibrant layout featuring neon color highlights (Cyan, Green, Warning Gold, Hazard Red, Phishing Purple), glowing gauges, circular risk indicators, and hover transitions.
- **🔌 Zero-Configuration Fallback**: The app loads immediately even without an API key configured. You can populate it inside `.env` or input it dynamically from the status pane while the server runs.


## 📸 Screenshots

### Homepage

![Homepage](screenshots/HOMEPAGE)

### Dashboard

![Dashboard](screenshots/DASHBOARD)

### Phishing Detection

![Phishing Detection](screenshots/PHISHING)

### URL Scanner

![URL Scanner](screenshots/URL)



## Project Structure

```
├── CyberGuardAI.py        # FastAPI server (API endpoints, CSV logging, static routing)
├── requirements.txt       # Dependencies (fastapi, uvicorn, google-genai, etc.)
├── .env.example           # Template for configuration
├── .env                   # Environment variable file for active API Key
├── static/
│   ├── index.html         # Dashboard HTML structure
│   ├── style.css          # Dark Mode styles, layouts, animations, and typography
│   └── app.js             # Single-page navigation, API fetch triggers, SVG charts
└── scan_history.csv       # Append-only database for scan logs (auto-generated)
```

## Installation

1. Install Python 3.8+ on your system.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Create a `.env` file in the root folder:
   ```env
   GEMINI_API_KEY=your_actual_gemini_api_key
   ```
2. You can get an API key for free from [Google AI Studio](https://aistudio.google.com/).
3. *Note*: If no key is set in `.env`, the system status in the sidebar will indicate "API Key Required" and will prompt you to enter it dynamically on the UI without restarting.

## Usage

Run the FastAPI web server:
```bash
python CyberGuardAI.py
```

Open your browser and navigate to:
```
http://127.0.0.1:8000
```
Use the sidebar navigation to switch between the Dashboard, URL Scanner, Phishing Detector, Security Tips, and History Logs.



## Tech Stack

- Python
- FastAPI
- Google Gemini AI
- HTML
- CSS
- JavaScript

## Author

Dhruv Ahire

B.Tech AI/ML Student
Chhatrapati Shivaji Maharaj University

GitHub:
https://github.com/dhruvahire24
