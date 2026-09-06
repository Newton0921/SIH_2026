# ThreatLens

**AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform**  
*Hackathon Problem Statement ID: 26106*

---

## 📌 Project Overview
ThreatLens is a comprehensive, multi-stage pipeline designed for automated email threat analysis and digital forensics. It ingests `.eml` files, processes them through a layered defense system, and produces an actionable intelligence report. The platform aims to bridge the gap between raw email data and actionable threat intelligence without overstating capabilities.

## 🏗️ Architecture & Pipeline
The analysis is composed of a rigorous 8-stage pipeline:

### 1. Robust EML Parsing (`modules/parser.py`)
- Full RFC 5322 compliance. Extracts headers, bodies, attachments, and traces the complete `Received` chain.
- Decodes base64/quoted-printable payloads safely without execution.

### 2. Dual-Layer Content Classification (`modules/content_classifier.py`)
- **ML Layer**: A TF-IDF + Logistic Regression model trained on 13K+ actual phishing emails (Nazario dataset augmented with Enron text), outputting a binary (clean/phishing) probability.
- **Heuristic Layer**: A rule-based sub-classifier targeting specific fraudulent techniques (BEC/fraud, brand impersonation, credential harvesting, extortion).

### 3. Header Forensics (`modules/header_forensics.py`)
- **Primary Auth Path**: Parses the existing `Authentication-Results` header stamped by receiving mail servers (M365/Google).
- **DNS Fallback Path**: In the absence of an auth header, queries public DNS (`checkdmarc`) to check SPF and DMARC policies. *(Note: DKIM cannot be verified without a public key selector; it safely returns "unknown").*
- **Anomaly Detection**: Flags mismatching `Reply-To`, mismatched `Return-Path`, and synthetic/spoofed `Message-ID` domains.

### 4. Origin Intelligence (`modules/origin_intel.py`)
- Executes concurrently using `ThreadPoolExecutor`.
- **Reputation**: Checks extracted IPs/URLs against Feodo (Botnet C2), URLhaus (Malware), TOR Bulk Exit Nodes, VirusTotal, and AbuseIPDB.
- **Geolocation**: Maps the earliest external IP in the `Received` chain using the offline `GeoLite2-City.mmdb` database.
- **Domain Intel**: Performs WHOIS lookups for domain age (flagging newly registered domains) and rapidfuzz string matching to detect homograph attacks against trusted brands.

### 5. Correlation & Attribution (`modules/correlation.py`)
- **Graph Clustering**: Uses `NetworkX` to link emails via shared IP addresses, sender domains, and attachment hashes.
- **Soft Links**: Uses TF-IDF cosine similarity (>0.85) to cluster campaigns even when infrastructure rotates.
- **Attribution Logic**: Generates probabilistic threat actor profiles (e.g., `likely-anonymized-infrastructure`, `likely-spoofed-domain`) without fabricating fictional identities.

### 6. Risk Scoring (`modules/risk_scoring.py`)
- 9-component weighted formula aggregating signals from all previous stages into a 0-100 risk score.
- Categorizes emails into: **Deliver** (<40), **Manual Review** (40-69), or **Quarantine** (70+).
- Weights are adjustable via `config.py` for rapid tuning.

### 7. Web Interface & Reporting (`app.py`, `templates/`)
- A premium, dark-themed Flask dashboard built with Bootstrap 5 and Glassmorphism design principles.
- Features `Leaflet.js` for geolocation mapping and `Chart.js` for risk score gauges.
- Provides sortable, filterable DataTables for case management and a forensic PDF exporter (`xhtml2pdf`).

### 8. Privacy & Compliance (`modules/compliance.py`)
- **Masked View**: Automatically redacts Personally Identifiable Information (PII) from reports (retaining only domain names) before external sharing.
- **Audit Log**: An append-only SQLite table recording all actions (views, exports, purges) for chain-of-custody requirements.
- **Data Retention**: A callable purge function to securely NULL email bodies older than a configurable number of days (default: 90) while preserving the analytical record.

---

## ⚠️ Capabilities & Limitations

Threat intelligence systems must be honest about their boundaries to remain trustworthy. ThreatLens operates strictly within the following constraints:

### Attribution is Probabilistic, Never Certain
**This platform does not identify named threat actors (e.g., "APT29" or "Lazarus").**  
No open-source, free-tier system can responsibly claim exact actor attribution from email metadata alone. 
Instead, ThreatLens provides **confidence-based investigative assessments** to assist analysts. It categorizes threats based on observable infrastructure and behavioral tactics:
- `likely-anonymized-infrastructure` (Uses TOR, Cloud Hosting, Proxy setups).
- `likely-spoofed-domain` (Fails SPF/DMARC, mismatched Return-Path).
- `likely-botnet-c2` (Originates from IPs found on Feodo tracker).

### ML vs. Heuristics
The core ML classifier strictly performs binary categorization based on text semantics and structural flags. It relies on the heuristic layer to provide the "why" (e.g., BEC vs Credential Harvesting). The ML model is highly accurate on its training distribution but may falter on highly novel, zero-day phishing lures lacking common semantic tells. 

### DKIM in DNS Fallback Mode
If an `Authentication-Results` header is absent, ThreatLens falls back to DNS lookups via `checkdmarc`. While SPF and DMARC policies can be queried globally by domain, **DKIM signatures cannot be verified without the exact selector used to sign the email.** Therefore, DKIM will always accurately and safely report as `unknown` in fallback mode, rather than guessing or fabricating a result.

### Geolocation Relies on the `Received` Chain
Geolocation tracing is only as good as the email's headers. 
- Synthetic `.eml` files (often created by security tools for testing) lacking a valid `Received` chain will bypass geolocation tracking entirely.
- The system gracefully handles these scenarios, explicitly noting the absence of routing data rather than crashing or plotting coordinates at 0,0.

---

## 🚀 Setup & Execution

### Requirements
- Python 3.10+
- `GeoLite2-City.mmdb` placed in the `data/` directory.

### Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
2. **Train the ML Model**
   ```bash
   python train_classifier.py
   ```
3. **Run the Dashboard**
   ```bash
   python app.py
   ```
4. Access the platform at `http://localhost:5000`

### Running Unit Tests
ThreatLens includes a rigorous suite of unit and end-to-end tests:
```bash
python -m pytest tests/ -s --no-header -v
```
