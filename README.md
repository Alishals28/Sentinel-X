# SENTINEL-X 🛡️

An autonomous AI incident commander that ingests large cybersecurity logs and alerts, analyzes the full context, plans its own investigation, and generates comprehensive incident reports.

## 🎯 Overview

SENTINEL-X is an intelligent cybersecurity investigation agent that:

- 📥 **Ingests** large volumes of security logs and alerts
- 🔍 **Analyzes** the full context autonomously
- 🎯 **Plans** its own investigation strategy
- 🛠️ **Calls tools** to detect anomalies, correlate events, and map attacks
- 🗺️ **Maps** activities to MITRE ATT&CK framework
- ⏱️ **Builds** detailed incident timelines
- 🧠 **Refines** hypotheses autonomously
- ✅ **Terminates** when confidence threshold is reached
- 📊 **Outputs** structured incident reports with root cause, affected assets, and mitigation actions

## 🚀 Features

### Autonomous Investigation
- Self-directed investigation planning
- Hypothesis formation and refinement
- Confidence-based termination

### Advanced Analysis
- Multi-method anomaly detection (frequency, pattern, temporal, volume)
- Event correlation across time and entities
- Attack chain detection
- MITRE ATT&CK technique mapping

### Comprehensive Reporting
- Structured incident reports
- Timeline reconstruction
- Root cause analysis
- Affected asset identification
- Mitigation recommendations

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Alishals28/Sentinel-X.git
cd Sentinel-X

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## 🔧 Usage

### Command Line Interface

```bash
# Analyze a log file
sentinel-x --log-file /path/to/logs.txt --output report.txt

# Generate JSON report
sentinel-x -f logs.txt --format json -o report.json

# Use custom confidence threshold
sentinel-x -f logs.txt --confidence 0.90

# Get summary only
sentinel-x -f logs.txt --format summary
```

### Python API

```python
from sentinel_x.core.agent import AutonomousAgent
from sentinel_x.utils.report_generator import ReportGenerator

# Create autonomous agent
agent = AutonomousAgent(confidence_threshold=0.85)

# Investigate from file
report = agent.investigate(log_file_path='logs.txt')

# Or investigate from log lines
log_lines = [
    "2024-02-05 10:15:30 server CRITICAL: SQL injection detected",
    "2024-02-05 10:16:00 server ERROR: Failed login attempt",
    # ... more logs
]
report = agent.investigate(log_lines=log_lines)

# Generate reports
text_report = ReportGenerator.generate_text_report(report)
json_report = ReportGenerator.generate_json_report(report)
summary = ReportGenerator.generate_summary(report)

print(text_report)
```

## 📊 Example Output

```
================================================================================
SENTINEL-X INCIDENT REPORT
================================================================================

Incident ID:  INC-20240205-140532
Timestamp:    2024-02-05 14:05:32
Severity:     CRITICAL
Confidence:   88.5%

Title: Cybersecurity Incident: Multi-stage attack: Reco

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Investigation completed with 12 alerts and 8 anomalies detected. Attack spans 
4 MITRE ATT&CK tactics: Reconnaissance, Initial Access, Credential Access, 
Exfiltration. Primary hypothesis: Multi-stage attack leading to data 
exfiltration (confidence: 89%).

ROOT CAUSE
--------------------------------------------------------------------------------
Attack follows pattern: Multi-stage attack: Reconnaissance → Initial Access → 
Credential Access → Exfiltration

AFFECTED ASSETS
--------------------------------------------------------------------------------
  • 203.0.113.45
  • web-server-01
  • file-server-01
  • database-01
  • 198.51.100.99

MITRE ATT&CK TECHNIQUES
--------------------------------------------------------------------------------
  • T1595: Active Scanning
    Tactic: Reconnaissance
    Confidence: 92.0%
    Evidence: Alert: Port scanning activity detected from 203.0.113.45...

  • T1110: Brute Force
    Tactic: Credential Access
    Confidence: 88.0%
    Evidence: Anomaly: Multiple failed authentication attempts...

RECOMMENDED MITIGATION ACTIONS
--------------------------------------------------------------------------------
1. Implement account lockout policy after failed login attempts
2. Enable multi-factor authentication
3. Apply security patches and updates
4. Review and rotate compromised credentials
5. Implement network segmentation
6. Monitor for indicators of compromise
```

## 🏗️ Architecture

```
sentinel_x/
├── core/
│   ├── models.py          # Data models (LogEntry, Alert, Anomaly, etc.)
│   ├── ingestion.py       # Log ingestion and parsing
│   └── agent.py           # Autonomous investigation agent
├── tools/
│   ├── anomaly_detection.py  # Anomaly detection algorithms
│   ├── correlation.py        # Event correlation engine
│   └── mitre_mapping.py      # MITRE ATT&CK mapper
├── utils/
│   └── report_generator.py   # Report generation utilities
└── main.py                    # CLI entry point
```

## 🔍 Investigation Process

1. **Data Ingestion**: Parses logs in multiple formats (JSON, syslog, CSV, generic)
2. **Anomaly Detection**: 
   - Frequency-based anomalies
   - Pattern matching (SQL injection, XSS, command injection, etc.)
   - Temporal anomalies (off-hours activity)
   - Volume spikes
   - Failed authentication patterns
   - Network anomalies (port scanning, lateral movement)

3. **Event Correlation**:
   - Temporal correlation (events in same time window)
   - Entity correlation (events affecting same assets)
   - Attack pattern correlation (multi-stage attacks)

4. **MITRE Mapping**: Maps detected activities to 18+ MITRE ATT&CK techniques

5. **Timeline Building**: Constructs chronological attack timeline

6. **Hypothesis Formation**: Generates investigation hypotheses

7. **Hypothesis Refinement**: Strengthens/weakens based on evidence

8. **Root Cause Determination**: Identifies primary attack vector

9. **Asset Identification**: Lists all affected systems

10. **Mitigation Recommendations**: Provides actionable remediation steps

## 🧪 Examples

See the `examples/` directory for:
- `sample_attack.log`: Example log file with simulated attack
- `example_usage.py`: Python API usage examples

Run the example:
```bash
python examples/example_usage.py
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔒 Security

SENTINEL-X is designed for analyzing security logs and should be used in accordance with your organization's security policies. Always ensure proper authorization before analyzing production logs.

## 📧 Contact

For questions or support, please open an issue on GitHub.
