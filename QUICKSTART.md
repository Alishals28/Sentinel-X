# Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/Alishals28/Sentinel-X.git
cd Sentinel-X

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## 5-Minute Quick Start

### 1. Run with Sample Data

```bash
# Analyze the provided sample attack logs
python -m sentinel_x.main -f examples/sample_attack.log --format summary
```

Expected output:
```
Incident INC-20240205-XXXXXX (CRITICAL)
Cybersecurity Incident: Multi-stage attack detected
Root cause identified with 85% confidence
3 affected assets
8 MITRE techniques identified
Confidence: 85.0%
```

### 2. Try the Python API

```bash
python examples/example_usage.py
```

This will:
- Analyze the sample attack logs
- Generate a detailed text report
- Save a JSON report
- Display investigation findings

### 3. Run the Complete Workflow Demo

```bash
python examples/complete_workflow.py
```

This demonstrates:
- Full autonomous investigation process
- Multi-stage attack detection
- MITRE ATT&CK mapping
- Timeline reconstruction
- Report generation

### 4. Run Your Own Analysis

Create a Python script:

```python
from sentinel_x.core.agent import AutonomousAgent

# Your log lines
logs = [
    "2024-02-05 10:00:00 server CRITICAL: SQL injection detected",
    "2024-02-05 10:01:00 server ERROR: Failed login attempt",
    # ... more logs
]

# Create agent and investigate
agent = AutonomousAgent(confidence_threshold=0.85)
report = agent.investigate(log_lines=logs)

# Display results
print(f"Incident: {report.incident_id}")
print(f"Severity: {report.severity}")
print(f"Root Cause: {report.root_cause}")
print(f"Confidence: {report.confidence:.0%}")
```

## Testing

```bash
# Run all validation tests
python tests/test_validation.py
```

Expected: `Results: 8 passed, 0 failed`

## What's Next?

1. **Read the full documentation**: See [README.md](README.md)
2. **Explore advanced features**: See [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md)
3. **Customize for your needs**: Adjust confidence thresholds, add custom patterns
4. **Integrate with your SIEM**: Use the Python API to connect with your security tools

## Common Use Cases

### Analyze Daily Security Logs

```bash
sentinel-x -f /var/log/security.log -o daily_report.txt
```

### Generate JSON for SIEM Integration

```bash
sentinel-x -f logs.txt --format json -o incident.json
```

### Quick Triage with Summary

```bash
sentinel-x -f suspicious_activity.log --format summary
```

### High-Confidence Investigation

```bash
sentinel-x -f critical_alerts.log --confidence 0.95
```

## Troubleshooting

**Issue**: "Module not found"
- **Solution**: Run `pip install -e .` from the project root

**Issue**: "File not found"
- **Solution**: Use absolute paths or run from project root

**Issue**: Low confidence in results
- **Solution**: Provide more log entries (100+ recommended) or lower threshold

## Support

- **Documentation**: See README.md and ADVANCED_FEATURES.md
- **Examples**: Check the `examples/` directory
- **Tests**: Review `tests/test_validation.py` for usage patterns
- **Issues**: Open an issue on GitHub

---

**Ready to analyze your security logs? Start with the sample data above!** 🚀
