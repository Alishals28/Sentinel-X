#!/usr/bin/env python3
"""
Example usage of SENTINEL-X API
"""

from sentinel_x.core.agent import AutonomousAgent
from sentinel_x.utils.report_generator import ReportGenerator


def example_file_investigation():
    """Example: Investigate a log file"""
    print("=" * 80)
    print("Example 1: Investigating a log file")
    print("=" * 80)
    
    # Create autonomous agent
    agent = AutonomousAgent(confidence_threshold=0.85)
    
    # Run investigation
    report = agent.investigate(log_file_path='examples/sample_attack.log')
    
    # Generate and print text report
    text_report = ReportGenerator.generate_text_report(report)
    print(text_report)
    
    # Save JSON report
    json_report = ReportGenerator.generate_json_report(report)
    with open('examples/sample_report.json', 'w', encoding='utf-8') as f:
        f.write(json_report)
    print("\nJSON report saved to: examples/sample_report.json")


def example_log_lines_investigation():
    """Example: Investigate log lines directly"""
    print("\n" + "=" * 80)
    print("Example 2: Investigating log lines directly")
    print("=" * 80)
    
    # Sample log lines
    log_lines = [
        "2024-02-05 10:15:30 server-01 CRITICAL: SQL injection detected from 192.168.1.100",
        "2024-02-05 10:16:00 server-01 ERROR: Failed login attempt for user admin",
        "2024-02-05 10:16:15 server-01 ERROR: Failed login attempt for user root",
        "2024-02-05 10:16:30 server-01 ERROR: Failed login attempt for user admin",
        "2024-02-05 10:17:00 server-01 CRITICAL: Successful login for admin after brute force",
        "2024-02-05 10:18:00 firewall-01 ALERT: Port scanning from 192.168.1.100",
        "2024-02-05 10:20:00 server-02 WARNING: Lateral movement detected",
        "2024-02-05 10:25:00 server-02 CRITICAL: Data exfiltration attempt",
    ]
    
    # Create agent and investigate
    agent = AutonomousAgent(confidence_threshold=0.80)
    report = agent.investigate(log_lines=log_lines)
    
    # Print summary
    summary = ReportGenerator.generate_summary(report)
    print(summary)
    
    print("\nInvestigation Details:")
    print(f"  - Alerts generated: {len(report.timeline)}")
    print(f"  - MITRE techniques: {len(report.mitre_mappings)}")
    print(f"  - Affected assets: {len(report.affected_assets)}")
    print(f"  - Hypotheses tested: {len(report.hypotheses)}")
    print(f"  - Final confidence: {report.confidence:.1%}")


def example_custom_confidence():
    """Example: Custom confidence threshold"""
    print("\n" + "=" * 80)
    print("Example 3: Using custom confidence threshold")
    print("=" * 80)
    
    # High confidence threshold - more thorough investigation
    agent = AutonomousAgent(confidence_threshold=0.95)
    
    log_lines = [
        "2024-02-05 12:00:00 web-01 CRITICAL: XSS attack detected",
        "2024-02-05 12:01:00 web-01 ERROR: Multiple failed authentications",
        "2024-02-05 12:05:00 web-01 ALERT: Suspicious file upload",
    ]
    
    report = agent.investigate(log_lines=log_lines)
    
    print(f"Investigation completed with {report.confidence:.1%} confidence")
    print(f"Root cause: {report.root_cause}")
    print(f"Mitigation actions: {len(report.mitigation_actions)}")


if __name__ == '__main__':
    # Run examples
    example_file_investigation()
    example_log_lines_investigation()
    example_custom_confidence()
    
    print("\n" + "=" * 80)
    print("All examples completed!")
    print("=" * 80)
