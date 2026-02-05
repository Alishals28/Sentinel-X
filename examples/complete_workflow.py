#!/usr/bin/env python3
"""
Complete workflow demonstration of SENTINEL-X
Shows the full investigation process from log ingestion to report generation
"""

from sentinel_x.core.agent import AutonomousAgent
from sentinel_x.utils.report_generator import ReportGenerator


def demonstrate_full_workflow():
    """Demonstrate complete SENTINEL-X workflow"""
    
    print("=" * 80)
    print("SENTINEL-X: Complete Workflow Demonstration")
    print("=" * 80)
    print()
    
    # Sample cybersecurity logs representing a multi-stage attack
    attack_logs = [
        # Phase 1: Reconnaissance
        "2024-02-05 10:00:00 firewall-01 INFO: Connection from 203.0.113.45",
        "2024-02-05 10:05:00 ids-01 ALERT: Port scanning detected from 203.0.113.45",
        "2024-02-05 10:10:00 web-server-01 WARNING: Unusual traffic pattern from 203.0.113.45",
        
        # Phase 2: Initial Access - SQL Injection
        "2024-02-05 10:15:00 web-server-01 CRITICAL: SQL injection attempt: ' OR 1=1 -- from 203.0.113.45",
        "2024-02-05 10:16:00 web-server-01 ERROR: Database error - possible SQL injection",
        
        # Phase 3: Credential Access - Brute Force
        "2024-02-05 10:20:00 web-server-01 ERROR: Failed login for admin from 203.0.113.45",
        "2024-02-05 10:20:15 web-server-01 ERROR: Failed login for root from 203.0.113.45",
        "2024-02-05 10:20:30 web-server-01 ERROR: Failed login for admin from 203.0.113.45",
        "2024-02-05 10:20:45 web-server-01 ERROR: Failed login for administrator from 203.0.113.45",
        "2024-02-05 10:21:00 web-server-01 CRITICAL: Successful login for admin from 203.0.113.45",
        
        # Phase 4: Privilege Escalation
        "2024-02-05 10:25:00 web-server-01 ERROR: Privilege escalation attempt detected",
        "2024-02-05 10:26:00 web-server-01 CRITICAL: Unauthorized sudo access",
        
        # Phase 5: Lateral Movement
        "2024-02-05 10:30:00 file-server-01 WARNING: Connection from web-server-01",
        "2024-02-05 10:31:00 database-01 WARNING: Connection from web-server-01",
        "2024-02-05 10:32:00 file-server-01 CRITICAL: Unauthorized file access",
        
        # Phase 6: Data Exfiltration
        "2024-02-05 10:40:00 firewall-01 ALERT: Large data transfer to 198.51.100.99",
        "2024-02-05 10:41:00 ids-01 CRITICAL: Data exfiltration detected to 198.51.100.99",
        "2024-02-05 10:45:00 firewall-01 WARNING: Unusual outbound traffic volume",
        
        # Some normal activity mixed in
        "2024-02-05 10:50:00 web-server-01 INFO: Normal user activity from 192.168.1.50",
        "2024-02-05 11:00:00 database-01 INFO: Scheduled backup completed",
    ]
    
    print("📥 Step 1: Preparing attack scenario logs")
    print(f"   - {len(attack_logs)} log entries simulating a multi-stage attack")
    print()
    
    # Create autonomous agent with default settings
    print("🤖 Step 2: Creating autonomous agent")
    agent = AutonomousAgent(confidence_threshold=0.85)
    print("   - Confidence threshold: 85%")
    print()
    
    # Run autonomous investigation
    print("🔍 Step 3: Running autonomous investigation...")
    print()
    report = agent.investigate(log_lines=attack_logs)
    
    # Display key findings
    print()
    print("=" * 80)
    print("📊 Investigation Results")
    print("=" * 80)
    print()
    
    print(f"🆔 Incident ID: {report.incident_id}")
    print(f"⚠️  Severity: {report.severity.value.upper()}")
    print(f"📈 Confidence: {report.confidence:.1%}")
    print()
    
    print("🎯 Root Cause:")
    print(f"   {report.root_cause}")
    print()
    
    print(f"💻 Affected Assets ({len(report.affected_assets)}):")
    for asset in report.affected_assets[:5]:
        print(f"   • {asset}")
    print()
    
    print(f"🛡️  MITRE ATT&CK Techniques ({len(report.mitre_mappings)}):")
    for mapping in report.mitre_mappings[:5]:
        print(f"   • {mapping.technique_id}: {mapping.technique_name}")
        print(f"     Tactic: {mapping.tactic} | Confidence: {mapping.confidence:.0%}")
    print()
    
    print(f"⏱️  Timeline Events ({len(report.timeline)}):")
    print(f"   • First event: {report.timeline[0].timestamp if report.timeline else 'N/A'}")
    print(f"   • Last event: {report.timeline[-1].timestamp if report.timeline else 'N/A'}")
    print(f"   • Duration: {(report.timeline[-1].timestamp - report.timeline[0].timestamp) if len(report.timeline) > 1 else 'N/A'}")
    print()
    
    print(f"🔧 Mitigation Actions ({len(report.mitigation_actions)}):")
    for i, action in enumerate(report.mitigation_actions[:5], 1):
        print(f"   {i}. {action}")
    print()
    
    print(f"🧪 Hypotheses Tested ({len(report.hypotheses)}):")
    for hyp in report.hypotheses:
        status_icon = "✅" if hyp.status == "confirmed" else "🔄"
        print(f"   {status_icon} {hyp.description}")
        print(f"      Confidence: {hyp.confidence:.0%} | Status: {hyp.status}")
    print()
    
    # Generate different report formats
    print("=" * 80)
    print("📝 Generating Reports")
    print("=" * 80)
    print()
    
    # Summary report
    print("📋 Summary Report:")
    print(ReportGenerator.generate_summary(report))
    print()
    
    # Save full text report
    text_report = ReportGenerator.generate_text_report(report)
    with open('/tmp/sentinel_x_demo_report.txt', 'w') as f:
        f.write(text_report)
    print("✅ Full text report saved to: /tmp/sentinel_x_demo_report.txt")
    
    # Save JSON report
    json_report = ReportGenerator.generate_json_report(report)
    with open('/tmp/sentinel_x_demo_report.json', 'w') as f:
        f.write(json_report)
    print("✅ JSON report saved to: /tmp/sentinel_x_demo_report.json")
    
    print()
    print("=" * 80)
    print("✅ Workflow Demonstration Complete!")
    print("=" * 80)
    print()
    print("Key Takeaways:")
    print("1. SENTINEL-X autonomously analyzed 20 log entries")
    print("2. Detected multi-stage attack spanning 6 phases")
    print("3. Mapped to MITRE ATT&CK framework automatically")
    print("4. Generated comprehensive incident report")
    print("5. Provided actionable mitigation recommendations")
    print(f"6. Achieved {report.confidence:.0%} confidence in findings")
    print()


if __name__ == '__main__':
    demonstrate_full_workflow()
