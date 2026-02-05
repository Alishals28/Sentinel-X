#!/usr/bin/env python3
"""
Validation tests for SENTINEL-X
"""

import sys
from datetime import datetime
from sentinel_x.core.agent import AutonomousAgent
from sentinel_x.core.ingestion import LogIngestionEngine
from sentinel_x.tools.anomaly_detection import AnomalyDetector
from sentinel_x.tools.correlation import EventCorrelator
from sentinel_x.tools.mitre_mapping import MitreMapper
from sentinel_x.utils.report_generator import ReportGenerator


def test_log_ingestion():
    """Test log ingestion functionality"""
    print("Testing log ingestion...")
    
    engine = LogIngestionEngine()
    
    # Test with various log formats
    log_lines = [
        "2024-02-05 10:00:00 server-01 INFO: Normal activity",
        "2024-02-05 10:01:00 server-01 ERROR: Failed login",
        "2024-02-05 10:02:00 server-01 CRITICAL: SQL injection detected",
    ]
    
    count = engine.ingest_logs(log_lines)
    assert count == 3, f"Expected 3 logs, got {count}"
    assert len(engine.get_alerts()) > 0, "Expected alerts to be generated"
    
    print("  ✓ Log ingestion working")


def test_anomaly_detection():
    """Test anomaly detection"""
    print("Testing anomaly detection...")
    
    engine = LogIngestionEngine()
    detector = AnomalyDetector()
    
    # Create logs with anomalies
    log_lines = [
        "2024-02-05 10:00:00 server-01 ERROR: Failed login for admin",
        "2024-02-05 10:00:15 server-01 ERROR: Failed login for root",
        "2024-02-05 10:00:30 server-01 ERROR: Failed login for admin",
        "2024-02-05 10:01:00 server-01 CRITICAL: Port scan detected",
        "2024-02-05 10:02:00 server-01 ALERT: SQL injection: ' OR 1=1",
    ]
    
    engine.ingest_logs(log_lines)
    anomalies = detector.detect_anomalies(engine.get_logs())
    
    assert len(anomalies) > 0, "Expected anomalies to be detected"
    print(f"  ✓ Detected {len(anomalies)} anomalies")


def test_event_correlation():
    """Test event correlation"""
    print("Testing event correlation...")
    
    engine = LogIngestionEngine()
    detector = AnomalyDetector()
    correlator = EventCorrelator()
    
    log_lines = [
        "2024-02-05 10:00:00 192.168.1.100 ERROR: Failed login",
        "2024-02-05 10:00:30 192.168.1.100 ERROR: Failed login",
        "2024-02-05 10:01:00 192.168.1.100 CRITICAL: Successful login",
        "2024-02-05 10:02:00 192.168.1.100 ALERT: Port scan",
    ]
    
    engine.ingest_logs(log_lines)
    anomalies = detector.detect_anomalies(engine.get_logs())
    correlations = correlator.correlate_events(
        engine.get_logs(),
        engine.get_alerts(),
        anomalies
    )
    
    assert len(correlations) > 0, "Expected correlations to be found"
    print(f"  ✓ Found {len(correlations)} correlations")


def test_mitre_mapping():
    """Test MITRE ATT&CK mapping"""
    print("Testing MITRE ATT&CK mapping...")
    
    engine = LogIngestionEngine()
    detector = AnomalyDetector()
    mapper = MitreMapper()
    
    log_lines = [
        "2024-02-05 10:00:00 server ALERT: Port scan detected",
        "2024-02-05 10:01:00 server CRITICAL: SQL injection attempt",
        "2024-02-05 10:02:00 server ERROR: Brute force attack",
    ]
    
    engine.ingest_logs(log_lines)
    anomalies = detector.detect_anomalies(engine.get_logs())
    mappings = mapper.map_to_mitre(engine.get_alerts(), anomalies)
    
    assert len(mappings) > 0, "Expected MITRE mappings"
    print(f"  ✓ Mapped {len(mappings)} MITRE techniques")


def test_timeline_building():
    """Test timeline construction"""
    print("Testing timeline building...")
    
    engine = LogIngestionEngine()
    detector = AnomalyDetector()
    correlator = EventCorrelator()
    
    log_lines = [
        "2024-02-05 10:00:00 server ALERT: Attack started",
        "2024-02-05 10:01:00 server CRITICAL: Attack continuing",
        "2024-02-05 10:02:00 server ERROR: Attack detected",
    ]
    
    engine.ingest_logs(log_lines)
    anomalies = detector.detect_anomalies(engine.get_logs())
    correlations = correlator.correlate_events(
        engine.get_logs(),
        engine.get_alerts(),
        anomalies
    )
    timeline = correlator.build_attack_timeline(correlations)
    
    assert len(timeline) > 0, "Expected timeline events"
    print(f"  ✓ Built timeline with {len(timeline)} events")


def test_autonomous_agent():
    """Test the full autonomous agent"""
    print("Testing autonomous agent...")
    
    log_lines = [
        "2024-02-05 14:00:00 server-01 INFO: Normal activity",
        "2024-02-05 14:01:00 server-01 ERROR: Failed login for admin",
        "2024-02-05 14:01:30 server-01 ERROR: Failed login for root",
        "2024-02-05 14:02:00 server-01 CRITICAL: SQL injection detected",
        "2024-02-05 14:03:00 server-01 ALERT: Port scanning from 192.168.1.100",
        "2024-02-05 14:04:00 server-02 WARNING: Lateral movement detected",
        "2024-02-05 14:05:00 server-02 CRITICAL: Data exfiltration attempt",
    ]
    
    agent = AutonomousAgent(confidence_threshold=0.70)
    report = agent.investigate(log_lines=log_lines)
    
    # Validate report structure
    assert report.incident_id is not None, "Expected incident ID"
    assert report.severity is not None, "Expected severity"
    assert report.root_cause is not None, "Expected root cause"
    assert len(report.mitigation_actions) > 0, "Expected mitigation actions"
    assert report.confidence > 0, "Expected confidence > 0"
    
    print(f"  ✓ Agent investigation complete (confidence: {report.confidence:.1%})")


def test_report_generation():
    """Test report generation"""
    print("Testing report generation...")
    
    agent = AutonomousAgent(confidence_threshold=0.70)
    log_lines = [
        "2024-02-05 10:00:00 server CRITICAL: Attack detected",
        "2024-02-05 10:01:00 server ERROR: Failed login",
    ]
    
    report = agent.investigate(log_lines=log_lines)
    
    # Test text report
    text_report = ReportGenerator.generate_text_report(report)
    assert "SENTINEL-X INCIDENT REPORT" in text_report, "Expected report header"
    assert "MITRE ATT&CK" in text_report, "Expected MITRE section"
    
    # Test JSON report
    json_report = ReportGenerator.generate_json_report(report)
    assert "incident_id" in json_report, "Expected JSON to contain incident_id"
    
    # Test summary
    summary = ReportGenerator.generate_summary(report)
    assert "Incident" in summary, "Expected summary to contain Incident"
    
    print("  ✓ Report generation working")


def test_file_based_investigation():
    """Test investigating from file"""
    print("Testing file-based investigation...")
    
    agent = AutonomousAgent(confidence_threshold=0.85)
    
    try:
        report = agent.investigate(log_file_path='examples/sample_attack.log')
        
        assert report is not None, "Expected report"
        assert len(report.timeline) > 0, "Expected timeline events"
        assert len(report.mitre_mappings) > 0, "Expected MITRE mappings"
        
        print(f"  ✓ File investigation complete")
        print(f"    - {len(report.timeline)} timeline events")
        print(f"    - {len(report.mitre_mappings)} MITRE techniques")
        print(f"    - {len(report.affected_assets)} affected assets")
        
    except FileNotFoundError:
        print("  ⚠ Skipping file test (sample file not found)")


def run_all_tests():
    """Run all validation tests"""
    print("=" * 80)
    print("SENTINEL-X Validation Tests")
    print("=" * 80)
    print()
    
    tests = [
        test_log_ingestion,
        test_anomaly_detection,
        test_event_correlation,
        test_mitre_mapping,
        test_timeline_building,
        test_autonomous_agent,
        test_report_generation,
        test_file_based_investigation,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
        print()
    
    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
