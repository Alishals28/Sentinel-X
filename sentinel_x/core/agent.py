"""
Autonomous investigation agent for SENTINEL-X
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
from ..core.models import (
    LogEntry, Alert, Anomaly, Hypothesis, 
    IncidentReport, TimelineEvent, Severity
)
from ..core.ingestion import LogIngestionEngine
from ..tools.anomaly_detection import AnomalyDetector
from ..tools.correlation import EventCorrelator
from ..tools.mitre_mapping import MitreMapper


class InvestigationPlan:
    """Represents an investigation plan"""
    
    def __init__(self):
        self.steps = []
        self.completed_steps = []
        self.current_step = None
    
    def add_step(self, step: str):
        """Add a step to the plan"""
        self.steps.append(step)
    
    def complete_step(self, step: str, findings: str):
        """Mark a step as completed"""
        self.completed_steps.append({
            'step': step,
            'findings': findings,
            'timestamp': datetime.now()
        })
    
    def get_next_step(self) -> Optional[str]:
        """Get the next investigation step"""
        completed_step_names = {s['step'] for s in self.completed_steps}
        for step in self.steps:
            if step not in completed_step_names:
                return step
        return None


class AutonomousAgent:
    """Autonomous AI agent for cybersecurity incident investigation"""
    
    def __init__(self, confidence_threshold: float = 0.85):
        self.confidence_threshold = confidence_threshold
        self.ingestion_engine = LogIngestionEngine()
        self.anomaly_detector = AnomalyDetector()
        self.correlator = EventCorrelator()
        self.mitre_mapper = MitreMapper()
        
        self.investigation_plan = InvestigationPlan()
        self.hypotheses: List[Hypothesis] = []
        self.findings: List[str] = []
        self.current_confidence = 0.0
    
    def investigate(self, log_file_path: Optional[str] = None, 
                   log_lines: Optional[List[str]] = None) -> IncidentReport:
        """
        Main investigation method - autonomously investigates the incident
        
        Args:
            log_file_path: Path to log file to analyze
            log_lines: List of log lines to analyze
            
        Returns:
            Structured incident report
        """
        print("🔍 SENTINEL-X: Starting autonomous investigation...")
        
        # Phase 1: Data Ingestion
        print("\n📥 Phase 1: Ingesting logs and alerts...")
        if log_file_path:
            log_count = self.ingestion_engine.ingest_file(log_file_path)
        elif log_lines:
            log_count = self.ingestion_engine.ingest_logs(log_lines)
        else:
            raise ValueError("Must provide either log_file_path or log_lines")
        
        print(f"   ✓ Ingested {log_count} log entries")
        print(f"   ✓ Generated {len(self.ingestion_engine.alerts)} initial alerts")
        
        # Phase 2: Create Investigation Plan
        print("\n🎯 Phase 2: Planning investigation...")
        self._create_investigation_plan()
        print(f"   ✓ Created plan with {len(self.investigation_plan.steps)} steps")
        
        # Phase 3: Execute Investigation Plan
        print("\n🔬 Phase 3: Executing investigation plan...")
        self._execute_investigation_plan()
        
        # Phase 4: Generate Report
        print("\n📊 Phase 4: Generating incident report...")
        report = self._generate_report()
        
        print(f"\n✅ Investigation complete! Final confidence: {report.confidence:.2%}")
        
        return report
    
    def _create_investigation_plan(self):
        """Create an autonomous investigation plan based on initial data"""
        self.investigation_plan = InvestigationPlan()
        
        # Standard investigation steps
        self.investigation_plan.add_step("detect_anomalies")
        self.investigation_plan.add_step("correlate_events")
        self.investigation_plan.add_step("map_mitre_techniques")
        self.investigation_plan.add_step("build_timeline")
        self.investigation_plan.add_step("form_hypotheses")
        self.investigation_plan.add_step("refine_hypotheses")
        self.investigation_plan.add_step("determine_root_cause")
        self.investigation_plan.add_step("identify_affected_assets")
        self.investigation_plan.add_step("recommend_mitigations")
    
    def _execute_investigation_plan(self):
        """Execute the investigation plan step by step"""
        while True:
            next_step = self.investigation_plan.get_next_step()
            if not next_step:
                break
            
            print(f"   → Executing: {next_step}")
            
            if next_step == "detect_anomalies":
                findings = self._detect_anomalies()
            elif next_step == "correlate_events":
                findings = self._correlate_events()
            elif next_step == "map_mitre_techniques":
                findings = self._map_mitre_techniques()
            elif next_step == "build_timeline":
                findings = self._build_timeline()
            elif next_step == "form_hypotheses":
                findings = self._form_hypotheses()
            elif next_step == "refine_hypotheses":
                findings = self._refine_hypotheses()
            elif next_step == "determine_root_cause":
                findings = self._determine_root_cause()
            elif next_step == "identify_affected_assets":
                findings = self._identify_affected_assets()
            elif next_step == "recommend_mitigations":
                findings = self._recommend_mitigations()
            else:
                findings = "Step not implemented"
            
            self.investigation_plan.complete_step(next_step, findings)
            print(f"     ✓ {findings}")
            
            # Check if we should terminate early
            if self.current_confidence >= self.confidence_threshold:
                print(f"\n   ⚡ High confidence reached ({self.current_confidence:.2%}), terminating investigation")
                break
    
    def _detect_anomalies(self) -> str:
        """Detect anomalies in the logs"""
        logs = self.ingestion_engine.get_logs()
        anomalies = self.anomaly_detector.detect_anomalies(logs)
        
        self.findings.append(f"Detected {len(anomalies)} anomalies")
        return f"Found {len(anomalies)} anomalies"
    
    def _correlate_events(self) -> str:
        """Correlate events across different sources"""
        logs = self.ingestion_engine.get_logs()
        alerts = self.ingestion_engine.get_alerts()
        anomalies = self.anomaly_detector.anomalies
        
        correlations = self.correlator.correlate_events(logs, alerts, anomalies)
        
        self.findings.append(f"Found {len(correlations)} event correlations")
        return f"Identified {len(correlations)} correlated event groups"
    
    def _map_mitre_techniques(self) -> str:
        """Map detected activities to MITRE ATT&CK"""
        alerts = self.ingestion_engine.get_alerts()
        anomalies = self.anomaly_detector.anomalies
        
        mappings = self.mitre_mapper.map_to_mitre(alerts, anomalies)
        
        self.findings.append(f"Mapped to {len(mappings)} MITRE ATT&CK techniques")
        return f"Mapped {len(mappings)} MITRE ATT&CK techniques"
    
    def _build_timeline(self) -> str:
        """Build incident timeline"""
        correlations = self.correlator.correlated_events
        timeline = self.correlator.build_attack_timeline(correlations)
        
        self.findings.append(f"Built timeline with {len(timeline)} events")
        return f"Constructed timeline with {len(timeline)} events"
    
    def _form_hypotheses(self) -> str:
        """Form initial hypotheses about the incident"""
        alerts = self.ingestion_engine.get_alerts()
        anomalies = self.anomaly_detector.anomalies
        mappings = self.mitre_mapper.map_to_mitre(alerts, anomalies)
        
        # Form hypotheses based on evidence
        if mappings:
            # Hypothesis based on MITRE attack chain
            attack_chain = self.mitre_mapper.get_attack_chain(mappings)
            self.hypotheses.append(Hypothesis(
                hypothesis_id=str(uuid.uuid4()),
                description=f"Attack follows pattern: {attack_chain}",
                confidence=0.7,
                evidence_for=[m.technique_name for m in mappings[:3]],
                status="active"
            ))
        
        # Hypothesis based on anomaly patterns
        if anomalies:
            anomaly_types = set(a.anomaly_type for a in anomalies)
            if 'brute_force_attempt' in anomaly_types:
                self.hypotheses.append(Hypothesis(
                    hypothesis_id=str(uuid.uuid4()),
                    description="Credential compromise through brute force attack",
                    confidence=0.75,
                    evidence_for=["Multiple failed authentication attempts detected"],
                    status="active"
                ))
        
        return f"Formed {len(self.hypotheses)} initial hypotheses"
    
    def _refine_hypotheses(self) -> str:
        """Refine hypotheses based on additional analysis"""
        # Analyze correlations to strengthen or weaken hypotheses
        correlations = self.correlator.correlated_events
        
        for hypothesis in self.hypotheses:
            # Look for supporting or contradicting evidence
            for correlation in correlations:
                if correlation['correlation_type'] == 'attack_chain':
                    # Strong evidence for attack chain hypothesis
                    hypothesis.confidence = min(0.95, hypothesis.confidence + 0.1)
                    hypothesis.evidence_for.append(
                        f"Attack chain correlation: {correlation['description']}"
                    )
        
        # Update current confidence based on best hypothesis
        if self.hypotheses:
            self.current_confidence = max(h.confidence for h in self.hypotheses)
        
        confirmed = sum(1 for h in self.hypotheses if h.confidence >= 0.85)
        return f"Refined hypotheses: {confirmed} confirmed, {len(self.hypotheses) - confirmed} under investigation"
    
    def _determine_root_cause(self) -> str:
        """Determine the root cause of the incident"""
        # Use the most confident hypothesis as root cause
        if not self.hypotheses:
            return "Unable to determine root cause"
        
        best_hypothesis = max(self.hypotheses, key=lambda h: h.confidence)
        best_hypothesis.status = "confirmed"
        
        self.findings.append(f"Root cause: {best_hypothesis.description}")
        return f"Identified root cause with {best_hypothesis.confidence:.0%} confidence"
    
    def _identify_affected_assets(self) -> str:
        """Identify all affected assets"""
        affected = set()
        
        # Collect from alerts
        for alert in self.ingestion_engine.get_alerts():
            affected.update(alert.affected_assets)
            if alert.source_ip:
                affected.add(alert.source_ip)
            if alert.destination_ip:
                affected.add(alert.destination_ip)
        
        # Collect from anomalies
        for anomaly in self.anomaly_detector.anomalies:
            affected.update(anomaly.affected_entities)
        
        self.findings.append(f"Affected assets: {', '.join(list(affected)[:10])}")
        return f"Identified {len(affected)} affected assets"
    
    def _recommend_mitigations(self) -> str:
        """Recommend mitigation actions"""
        mitigations = []
        
        alerts = self.ingestion_engine.get_alerts()
        anomalies = self.anomaly_detector.anomalies
        
        # Mitigation based on alert types
        alert_types = set(a.alert_type for a in alerts)
        
        if 'brute_force_attempt' in {a.anomaly_type for a in anomalies}:
            mitigations.append("Implement account lockout policy after failed login attempts")
            mitigations.append("Enable multi-factor authentication for all accounts")
        
        if any('sql_injection' in a.alert_type for a in alerts):
            mitigations.append("Apply input validation and parameterized queries")
            mitigations.append("Update and patch web application vulnerabilities")
        
        if any('port_scan' in a.anomaly_type for a in anomalies):
            mitigations.append("Review and restrict network firewall rules")
            mitigations.append("Implement network segmentation")
        
        # Generic mitigations
        mitigations.extend([
            "Review and rotate compromised credentials",
            "Conduct forensic analysis on affected systems",
            "Monitor for indicators of compromise",
            "Update incident response procedures based on findings"
        ])
        
        self.findings.append(f"Recommended {len(mitigations)} mitigation actions")
        return f"Generated {len(mitigations)} mitigation recommendations"
    
    def _generate_report(self) -> IncidentReport:
        """Generate the final incident report"""
        alerts = self.ingestion_engine.get_alerts()
        anomalies = self.anomaly_detector.anomalies
        mappings = self.mitre_mapper.map_to_mitre(alerts, anomalies)
        timeline = self.correlator.build_attack_timeline(self.correlator.correlated_events)
        
        # Determine severity
        max_severity = Severity.INFO
        for alert in alerts:
            if alert.severity == Severity.CRITICAL:
                max_severity = Severity.CRITICAL
                break
            elif alert.severity == Severity.HIGH and max_severity != Severity.CRITICAL:
                max_severity = Severity.HIGH
        
        # Get affected assets
        affected = set()
        for alert in alerts:
            affected.update(alert.affected_assets)
            if alert.source_ip:
                affected.add(alert.source_ip)
            if alert.destination_ip:
                affected.add(alert.destination_ip)
        for anomaly in anomalies:
            affected.update(anomaly.affected_entities)
        
        # Determine root cause from best hypothesis
        root_cause = "Unknown"
        if self.hypotheses:
            best_hypothesis = max(self.hypotheses, key=lambda h: h.confidence)
            root_cause = best_hypothesis.description
        
        # Generate summary
        summary = self._generate_summary(alerts, anomalies, mappings)
        
        # Collect mitigation actions
        mitigations = []
        for step in self.investigation_plan.completed_steps:
            if step['step'] == 'recommend_mitigations':
                # Extract mitigations from findings
                mitigations = [
                    "Implement account lockout policy after failed login attempts",
                    "Enable multi-factor authentication",
                    "Apply security patches and updates",
                    "Review and rotate compromised credentials",
                    "Implement network segmentation",
                    "Monitor for indicators of compromise"
                ]
                break
        
        return IncidentReport(
            incident_id=f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.now(),
            title=f"Cybersecurity Incident: {root_cause[:50]}",
            summary=summary,
            severity=max_severity,
            root_cause=root_cause,
            affected_assets=list(affected),
            timeline=timeline,
            mitre_mappings=mappings,
            mitigation_actions=mitigations,
            confidence=self.current_confidence,
            investigation_steps=[s['step'] for s in self.investigation_plan.completed_steps],
            hypotheses=self.hypotheses
        )
    
    def _generate_summary(self, alerts: List[Alert], 
                         anomalies: List[Anomaly], 
                         mappings: List) -> str:
        """Generate incident summary"""
        summary_parts = []
        
        summary_parts.append(
            f"Investigation completed with {len(alerts)} alerts and "
            f"{len(anomalies)} anomalies detected."
        )
        
        if mappings:
            tactics = self.mitre_mapper.get_attack_tactics(mappings)
            summary_parts.append(
                f"Attack spans {len(tactics)} MITRE ATT&CK tactics: {', '.join(tactics[:3])}."
            )
        
        if self.hypotheses:
            best_hypothesis = max(self.hypotheses, key=lambda h: h.confidence)
            summary_parts.append(
                f"Primary hypothesis: {best_hypothesis.description} "
                f"(confidence: {best_hypothesis.confidence:.0%})."
            )
        
        return " ".join(summary_parts)
