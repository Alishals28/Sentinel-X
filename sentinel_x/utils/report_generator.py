"""
Report generation utilities for SENTINEL-X
"""

from typing import Dict, Any
import json
from ..core.models import IncidentReport


class ReportGenerator:
    """Generates formatted incident reports"""
    
    @staticmethod
    def generate_text_report(report: IncidentReport) -> str:
        """Generate a text-based incident report"""
        lines = []
        lines.append("=" * 80)
        lines.append("SENTINEL-X INCIDENT REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append(f"Incident ID:  {report.incident_id}")
        lines.append(f"Timestamp:    {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Severity:     {report.severity.value.upper()}")
        lines.append(f"Confidence:   {report.confidence:.1%}")
        lines.append("")
        
        lines.append(f"Title: {report.title}")
        lines.append("-" * 80)
        lines.append("")
        
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        lines.append(report.summary)
        lines.append("")
        
        lines.append("ROOT CAUSE")
        lines.append("-" * 80)
        lines.append(report.root_cause)
        lines.append("")
        
        if report.affected_assets:
            lines.append("AFFECTED ASSETS")
            lines.append("-" * 80)
            for asset in report.affected_assets[:20]:
                lines.append(f"  • {asset}")
            if len(report.affected_assets) > 20:
                lines.append(f"  ... and {len(report.affected_assets) - 20} more")
            lines.append("")
        
        if report.mitre_mappings:
            lines.append("MITRE ATT&CK TECHNIQUES")
            lines.append("-" * 80)
            for mapping in report.mitre_mappings[:10]:
                lines.append(f"  • {mapping.technique_id}: {mapping.technique_name}")
                lines.append(f"    Tactic: {mapping.tactic}")
                lines.append(f"    Confidence: {mapping.confidence:.1%}")
                if mapping.evidence:
                    lines.append(f"    Evidence: {mapping.evidence[0][:60]}...")
                lines.append("")
        
        if report.timeline:
            lines.append("INCIDENT TIMELINE")
            lines.append("-" * 80)
            for i, event in enumerate(report.timeline[:15], 1):
                lines.append(
                    f"{i}. [{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"{event.event_type}: {event.description[:60]}..."
                )
            if len(report.timeline) > 15:
                lines.append(f"   ... and {len(report.timeline) - 15} more events")
            lines.append("")
        
        if report.hypotheses:
            lines.append("INVESTIGATION HYPOTHESES")
            lines.append("-" * 80)
            for hyp in report.hypotheses:
                lines.append(f"  • {hyp.description}")
                lines.append(f"    Status: {hyp.status} | Confidence: {hyp.confidence:.1%}")
                if hyp.evidence_for:
                    lines.append(f"    Supporting evidence: {len(hyp.evidence_for)} items")
                lines.append("")
        
        if report.mitigation_actions:
            lines.append("RECOMMENDED MITIGATION ACTIONS")
            lines.append("-" * 80)
            for i, action in enumerate(report.mitigation_actions, 1):
                lines.append(f"{i}. {action}")
            lines.append("")
        
        if report.investigation_steps:
            lines.append("INVESTIGATION STEPS COMPLETED")
            lines.append("-" * 80)
            for step in report.investigation_steps:
                lines.append(f"  ✓ {step}")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    @staticmethod
    def generate_json_report(report: IncidentReport) -> str:
        """Generate a JSON-formatted incident report"""
        return report.model_dump_json(indent=2)
    
    @staticmethod
    def generate_summary(report: IncidentReport) -> str:
        """Generate a brief summary of the incident"""
        summary = []
        summary.append(f"🔴 Incident {report.incident_id} ({report.severity.value.upper()})")
        summary.append(f"📋 {report.title}")
        summary.append(f"🎯 {report.root_cause}")
        summary.append(f"💻 {len(report.affected_assets)} affected assets")
        summary.append(f"🛡️  {len(report.mitre_mappings)} MITRE techniques identified")
        summary.append(f"📊 Confidence: {report.confidence:.1%}")
        
        return "\n".join(summary)
