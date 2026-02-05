"""
MITRE ATT&CK mapping for SENTINEL-X
"""

from typing import List, Dict, Set
from ..core.models import Alert, Anomaly, MitreMapping


class MitreMapper:
    """Maps detected activities to MITRE ATT&CK framework"""
    
    def __init__(self):
        # Simplified MITRE ATT&CK technique database
        self.techniques = {
            'T1595': {
                'name': 'Active Scanning',
                'tactic': 'Reconnaissance',
                'keywords': ['port scan', 'network scan', 'probe', 'reconnaissance']
            },
            'T1110': {
                'name': 'Brute Force',
                'tactic': 'Credential Access',
                'keywords': ['brute force', 'password spray', 'failed login', 'authentication failed']
            },
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'keywords': ['sql injection', 'xss', 'exploit', 'vulnerability', 'web attack']
            },
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'keywords': ['command injection', 'shell', 'powershell', 'bash', 'script execution']
            },
            'T1548': {
                'name': 'Abuse Elevation Control Mechanism',
                'tactic': 'Privilege Escalation',
                'keywords': ['privilege escalation', 'sudo', 'admin rights', 'elevation']
            },
            'T1078': {
                'name': 'Valid Accounts',
                'tactic': 'Defense Evasion',
                'keywords': ['compromised account', 'unauthorized access', 'credential theft']
            },
            'T1021': {
                'name': 'Remote Services',
                'tactic': 'Lateral Movement',
                'keywords': ['lateral movement', 'remote execution', 'rdp', 'ssh', 'smb']
            },
            'T1070': {
                'name': 'Indicator Removal on Host',
                'tactic': 'Defense Evasion',
                'keywords': ['log deletion', 'clear logs', 'hide traces', 'anti-forensics']
            },
            'T1087': {
                'name': 'Account Discovery',
                'tactic': 'Discovery',
                'keywords': ['user enumeration', 'account discovery', 'whoami', 'net user']
            },
            'T1046': {
                'name': 'Network Service Scanning',
                'tactic': 'Discovery',
                'keywords': ['service scan', 'port enumeration', 'banner grab']
            },
            'T1003': {
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'keywords': ['credential dump', 'mimikatz', 'password hash', 'lsass']
            },
            'T1041': {
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'keywords': ['data exfiltration', 'c2', 'command and control', 'beacon']
            },
            'T1048': {
                'name': 'Exfiltration Over Alternative Protocol',
                'tactic': 'Exfiltration',
                'keywords': ['dns exfiltration', 'icmp tunnel', 'covert channel']
            },
            'T1486': {
                'name': 'Data Encrypted for Impact',
                'tactic': 'Impact',
                'keywords': ['ransomware', 'encryption', 'crypto', 'locked files']
            },
            'T1498': {
                'name': 'Network Denial of Service',
                'tactic': 'Impact',
                'keywords': ['ddos', 'dos', 'flood', 'denial of service']
            },
            'T1566': {
                'name': 'Phishing',
                'tactic': 'Initial Access',
                'keywords': ['phishing', 'spear phishing', 'malicious email', 'attachment']
            },
            'T1204': {
                'name': 'User Execution',
                'tactic': 'Execution',
                'keywords': ['malicious file', 'user clicked', 'executed attachment']
            },
            'T1071': {
                'name': 'Application Layer Protocol',
                'tactic': 'Command and Control',
                'keywords': ['http c2', 'https beacon', 'web shell']
            }
        }
    
    def map_to_mitre(self, alerts: List[Alert], anomalies: List[Anomaly]) -> List[MitreMapping]:
        """Map alerts and anomalies to MITRE ATT&CK techniques"""
        mappings = []
        technique_evidence = {}
        
        # Analyze alerts
        for alert in alerts:
            text = f"{alert.alert_type} {alert.description}".lower()
            matched_techniques = self._match_techniques(text)
            
            for technique_id in matched_techniques:
                if technique_id not in technique_evidence:
                    technique_evidence[technique_id] = {
                        'evidence': [],
                        'confidence_scores': []
                    }
                
                evidence_text = f"Alert: {alert.description[:100]}"
                technique_evidence[technique_id]['evidence'].append(evidence_text)
                technique_evidence[technique_id]['confidence_scores'].append(0.85)
        
        # Analyze anomalies
        for anomaly in anomalies:
            text = f"{anomaly.anomaly_type} {anomaly.description}".lower()
            matched_techniques = self._match_techniques(text)
            
            for technique_id in matched_techniques:
                if technique_id not in technique_evidence:
                    technique_evidence[technique_id] = {
                        'evidence': [],
                        'confidence_scores': []
                    }
                
                evidence_text = f"Anomaly: {anomaly.description[:100]}"
                technique_evidence[technique_id]['evidence'].append(evidence_text)
                
                # Anomalies have slightly lower confidence than explicit alerts
                base_confidence = anomaly.confidence * 0.8
                technique_evidence[technique_id]['confidence_scores'].append(base_confidence)
        
        # Create MITRE mappings
        for technique_id, data in technique_evidence.items():
            technique = self.techniques[technique_id]
            
            # Calculate average confidence
            avg_confidence = sum(data['confidence_scores']) / len(data['confidence_scores'])
            
            # Boost confidence if there's multiple evidence
            if len(data['evidence']) > 1:
                avg_confidence = min(0.95, avg_confidence * 1.2)
            
            mappings.append(MitreMapping(
                technique_id=technique_id,
                technique_name=technique['name'],
                tactic=technique['tactic'],
                confidence=avg_confidence,
                evidence=data['evidence']
            ))
        
        # Sort by confidence
        mappings.sort(key=lambda x: x.confidence, reverse=True)
        
        return mappings
    
    def _match_techniques(self, text: str) -> Set[str]:
        """Match text to MITRE ATT&CK techniques"""
        matched = set()
        
        for technique_id, technique in self.techniques.items():
            for keyword in technique['keywords']:
                if keyword in text:
                    matched.add(technique_id)
                    break
        
        return matched
    
    def get_attack_tactics(self, mappings: List[MitreMapping]) -> List[str]:
        """Get unique attack tactics from mappings"""
        tactics = []
        seen = set()
        
        for mapping in mappings:
            if mapping.tactic not in seen:
                tactics.append(mapping.tactic)
                seen.add(mapping.tactic)
        
        return tactics
    
    def get_attack_chain(self, mappings: List[MitreMapping]) -> str:
        """Describe the attack chain based on MITRE tactics"""
        # Order tactics in typical attack progression
        tactic_order = [
            'Reconnaissance',
            'Resource Development',
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Command and Control',
            'Exfiltration',
            'Impact'
        ]
        
        present_tactics = self.get_attack_tactics(mappings)
        ordered_tactics = [t for t in tactic_order if t in present_tactics]
        
        if len(ordered_tactics) == 0:
            return "No clear attack chain detected"
        elif len(ordered_tactics) == 1:
            return f"Single-stage attack: {ordered_tactics[0]}"
        else:
            return f"Multi-stage attack: {' > '.join(ordered_tactics)}"
