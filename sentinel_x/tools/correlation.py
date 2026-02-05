"""
Event correlation engine for SENTINEL-X
"""

from typing import List, Dict, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import re
from ..core.models import LogEntry, Alert, Anomaly, TimelineEvent, Severity


class EventCorrelator:
    """Correlates events across different sources and time windows"""
    
    def __init__(self, correlation_window: timedelta = timedelta(minutes=5)):
        self.correlation_window = correlation_window
        self.correlated_events: List[Dict] = []
    
    def correlate_events(self, logs: List[LogEntry], 
                        alerts: List[Alert], 
                        anomalies: List[Anomaly]) -> List[Dict]:
        """Correlate logs, alerts, and anomalies to find related events"""
        self.correlated_events.clear()
        
        # Correlate by time proximity
        self.correlated_events.extend(self._correlate_by_time(logs, alerts, anomalies))
        
        # Correlate by entities (IPs, hostnames, users)
        self.correlated_events.extend(self._correlate_by_entities(logs, alerts, anomalies))
        
        # Correlate by attack patterns
        self.correlated_events.extend(self._correlate_by_patterns(logs, alerts, anomalies))
        
        return self.correlated_events
    
    def _correlate_by_time(self, logs: List[LogEntry], 
                          alerts: List[Alert], 
                          anomalies: List[Anomaly]) -> List[Dict]:
        """Correlate events that occur within the same time window"""
        correlations = []
        
        # Group alerts by time windows
        time_windows = defaultdict(lambda: {'alerts': [], 'anomalies': [], 'logs': []})
        
        for alert in alerts:
            window_key = self._get_time_window(alert.timestamp)
            time_windows[window_key]['alerts'].append(alert)
        
        for anomaly in anomalies:
            window_key = self._get_time_window(anomaly.timestamp)
            time_windows[window_key]['anomalies'].append(anomaly)
        
        # Only include relevant high-severity logs
        for log in logs:
            if log.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                window_key = self._get_time_window(log.timestamp)
                time_windows[window_key]['logs'].append(log)
        
        # Create correlations for windows with multiple events
        for window_key, events in time_windows.items():
            total_events = len(events['alerts']) + len(events['anomalies']) + len(events['logs'])
            if total_events >= 2:
                correlations.append({
                    'correlation_type': 'temporal',
                    'window': window_key,
                    'alerts': events['alerts'],
                    'anomalies': events['anomalies'],
                    'logs': events['logs'],
                    'confidence': min(0.95, 0.5 + (total_events * 0.1)),
                    'description': f"Temporal correlation: {total_events} related events within {self.correlation_window}"
                })
        
        return correlations
    
    def _correlate_by_entities(self, logs: List[LogEntry], 
                               alerts: List[Alert], 
                               anomalies: List[Anomaly]) -> List[Dict]:
        """Correlate events affecting the same entities"""
        correlations = []
        
        # Extract entities from all sources
        entity_events = defaultdict(lambda: {'alerts': [], 'anomalies': [], 'logs': []})
        
        # Extract IPs, hostnames, usernames from logs and alerts
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        for alert in alerts:
            entities = set()
            if alert.source_ip:
                entities.add(alert.source_ip)
            if alert.destination_ip:
                entities.add(alert.destination_ip)
            entities.update(alert.affected_assets)
            
            # Also extract from description
            entities.update(ip_pattern.findall(alert.description))
            
            for entity in entities:
                entity_events[entity]['alerts'].append(alert)
        
        for anomaly in anomalies:
            entities = set(anomaly.affected_entities)
            for entity in entities:
                entity_events[entity]['anomalies'].append(anomaly)
        
        for log in logs:
            if log.severity in [Severity.CRITICAL, Severity.HIGH]:
                entities = set()
                entities.add(log.source)
                entities.update(ip_pattern.findall(log.message))
                
                for entity in entities:
                    entity_events[entity]['logs'].append(log)
        
        # Create correlations for entities with multiple events
        for entity, events in entity_events.items():
            total_events = len(events['alerts']) + len(events['anomalies']) + len(events['logs'])
            if total_events >= 2:
                correlations.append({
                    'correlation_type': 'entity',
                    'entity': entity,
                    'alerts': events['alerts'],
                    'anomalies': events['anomalies'],
                    'logs': events['logs'],
                    'confidence': min(0.90, 0.6 + (total_events * 0.08)),
                    'description': f"Entity correlation: {total_events} events affecting {entity}"
                })
        
        return correlations
    
    def _correlate_by_patterns(self, logs: List[LogEntry], 
                               alerts: List[Alert], 
                               anomalies: List[Anomaly]) -> List[Dict]:
        """Correlate events by attack patterns"""
        correlations = []
        
        # Define attack chain patterns
        attack_chains = {
            'reconnaissance': ['port scan', 'network probe', 'dns enumeration'],
            'initial_access': ['brute force', 'phishing', 'exploit'],
            'privilege_escalation': ['privilege escalation', 'sudo', 'admin'],
            'lateral_movement': ['lateral movement', 'remote execution', 'smb'],
            'exfiltration': ['data exfiltration', 'large transfer', 'unusual upload']
        }
        
        # Track which attack stages are present
        detected_stages = defaultdict(lambda: {'alerts': [], 'anomalies': [], 'logs': []})
        
        for alert in alerts:
            alert_text = f"{alert.alert_type} {alert.description}".lower()
            for stage, keywords in attack_chains.items():
                if any(keyword in alert_text for keyword in keywords):
                    detected_stages[stage]['alerts'].append(alert)
        
        for anomaly in anomalies:
            anomaly_text = f"{anomaly.anomaly_type} {anomaly.description}".lower()
            for stage, keywords in attack_chains.items():
                if any(keyword in anomaly_text for keyword in keywords):
                    detected_stages[stage]['anomalies'].append(anomaly)
        
        for log in logs:
            if log.severity in [Severity.CRITICAL, Severity.HIGH]:
                log_text = log.message.lower()
                for stage, keywords in attack_chains.items():
                    if any(keyword in log_text for keyword in keywords):
                        detected_stages[stage]['logs'].append(log)
        
        # Create correlation if multiple attack stages are detected
        if len(detected_stages) >= 2:
            all_alerts = []
            all_anomalies = []
            all_logs = []
            
            for stage, events in detected_stages.items():
                all_alerts.extend(events['alerts'])
                all_anomalies.extend(events['anomalies'])
                all_logs.extend(events['logs'])
            
            correlations.append({
                'correlation_type': 'attack_chain',
                'stages': list(detected_stages.keys()),
                'alerts': all_alerts,
                'anomalies': all_anomalies,
                'logs': all_logs,
                'confidence': min(0.95, 0.7 + (len(detected_stages) * 0.1)),
                'description': f"Attack chain detected: {', '.join(detected_stages.keys())}"
            })
        
        return correlations
    
    def _get_time_window(self, timestamp: datetime) -> datetime:
        """Get the time window key for a timestamp"""
        # Round down to the nearest correlation window
        total_seconds = int(timestamp.timestamp())
        window_seconds = int(self.correlation_window.total_seconds())
        window_start = (total_seconds // window_seconds) * window_seconds
        return datetime.fromtimestamp(window_start)
    
    def build_attack_timeline(self, correlations: List[Dict]) -> List[TimelineEvent]:
        """Build a chronological timeline from correlated events"""
        timeline = []
        
        for correlation in correlations:
            # Add all events from the correlation
            for alert in correlation.get('alerts', []):
                timeline.append(TimelineEvent(
                    timestamp=alert.timestamp,
                    event_type=alert.alert_type,
                    description=alert.description,
                    source='alert',
                    severity=alert.severity,
                    related_entities=alert.affected_assets
                ))
            
            for anomaly in correlation.get('anomalies', []):
                timeline.append(TimelineEvent(
                    timestamp=anomaly.timestamp,
                    event_type=anomaly.anomaly_type,
                    description=anomaly.description,
                    source='anomaly',
                    severity=Severity.MEDIUM,
                    related_entities=anomaly.affected_entities
                ))
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x.timestamp)
        
        return timeline
