"""
Anomaly detection tools for SENTINEL-X
"""

import re
from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import numpy as np
from ..core.models import LogEntry, Anomaly, Severity


class AnomalyDetector:
    """Detects anomalies in cybersecurity logs"""
    
    def __init__(self):
        self.baseline_threshold = 3.0  # Standard deviations for anomaly
        self.anomalies: List[Anomaly] = []
        self.anomaly_counter = 0
    
    def detect_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Run all anomaly detection methods"""
        self.anomalies.clear()
        
        # Various anomaly detection techniques
        self.anomalies.extend(self._detect_frequency_anomalies(logs))
        self.anomalies.extend(self._detect_pattern_anomalies(logs))
        self.anomalies.extend(self._detect_temporal_anomalies(logs))
        self.anomalies.extend(self._detect_volume_anomalies(logs))
        self.anomalies.extend(self._detect_failed_auth_anomalies(logs))
        self.anomalies.extend(self._detect_network_anomalies(logs))
        
        return self.anomalies
    
    def _detect_frequency_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Detect anomalies based on event frequency"""
        anomalies = []
        
        # Count events per source
        source_counts = Counter(log.source for log in logs)
        
        if len(source_counts) < 2:
            return anomalies
        
        # Calculate statistics
        counts = list(source_counts.values())
        mean_count = np.mean(counts)
        std_count = np.std(counts)
        
        if std_count == 0:
            return anomalies
        
        # Find outliers
        for source, count in source_counts.items():
            z_score = (count - mean_count) / std_count
            if abs(z_score) > self.baseline_threshold:
                self.anomaly_counter += 1
                anomalies.append(Anomaly(
                    anomaly_id=f"anomaly_{self.anomaly_counter}",
                    timestamp=datetime.now(),
                    anomaly_type="frequency_anomaly",
                    confidence=min(0.95, abs(z_score) / 10),
                    description=f"Unusual event frequency from {source}: {count} events (z-score: {z_score:.2f})",
                    affected_entities=[source],
                    evidence=[f"Expected ~{mean_count:.0f} events, observed {count}"]
                ))
        
        return anomalies
    
    def _detect_pattern_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Detect anomalies based on suspicious patterns"""
        anomalies = []
        
        # Suspicious patterns to look for
        attack_patterns = {
            'sql_injection': [r'union\s+select', r'or\s+1\s*=\s*1', r'drop\s+table', r"'\s*or\s*'"],
            'xss': [r'<script>', r'javascript:', r'onerror\s*=', r'onload\s*='],
            'command_injection': [r';\s*cat\s+', r'\|\s*nc\s+', r'&&\s*', r'`.*`'],
            'path_traversal': [r'\.\./\.\./', r'\.\.\\\.\.\\'],
            'brute_force': [r'failed.*login', r'authentication.*failed', r'invalid.*password'],
        }
        
        for log in logs:
            message_lower = log.message.lower()
            for attack_type, patterns in attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, message_lower, re.IGNORECASE):
                        self.anomaly_counter += 1
                        anomalies.append(Anomaly(
                            anomaly_id=f"anomaly_{self.anomaly_counter}",
                            timestamp=log.timestamp,
                            anomaly_type=f"pattern_{attack_type}",
                            confidence=0.85,
                            description=f"Detected {attack_type.replace('_', ' ')} pattern: {log.message[:100]}",
                            affected_entities=[log.source],
                            evidence=[f"Pattern matched: {pattern}", f"Message: {log.message[:200]}"]
                        ))
                        break
        
        return anomalies
    
    def _detect_temporal_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Detect anomalies in temporal patterns"""
        anomalies = []
        
        if len(logs) < 10:
            return anomalies
        
        # Group logs by hour
        hourly_counts = defaultdict(int)
        for log in logs:
            hour_key = log.timestamp.replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour_key] += 1
        
        if len(hourly_counts) < 2:
            return anomalies
        
        # Detect unusual activity times (e.g., off-hours)
        for hour, count in hourly_counts.items():
            # Flag activity between 2 AM and 5 AM as potentially suspicious
            if 2 <= hour.hour <= 5 and count > 5:
                self.anomaly_counter += 1
                anomalies.append(Anomaly(
                    anomaly_id=f"anomaly_{self.anomaly_counter}",
                    timestamp=hour,
                    anomaly_type="temporal_anomaly",
                    confidence=0.70,
                    description=f"Unusual activity during off-hours: {count} events at {hour.strftime('%Y-%m-%d %H:%M')}",
                    affected_entities=['system'],
                    evidence=[f"{count} events during typical off-hours"]
                ))
        
        return anomalies
    
    def _detect_volume_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Detect anomalies based on traffic volume"""
        anomalies = []
        
        # Group logs by minute
        minute_counts = defaultdict(int)
        for log in logs:
            minute_key = log.timestamp.replace(second=0, microsecond=0)
            minute_counts[minute_key] += 1
        
        if len(minute_counts) < 5:
            return anomalies
        
        counts = list(minute_counts.values())
        mean_count = np.mean(counts)
        std_count = np.std(counts)
        
        if std_count == 0:
            return anomalies
        
        # Detect volume spikes
        for minute, count in minute_counts.items():
            z_score = (count - mean_count) / std_count
            if z_score > self.baseline_threshold:
                self.anomaly_counter += 1
                anomalies.append(Anomaly(
                    anomaly_id=f"anomaly_{self.anomaly_counter}",
                    timestamp=minute,
                    anomaly_type="volume_spike",
                    confidence=min(0.90, z_score / 5),
                    description=f"Traffic volume spike: {count} events/minute (z-score: {z_score:.2f})",
                    affected_entities=['network'],
                    evidence=[f"Normal rate: {mean_count:.0f}/min, observed: {count}/min"]
                ))
        
        return anomalies
    
    def _detect_failed_auth_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Detect authentication-related anomalies"""
        anomalies = []
        
        # Track failed authentication attempts per source
        failed_auth_pattern = re.compile(r'fail.*auth|auth.*fail|invalid.*password|login.*fail', re.IGNORECASE)
        failed_auths = defaultdict(list)
        
        for log in logs:
            if failed_auth_pattern.search(log.message):
                failed_auths[log.source].append(log)
        
        # Flag sources with multiple failed attempts
        for source, auth_logs in failed_auths.items():
            if len(auth_logs) >= 3:
                self.anomaly_counter += 1
                time_span = auth_logs[-1].timestamp - auth_logs[0].timestamp
                anomalies.append(Anomaly(
                    anomaly_id=f"anomaly_{self.anomaly_counter}",
                    timestamp=auth_logs[-1].timestamp,
                    anomaly_type="brute_force_attempt",
                    confidence=0.88,
                    description=f"Multiple failed authentication attempts from {source}: {len(auth_logs)} failures",
                    affected_entities=[source],
                    evidence=[
                        f"{len(auth_logs)} failed authentication attempts",
                        f"Time span: {time_span}",
                        f"Sample: {auth_logs[0].message[:100]}"
                    ]
                ))
        
        return anomalies
    
    def _detect_network_anomalies(self, logs: List[LogEntry]) -> List[Anomaly]:
        """Detect network-related anomalies"""
        anomalies = []
        
        # Extract IP patterns from logs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # Track connections per IP
        connections = defaultdict(set)
        port_scan_pattern = re.compile(r'port\s*(?:scan|probe)', re.IGNORECASE)
        
        for log in logs:
            # Check for port scanning
            if port_scan_pattern.search(log.message):
                ips = ip_pattern.findall(log.message)
                if ips:
                    self.anomaly_counter += 1
                    anomalies.append(Anomaly(
                        anomaly_id=f"anomaly_{self.anomaly_counter}",
                        timestamp=log.timestamp,
                        anomaly_type="port_scan",
                        confidence=0.92,
                        description=f"Port scanning activity detected from {ips[0]}",
                        affected_entities=ips,
                        evidence=[f"Log message: {log.message[:150]}"]
                    ))
            
            # Track unique destinations per source IP
            ips = ip_pattern.findall(log.message)
            if len(ips) >= 2:
                connections[ips[0]].add(ips[1])
        
        # Flag IPs connecting to many destinations (potential lateral movement)
        for source_ip, destinations in connections.items():
            if len(destinations) > 10:
                self.anomaly_counter += 1
                anomalies.append(Anomaly(
                    anomaly_id=f"anomaly_{self.anomaly_counter}",
                    timestamp=datetime.now(),
                    anomaly_type="lateral_movement",
                    confidence=0.75,
                    description=f"Potential lateral movement: {source_ip} connected to {len(destinations)} destinations",
                    affected_entities=[source_ip],
                    evidence=[f"Connected to {len(destinations)} unique destinations"]
                ))
        
        return anomalies
