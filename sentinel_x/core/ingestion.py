"""
Log ingestion system for SENTINEL-X
"""

import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from ..core.models import LogEntry, Alert, Severity


class LogParser:
    """Parses various log formats"""
    
    def __init__(self):
        self.parsers = {
            'json': self._parse_json,
            'syslog': self._parse_syslog,
            'csv': self._parse_csv,
            'generic': self._parse_generic
        }
    
    def parse(self, log_line: str, format_type: str = 'generic') -> Optional[LogEntry]:
        """Parse a log line based on format type"""
        parser = self.parsers.get(format_type, self._parse_generic)
        return parser(log_line)
    
    def _parse_json(self, log_line: str) -> Optional[LogEntry]:
        """Parse JSON formatted log"""
        try:
            data = json.loads(log_line)
            return LogEntry(
                timestamp=self._parse_timestamp(data.get('timestamp', data.get('time', ''))),
                source=data.get('source', data.get('host', 'unknown')),
                message=data.get('message', data.get('msg', str(data))),
                severity=self._parse_severity(data.get('severity', data.get('level', 'info'))),
                metadata=data,
                raw_data=log_line
            )
        except Exception:
            return None
    
    def _parse_syslog(self, log_line: str) -> Optional[LogEntry]:
        """Parse syslog formatted log"""
        # Basic syslog pattern: <priority>timestamp host process[pid]: message
        pattern = r'<(\d+)>(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+?):\s+(.+)'
        match = re.match(pattern, log_line)
        
        if match:
            priority, timestamp_str, host, process, message = match.groups()
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp_str),
                source=host,
                message=message,
                severity=self._severity_from_priority(int(priority)),
                metadata={'process': process, 'priority': priority},
                raw_data=log_line
            )
        return self._parse_generic(log_line)
    
    def _parse_csv(self, log_line: str) -> Optional[LogEntry]:
        """Parse CSV formatted log"""
        parts = log_line.split(',')
        if len(parts) >= 3:
            return LogEntry(
                timestamp=self._parse_timestamp(parts[0].strip()),
                source=parts[1].strip() if len(parts) > 1 else 'unknown',
                message=','.join(parts[2:]).strip(),
                severity=Severity.INFO,
                raw_data=log_line
            )
        return None
    
    def _parse_generic(self, log_line: str) -> Optional[LogEntry]:
        """Parse generic log format"""
        try:
            # Try to extract timestamp from common patterns
            timestamp_patterns = [
                r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
                r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
                r'\w+\s+\d+\s+\d{2}:\d{2}:\d{2}'
            ]
            
            timestamp = datetime.now()
            for pattern in timestamp_patterns:
                match = re.search(pattern, log_line)
                if match:
                    timestamp = self._parse_timestamp(match.group())
                    break
            
            return LogEntry(
                timestamp=timestamp,
                source='unknown',
                message=log_line,
                severity=self._detect_severity(log_line),
                raw_data=log_line
            )
        except Exception:
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats"""
        if not timestamp_str:
            return datetime.now()
        
        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%b %d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%SZ',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str.strip(), fmt)
            except ValueError:
                continue
        
        return datetime.now()
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity level"""
        severity_lower = str(severity_str).lower()
        if 'crit' in severity_lower or 'fatal' in severity_lower:
            return Severity.CRITICAL
        elif 'err' in severity_lower or 'alert' in severity_lower:
            return Severity.HIGH
        elif 'warn' in severity_lower:
            return Severity.MEDIUM
        elif 'info' in severity_lower or 'notice' in severity_lower:
            return Severity.INFO
        elif 'debug' in severity_lower or 'trace' in severity_lower:
            return Severity.LOW
        return Severity.INFO
    
    def _severity_from_priority(self, priority: int) -> Severity:
        """Convert syslog priority to severity"""
        severity_num = priority & 0x07
        if severity_num <= 2:
            return Severity.CRITICAL
        elif severity_num <= 4:
            return Severity.HIGH
        elif severity_num == 5:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _detect_severity(self, message: str) -> Severity:
        """Detect severity from message content"""
        message_lower = message.lower()
        if any(word in message_lower for word in ['critical', 'fatal', 'emergency', 'attack', 'breach']):
            return Severity.CRITICAL
        elif any(word in message_lower for word in ['error', 'failed', 'alert', 'unauthorized', 'malicious']):
            return Severity.HIGH
        elif any(word in message_lower for word in ['warning', 'suspect', 'unusual', 'anomaly']):
            return Severity.MEDIUM
        else:
            return Severity.INFO


class LogIngestionEngine:
    """Main log ingestion engine"""
    
    def __init__(self):
        self.parser = LogParser()
        self.logs: List[LogEntry] = []
        self.alerts: List[Alert] = []
    
    def ingest_file(self, file_path: str, format_type: str = 'generic') -> int:
        """Ingest logs from a file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        count = 0
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                log_entry = self.parser.parse(line, format_type)
                if log_entry:
                    self.logs.append(log_entry)
                    count += 1
                    
                    # Check if this log should generate an alert
                    alert = self._check_for_alert(log_entry)
                    if alert:
                        self.alerts.append(alert)
        
        return count
    
    def ingest_logs(self, log_lines: List[str], format_type: str = 'generic') -> int:
        """Ingest logs from a list of log lines"""
        count = 0
        for line in log_lines:
            log_entry = self.parser.parse(line, format_type)
            if log_entry:
                self.logs.append(log_entry)
                count += 1
                
                alert = self._check_for_alert(log_entry)
                if alert:
                    self.alerts.append(alert)
        
        return count
    
    def _check_for_alert(self, log_entry: LogEntry) -> Optional[Alert]:
        """Check if a log entry should generate an alert"""
        # Generate alerts for high severity logs or suspicious patterns
        if log_entry.severity in [Severity.CRITICAL, Severity.HIGH]:
            return Alert(
                alert_id=f"alert_{len(self.alerts) + 1}",
                timestamp=log_entry.timestamp,
                alert_type="suspicious_activity",
                severity=log_entry.severity,
                description=log_entry.message,
                metadata={'source_log': log_entry.source}
            )
        
        # Check for specific attack patterns
        suspicious_patterns = [
            'sql injection', 'xss', 'command injection', 'buffer overflow',
            'privilege escalation', 'lateral movement', 'data exfiltration',
            'brute force', 'port scan', 'malware', 'ransomware', 'backdoor'
        ]
        
        message_lower = log_entry.message.lower()
        for pattern in suspicious_patterns:
            if pattern in message_lower:
                return Alert(
                    alert_id=f"alert_{len(self.alerts) + 1}",
                    timestamp=log_entry.timestamp,
                    alert_type=pattern.replace(' ', '_'),
                    severity=Severity.HIGH,
                    description=f"Potential {pattern} detected: {log_entry.message[:100]}",
                    metadata={'pattern': pattern, 'source_log': log_entry.source}
                )
        
        return None
    
    def get_logs(self, start_time: Optional[datetime] = None, 
                 end_time: Optional[datetime] = None,
                 severity: Optional[Severity] = None) -> List[LogEntry]:
        """Get filtered logs"""
        filtered_logs = self.logs
        
        if start_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp >= start_time]
        if end_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp <= end_time]
        if severity:
            filtered_logs = [log for log in filtered_logs if log.severity == severity]
        
        return filtered_logs
    
    def get_alerts(self) -> List[Alert]:
        """Get all alerts"""
        return self.alerts
    
    def clear(self):
        """Clear all ingested data"""
        self.logs.clear()
        self.alerts.clear()
