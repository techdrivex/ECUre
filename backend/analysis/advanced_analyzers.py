"""
Advanced firmware analysis tools for ECU vulnerability scanning.
"""

import os
import re
import hashlib
import binascii
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import logging
from collections import defaultdict
import struct

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """Analyze firmware for network-related vulnerabilities and configurations."""
    
    def __init__(self):
        self.network_patterns = {
            'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'mac_addresses': r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
            'urls': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'domain_names': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        }
        
        self.suspicious_network_patterns = {
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'passwd\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'key\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
            ],
            'insecure_protocols': [
                r'ftp://',
                r'telnet://',
                r'http://(?!localhost)',
                r'ws://(?!localhost)',
            ],
            'debug_endpoints': [
                r'/debug',
                r'/admin',
                r'/console',
                r'/shell',
                r'/terminal',
            ]
        }
    
    def analyze_network_config(self, firmware_data: bytes) -> Dict[str, Any]:
        """Analyze firmware for network configuration and vulnerabilities."""
        results = {
            'network_configs': [],
            'vulnerabilities': [],
            'suspicious_patterns': [],
            'statistics': {}
        }
        
        # Convert bytes to string for pattern matching
        firmware_text = firmware_data.decode('utf-8', errors='ignore')
        
        # Find network configurations
        for pattern_name, pattern in self.network_patterns.items():
            matches = re.findall(pattern, firmware_text)
            if matches:
                results['network_configs'].append({
                    'type': pattern_name,
                    'matches': list(set(matches)),
                    'count': len(set(matches))
                })
        
        # Find suspicious patterns
        for category, patterns in self.suspicious_network_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, firmware_text, re.IGNORECASE)
                if matches:
                    results['suspicious_patterns'].append({
                        'category': category,
                        'pattern': pattern,
                        'matches': list(set(matches)),
                        'count': len(set(matches)),
                        'severity': self._get_network_severity(category)
                    })
        
        # Calculate statistics
        results['statistics'] = {
            'total_network_configs': sum(len(config['matches']) for config in results['network_configs']),
            'total_suspicious_patterns': sum(len(pattern['matches']) for pattern in results['suspicious_patterns']),
            'vulnerability_score': self._calculate_network_vulnerability_score(results)
        }
        
        return results
    
    def _get_network_severity(self, category: str) -> str:
        """Get severity level for network vulnerability category."""
        severity_map = {
            'hardcoded_credentials': 'CRITICAL',
            'insecure_protocols': 'HIGH',
            'debug_endpoints': 'MEDIUM'
        }
        return severity_map.get(category, 'LOW')
    
    def _calculate_network_vulnerability_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall network vulnerability score."""
        score = 0.0
        
        for pattern in results['suspicious_patterns']:
            if pattern['severity'] == 'CRITICAL':
                score += 10.0
            elif pattern['severity'] == 'HIGH':
                score += 7.0
            elif pattern['severity'] == 'MEDIUM':
                score += 4.0
            else:
                score += 1.0
        
        return min(score, 10.0)  # Cap at 10.0


class CryptographyAnalyzer:
    """Analyze firmware for cryptographic implementations and vulnerabilities."""
    
    def __init__(self):
        self.crypto_patterns = {
            'weak_algorithms': [
                'md5', 'sha1', 'des', '3des', 'rc4', 'blowfish'
            ],
            'strong_algorithms': [
                'sha256', 'sha384', 'sha512', 'aes', 'rsa', 'ecdsa', 'chacha20'
            ],
            'crypto_functions': [
                'encrypt', 'decrypt', 'hash', 'sign', 'verify', 'keygen'
            ],
            'random_generators': [
                'rand', 'random', 'urandom', 'securerandom'
            ]
        }
        
        self.suspicious_crypto_patterns = {
            'weak_random': [
                r'rand\(\)',
                r'random\(\)',
                r'Math\.random\(\)',
            ],
            'hardcoded_keys': [
                r'private_key\s*=\s*["\'][^"\']+["\']',
                r'secret_key\s*=\s*["\'][^"\']+["\']',
                r'encryption_key\s*=\s*["\'][^"\']+["\']',
            ],
            'weak_encryption': [
                r'xor\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[a-zA-Z_][a-zA-Z0-9_]*',
                r'caesar',
                r'rot13',
            ]
        }
    
    def analyze_cryptography(self, firmware_data: bytes) -> Dict[str, Any]:
        """Analyze firmware for cryptographic implementations and vulnerabilities."""
        results = {
            'crypto_implementations': [],
            'vulnerabilities': [],
            'algorithm_usage': {},
            'statistics': {}
        }
        
        firmware_text = firmware_data.decode('utf-8', errors='ignore').lower()
        
        # Analyze algorithm usage
        for category, algorithms in self.crypto_patterns.items():
            usage = {}
            for algorithm in algorithms:
                count = firmware_text.count(algorithm)
                if count > 0:
                    usage[algorithm] = count
            
            if usage:
                results['algorithm_usage'][category] = usage
        
        # Find suspicious patterns
        for category, patterns in self.suspicious_crypto_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, firmware_text, re.IGNORECASE)
                if matches:
                    results['vulnerabilities'].append({
                        'category': category,
                        'pattern': pattern,
                        'matches': list(set(matches)),
                        'count': len(set(matches)),
                        'severity': self._get_crypto_severity(category)
                    })
        
        # Calculate statistics
        results['statistics'] = {
            'total_algorithms': sum(len(algs) for algs in results['algorithm_usage'].values()),
            'total_vulnerabilities': sum(len(vuln['matches']) for vuln in results['vulnerabilities']),
            'vulnerability_score': self._calculate_crypto_vulnerability_score(results)
        }
        
        return results
    
    def _get_crypto_severity(self, category: str) -> str:
        """Get severity level for cryptographic vulnerability category."""
        severity_map = {
            'weak_random': 'HIGH',
            'hardcoded_keys': 'CRITICAL',
            'weak_encryption': 'HIGH'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _calculate_crypto_vulnerability_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall cryptographic vulnerability score."""
        score = 0.0
        
        for vuln in results['vulnerabilities']:
            if vuln['severity'] == 'CRITICAL':
                score += 10.0
            elif vuln['severity'] == 'HIGH':
                score += 7.0
            elif vuln['severity'] == 'MEDIUM':
                score += 4.0
            else:
                score += 1.0
        
        return min(score, 10.0)


class MemoryAnalyzer:
    """Analyze firmware for memory-related vulnerabilities and patterns."""
    
    def __init__(self):
        self.memory_patterns = {
            'buffer_overflow_indicators': [
                r'strcpy\s*\(',
                r'strcat\s*\(',
                r'sprintf\s*\(',
                r'gets\s*\(',
                r'fscanf\s*\(',
            ],
            'memory_management': [
                r'malloc\s*\(',
                r'free\s*\(',
                r'calloc\s*\(',
                r'realloc\s*\(',
                r'new\s+',
                r'delete\s+',
            ],
            'pointer_operations': [
                r'\*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\+',
                r'\+\+[a-zA-Z_][a-zA-Z0-9_]*\*',
                r'[a-zA-Z_][a-zA-Z0-9_]*\*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\+',
            ]
        }
        
        self.suspicious_memory_patterns = {
            'potential_buffer_overflow': [
                r'char\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\[\s*\d+\s*\]',
                r'char\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*\d+',
            ],
            'unchecked_memory_allocation': [
                r'if\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*malloc\s*\(',
                r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*malloc\s*\([^)]*\)\s*;',
            ]
        }
    
    def analyze_memory_patterns(self, firmware_data: bytes) -> Dict[str, Any]:
        """Analyze firmware for memory-related patterns and vulnerabilities."""
        results = {
            'memory_patterns': [],
            'vulnerabilities': [],
            'statistics': {}
        }
        
        firmware_text = firmware_data.decode('utf-8', errors='ignore')
        
        # Analyze memory patterns
        for category, patterns in self.memory_patterns.items():
            usage = {}
            for pattern in patterns:
                matches = re.findall(pattern, firmware_text)
                if matches:
                    usage[pattern] = len(matches)
            
            if usage:
                results['memory_patterns'].append({
                    'category': category,
                    'patterns': usage,
                    'total_count': sum(usage.values())
                })
        
        # Find suspicious patterns
        for category, patterns in self.suspicious_memory_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, firmware_text)
                if matches:
                    results['vulnerabilities'].append({
                        'category': category,
                        'pattern': pattern,
                        'matches': list(set(matches)),
                        'count': len(set(matches)),
                        'severity': self._get_memory_severity(category)
                    })
        
        # Calculate statistics
        results['statistics'] = {
            'total_memory_patterns': sum(pattern['total_count'] for pattern in results['memory_patterns']),
            'total_vulnerabilities': sum(len(vuln['matches']) for vuln in results['vulnerabilities']),
            'vulnerability_score': self._calculate_memory_vulnerability_score(results)
        }
        
        return results
    
    def _get_memory_severity(self, category: str) -> str:
        """Get severity level for memory vulnerability category."""
        severity_map = {
            'potential_buffer_overflow': 'HIGH',
            'unchecked_memory_allocation': 'MEDIUM'
        }
        return severity_map.get(category, 'LOW')
    
    def _calculate_memory_vulnerability_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall memory vulnerability score."""
        score = 0.0
        
        for vuln in results['vulnerabilities']:
            if vuln['severity'] == 'HIGH':
                score += 7.0
            elif vuln['severity'] == 'MEDIUM':
                score += 4.0
            else:
                score += 1.0
        
        return min(score, 10.0)


class ProtocolAnalyzer:
    """Analyze firmware for communication protocols and their security implications."""
    
    def __init__(self):
        self.protocol_patterns = {
            'automotive_protocols': [
                'can', 'lin', 'flexray', 'most', 'ethernet', 'wifi', 'bluetooth'
            ],
            'security_protocols': [
                'tls', 'ssl', 'ssh', 'ipsec', 'dtls', 'wpa', 'wpa2', 'wpa3'
            ],
            'insecure_protocols': [
                'telnet', 'ftp', 'http', 'snmpv1', 'snmpv2'
            ]
        }
        
        self.protocol_vulnerabilities = {
            'weak_authentication': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'auth\s*=\s*["\'][^"\']+["\']',
                r'key\s*=\s*["\'][^"\']+["\']',
            ],
            'insecure_communication': [
                r'http://',
                r'ws://',
                r'ftp://',
                r'telnet://',
            ],
            'debug_modes': [
                r'debug\s*=\s*true',
                r'verbose\s*=\s*true',
                r'log_level\s*=\s*debug',
            ]
        }
    
    def analyze_protocols(self, firmware_data: bytes) -> Dict[str, Any]:
        """Analyze firmware for communication protocols and security."""
        results = {
            'protocols_detected': [],
            'vulnerabilities': [],
            'security_assessment': {},
            'statistics': {}
        }
        
        firmware_text = firmware_data.decode('utf-8', errors='ignore').lower()
        
        # Detect protocols
        for category, protocols in self.protocol_patterns.items():
            detected = []
            for protocol in protocols:
                if protocol in firmware_text:
                    detected.append(protocol)
            
            if detected:
                results['protocols_detected'].append({
                    'category': category,
                    'protocols': detected,
                    'count': len(detected)
                })
        
        # Find protocol vulnerabilities
        for category, patterns in self.protocol_vulnerabilities.items():
            for pattern in patterns:
                matches = re.findall(pattern, firmware_text, re.IGNORECASE)
                if matches:
                    results['vulnerabilities'].append({
                        'category': category,
                        'pattern': pattern,
                        'matches': list(set(matches)),
                        'count': len(set(matches)),
                        'severity': self._get_protocol_severity(category)
                    })
        
        # Security assessment
        results['security_assessment'] = {
            'overall_score': self._calculate_protocol_security_score(results),
            'recommendations': self._generate_protocol_recommendations(results)
        }
        
        # Calculate statistics
        results['statistics'] = {
            'total_protocols': sum(len(protocol['protocols']) for protocol in results['protocols_detected']),
            'total_vulnerabilities': sum(len(vuln['matches']) for vuln in results['vulnerabilities']),
            'security_score': results['security_assessment']['overall_score']
        }
        
        return results
    
    def _get_protocol_severity(self, category: str) -> str:
        """Get severity level for protocol vulnerability category."""
        severity_map = {
            'weak_authentication': 'CRITICAL',
            'insecure_communication': 'HIGH',
            'debug_modes': 'MEDIUM'
        }
        return severity_map.get(category, 'LOW')
    
    def _calculate_protocol_security_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall protocol security score."""
        base_score = 10.0
        
        for vuln in results['vulnerabilities']:
            if vuln['severity'] == 'CRITICAL':
                base_score -= 3.0
            elif vuln['severity'] == 'HIGH':
                base_score -= 2.0
            elif vuln['severity'] == 'MEDIUM':
                base_score -= 1.0
            else:
                base_score -= 0.5
        
        return max(base_score, 0.0)
    
    def _generate_protocol_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        for vuln in results['vulnerabilities']:
            if vuln['category'] == 'weak_authentication':
                recommendations.append("Implement strong authentication mechanisms")
            elif vuln['category'] == 'insecure_communication':
                recommendations.append("Use encrypted communication protocols (TLS, DTLS)")
            elif vuln['category'] == 'debug_modes':
                recommendations.append("Disable debug modes in production firmware")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
        
        return recommendations


class AdvancedFirmwareAnalyzer:
    """Advanced firmware analysis orchestrator with multiple specialized analyzers."""
    
    def __init__(self):
        self.network_analyzer = NetworkAnalyzer()
        self.crypto_analyzer = CryptographyAnalyzer()
        self.memory_analyzer = MemoryAnalyzer()
        self.protocol_analyzer = ProtocolAnalyzer()
    
    def comprehensive_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive firmware analysis using all analyzers."""
        try:
            with open(file_path, 'rb') as f:
                firmware_data = f.read()
            
            results = {
                'file_info': {
                    'path': file_path,
                    'size': len(firmware_data),
                    'hash': hashlib.sha256(firmware_data).hexdigest(),
                },
                'network_analysis': self.network_analyzer.analyze_network_config(firmware_data),
                'cryptography_analysis': self.crypto_analyzer.analyze_cryptography(firmware_data),
                'memory_analysis': self.memory_analyzer.analyze_memory_patterns(firmware_data),
                'protocol_analysis': self.protocol_analyzer.analyze_protocols(firmware_data),
                'overall_assessment': {}
            }
            
            # Calculate overall assessment
            results['overall_assessment'] = self._calculate_overall_assessment(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in comprehensive analysis: {e}")
            return {
                'error': str(e),
                'file_path': file_path
            }
    
    def _calculate_overall_assessment(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall security assessment."""
        scores = [
            results['network_analysis']['statistics']['vulnerability_score'],
            results['cryptography_analysis']['statistics']['vulnerability_score'],
            results['memory_analysis']['statistics']['vulnerability_score'],
            10.0 - results['protocol_analysis']['statistics']['security_score']  # Convert to vulnerability score
        ]
        
        overall_score = sum(scores) / len(scores)
        
        # Determine risk level
        if overall_score >= 8.0:
            risk_level = 'CRITICAL'
        elif overall_score >= 6.0:
            risk_level = 'HIGH'
        elif overall_score >= 4.0:
            risk_level = 'MEDIUM'
        elif overall_score >= 2.0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'overall_vulnerability_score': overall_score,
            'risk_level': risk_level,
            'recommendations': self._generate_overall_recommendations(results, overall_score)
        }
    
    def _generate_overall_recommendations(self, results: Dict[str, Any], score: float) -> List[str]:
        """Generate overall security recommendations."""
        recommendations = []
        
        if score >= 8.0:
            recommendations.append("Immediate security review required")
            recommendations.append("Consider firmware replacement if possible")
        elif score >= 6.0:
            recommendations.append("High priority security fixes needed")
            recommendations.append("Implement security patches immediately")
        elif score >= 4.0:
            recommendations.append("Medium priority security improvements recommended")
            recommendations.append("Schedule security updates")
        elif score >= 2.0:
            recommendations.append("Low priority security enhancements suggested")
        else:
            recommendations.append("Firmware appears secure")
        
        return recommendations
