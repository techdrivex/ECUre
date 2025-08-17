"""
Report generation tools for ECUre vulnerability scanning results.
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
from django.template.loader import render_to_string
from django.conf import settings

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate comprehensive vulnerability reports in multiple formats."""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / 'templates'
        self.output_dir = Path(settings.MEDIA_ROOT) / 'reports'
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_json_report(self, scan_data: Dict[str, Any], filename: str = None) -> str:
        """Generate JSON format report."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_report_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        try:
            # Prepare report data
            report_data = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'tool_version': '1.0.0',
                    'scan_id': scan_data.get('scan_id'),
                    'firmware_file': scan_data.get('firmware_file', {}),
                },
                'scan_summary': {
                    'scan_type': scan_data.get('scan_type'),
                    'start_time': scan_data.get('start_time'),
                    'end_time': scan_data.get('end_time'),
                    'total_vulnerabilities': len(scan_data.get('vulnerabilities', [])),
                    'risk_level': scan_data.get('risk_level', 'UNKNOWN'),
                },
                'vulnerabilities': scan_data.get('vulnerabilities', []),
                'analysis_results': scan_data.get('analysis_results', {}),
                'recommendations': scan_data.get('recommendations', []),
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise
    
    def generate_csv_report(self, scan_data: Dict[str, Any], filename: str = None) -> str:
        """Generate CSV format report."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_report_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        try:
            vulnerabilities = scan_data.get('vulnerabilities', [])
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                if vulnerabilities:
                    # Write vulnerabilities to CSV
                    fieldnames = [
                        'id', 'title', 'description', 'severity', 'status',
                        'cve_id', 'cvss_score', 'location', 'evidence',
                        'recommendations', 'discovered_at'
                    ]
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for vuln in vulnerabilities:
                        writer.writerow({
                            'id': vuln.get('id', ''),
                            'title': vuln.get('title', ''),
                            'description': vuln.get('description', ''),
                            'severity': vuln.get('severity', ''),
                            'status': vuln.get('status', ''),
                            'cve_id': vuln.get('cve_id', ''),
                            'cvss_score': vuln.get('cvss_score', ''),
                            'location': json.dumps(vuln.get('location', {})),
                            'evidence': vuln.get('evidence', ''),
                            'recommendations': vuln.get('recommendations', ''),
                            'discovered_at': vuln.get('discovered_at', ''),
                        })
                else:
                    # Write summary if no vulnerabilities
                    writer = csv.writer(f)
                    writer.writerow(['No vulnerabilities found'])
                    writer.writerow(['Scan completed successfully'])
            
            logger.info(f"CSV report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            raise
    
    def generate_html_report(self, scan_data: Dict[str, Any], filename: str = None) -> str:
        """Generate HTML format report."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"scan_report_{timestamp}.html"
        
        filepath = self.output_dir / filename
        
        try:
            # Prepare template context
            context = {
                'scan_data': scan_data,
                'generated_at': datetime.now(),
                'tool_version': '1.0.0',
                'total_vulnerabilities': len(scan_data.get('vulnerabilities', [])),
                'vulnerabilities_by_severity': self._group_vulnerabilities_by_severity(
                    scan_data.get('vulnerabilities', [])
                ),
                'risk_level': scan_data.get('risk_level', 'UNKNOWN'),
                'recommendations': scan_data.get('recommendations', []),
            }
            
            # Generate HTML content
            html_content = self._generate_html_content(context)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
    
    def generate_pdf_report(self, scan_data: Dict[str, Any], filename: str = None) -> str:
        """Generate PDF format report using HTML template."""
        try:
            # First generate HTML
            html_file = self.generate_html_report(scan_data, filename)
            
            # Convert HTML to PDF using weasyprint or similar
            # For now, return the HTML file path
            # TODO: Implement PDF conversion
            logger.info(f"PDF generation not yet implemented, returning HTML: {html_file}")
            return html_file
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
    
    def generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of scan results."""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk metrics
        total_vulns = len(vulnerabilities)
        critical_vulns = severity_counts.get('CRITICAL', 0)
        high_vulns = severity_counts.get('HIGH', 0)
        medium_vulns = severity_counts.get('MEDIUM', 0)
        low_vulns = severity_counts.get('LOW', 0)
        
        # Calculate risk score
        risk_score = (critical_vulns * 10 + high_vulns * 7 + medium_vulns * 4 + low_vulns * 1) / max(total_vulns, 1)
        
        # Determine overall risk level
        if risk_score >= 8.0:
            risk_level = 'CRITICAL'
        elif risk_score >= 6.0:
            risk_level = 'HIGH'
        elif risk_score >= 4.0:
            risk_level = 'MEDIUM'
        elif risk_score >= 2.0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'executive_summary': {
                'total_vulnerabilities': total_vulns,
                'critical_vulnerabilities': critical_vulns,
                'high_vulnerabilities': high_vulns,
                'medium_vulnerabilities': medium_vulns,
                'low_vulnerabilities': low_vulns,
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'scan_duration': self._calculate_scan_duration(scan_data),
                'firmware_info': scan_data.get('firmware_file', {}),
            },
            'key_findings': self._extract_key_findings(vulnerabilities),
            'immediate_actions': self._generate_immediate_actions(severity_counts),
            'long_term_recommendations': self._generate_long_term_recommendations(scan_data),
        }
    
    def _group_vulnerabilities_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by severity level."""
        grouped = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(vuln)
        return grouped
    
    def _calculate_scan_duration(self, scan_data: Dict[str, Any]) -> str:
        """Calculate scan duration."""
        start_time = scan_data.get('start_time')
        end_time = scan_data.get('end_time')
        
        if start_time and end_time:
            try:
                start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                duration = end - start
                return str(duration)
            except:
                pass
        
        return 'Unknown'
    
    def _extract_key_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from vulnerabilities."""
        findings = []
        
        # Find critical and high severity vulnerabilities
        for vuln in vulnerabilities:
            if vuln.get('severity') in ['CRITICAL', 'HIGH']:
                findings.append(f"{vuln.get('severity')}: {vuln.get('title', 'Unknown vulnerability')}")
        
        # Limit to top 5 findings
        return findings[:5]
    
    def _generate_immediate_actions(self, severity_counts: Dict[str, int]) -> List[str]:
        """Generate immediate action items."""
        actions = []
        
        if severity_counts.get('CRITICAL', 0) > 0:
            actions.append("Immediately address all CRITICAL vulnerabilities")
        
        if severity_counts.get('HIGH', 0) > 0:
            actions.append("Address HIGH severity vulnerabilities within 24-48 hours")
        
        if severity_counts.get('MEDIUM', 0) > 0:
            actions.append("Plan remediation for MEDIUM severity vulnerabilities")
        
        if not actions:
            actions.append("No immediate actions required")
        
        return actions
    
    def _generate_long_term_recommendations(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate long-term security recommendations."""
        recommendations = [
            "Implement secure development lifecycle (SDL) practices",
            "Regular security training for development teams",
            "Automated security testing in CI/CD pipeline",
            "Regular firmware security assessments",
            "Keep firmware updated with latest security patches",
        ]
        
        # Add specific recommendations based on scan data
        if scan_data.get('analysis_results', {}).get('network_analysis'):
            recommendations.append("Implement network segmentation and monitoring")
        
        if scan_data.get('analysis_results', {}).get('cryptography_analysis'):
            recommendations.append("Use strong cryptographic algorithms and key management")
        
        return recommendations
    
    def _generate_html_content(self, context: Dict[str, Any]) -> str:
        """Generate HTML content for the report."""
        # Simple HTML template - in production, use proper Django templates
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ECUre Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .summary { background: #e9ecef; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .vulnerability { border: 1px solid #dee2e6; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .severity-badge { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ECUre Vulnerability Scan Report</h1>
        <p><strong>Generated:</strong> {generated_at}</p>
        <p><strong>Tool Version:</strong> {tool_version}</p>
        <p><strong>Risk Level:</strong> {risk_level}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {total_vulnerabilities}</p>
        <p><strong>Risk Level:</strong> {risk_level}</p>
    </div>
    
    <h2>Vulnerabilities by Severity</h2>
    {vulnerabilities_section}
    
    <h2>Recommendations</h2>
    <ul>
        {recommendations_list}
    </ul>
</body>
</html>
        """
        
        # Generate vulnerabilities section
        vulnerabilities_html = ""
        for severity, vulns in context['vulnerabilities_by_severity'].items():
            for vuln in vulns:
                severity_class = f"severity-{severity.lower()}"
                vulnerabilities_html += f"""
                <div class="vulnerability {severity.lower()}">
                    <h3>{vuln.get('title', 'Unknown')}</h3>
                    <span class="severity-badge {severity_class}">{severity}</span>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                    <p><strong>Status:</strong> {vuln.get('status', 'Unknown')}</p>
                    <p><strong>Evidence:</strong> {vuln.get('evidence', 'No evidence')}</p>
                </div>
                """
        
        # Generate recommendations list
        recommendations_html = ""
        for rec in context['recommendations']:
            recommendations_html += f"<li>{rec}</li>"
        
        # Fill template
        return html_template.format(
            generated_at=context['generated_at'],
            tool_version=context['tool_version'],
            risk_level=context['risk_level'],
            total_vulnerabilities=context['total_vulnerabilities'],
            vulnerabilities_section=vulnerabilities_html,
            recommendations_list=recommendations_html
        )


class ReportExporter:
    """Export reports in various formats and manage report storage."""
    
    def __init__(self):
        self.generator = ReportGenerator()
        self.supported_formats = ['json', 'csv', 'html', 'pdf']
    
    def export_report(self, scan_data: Dict[str, Any], formats: List[str] = None) -> Dict[str, str]:
        """Export scan report in multiple formats."""
        if formats is None:
            formats = ['json', 'html']
        
        exported_files = {}
        
        for format_type in formats:
            if format_type not in self.supported_formats:
                logger.warning(f"Unsupported format: {format_type}")
                continue
            
            try:
                if format_type == 'json':
                    filepath = self.generator.generate_json_report(scan_data)
                elif format_type == 'csv':
                    filepath = self.generator.generate_csv_report(scan_data)
                elif format_type == 'html':
                    filepath = self.generator.generate_html_report(scan_data)
                elif format_type == 'pdf':
                    filepath = self.generator.generate_pdf_report(scan_data)
                
                exported_files[format_type] = filepath
                
            except Exception as e:
                logger.error(f"Error exporting {format_type} report: {e}")
                exported_files[format_type] = f"Error: {str(e)}"
        
        return exported_files
    
    def generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for stakeholders."""
        return self.generator.generate_executive_summary(scan_data)
    
    def cleanup_old_reports(self, days_old: int = 30) -> int:
        """Clean up old report files."""
        try:
            cutoff_date = datetime.now().timestamp() - (days_old * 24 * 60 * 60)
            cleaned_count = 0
            
            for filepath in self.generator.output_dir.glob('*'):
                if filepath.is_file() and filepath.stat().st_mtime < cutoff_date:
                    filepath.unlink()
                    cleaned_count += 1
            
            logger.info(f"Cleaned up {cleaned_count} old report files")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old reports: {e}")
            return 0
