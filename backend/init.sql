-- ECUre Database Initialization Script

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_firmware_files_hash ON scanner_firmwarefile(file_hash);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scanner_scansession(status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON scanner_vulnerability(severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON core_auditlog(timestamp);

-- Create views for common queries
CREATE OR REPLACE VIEW vulnerability_summary AS
SELECT 
    vs.severity,
    COUNT(*) as count,
    AVG(CASE WHEN vs.cvss_score IS NOT NULL THEN vs.cvss_score ELSE 0 END) as avg_cvss
FROM scanner_vulnerability vs
GROUP BY vs.severity;

CREATE OR REPLACE VIEW scan_statistics AS
SELECT 
    ss.scan_type,
    COUNT(*) as total_scans,
    AVG(EXTRACT(EPOCH FROM (ss.end_time - ss.start_time))) as avg_duration_seconds,
    COUNT(CASE WHEN ss.status = 'COMPLETED' THEN 1 END) as completed_scans,
    COUNT(CASE WHEN ss.status = 'FAILED' THEN 1 END) as failed_scans
FROM scanner_scansession ss
GROUP BY ss.scan_type;
