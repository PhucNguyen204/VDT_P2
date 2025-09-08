-- EDR Database Initialization Script
-- This script sets up the initial database schema and sample data

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname);

CREATE INDEX IF NOT EXISTS idx_processes_agent_id ON processes(agent_id);
CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_parent_pid ON processes(parent_pid);
CREATE INDEX IF NOT EXISTS idx_processes_tree_id ON processes(tree_id);

CREATE INDEX IF NOT EXISTS idx_process_trees_agent_id ON process_trees(agent_id);
CREATE INDEX IF NOT EXISTS idx_process_trees_root_process_id ON process_trees(root_process_id);

CREATE INDEX IF NOT EXISTS idx_sigma_rules_enabled ON sigma_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_sigma_rules_level ON sigma_rules(level);

CREATE INDEX IF NOT EXISTS idx_detections_rule_id ON detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_detections_event_id ON detections(event_id);
CREATE INDEX IF NOT EXISTS idx_detections_agent_id ON detections(agent_id);
CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections(created_at);

-- GIN indexes for JSON fields
CREATE INDEX IF NOT EXISTS idx_events_event_data_gin ON events USING GIN (event_data);
CREATE INDEX IF NOT EXISTS idx_alerts_tags_gin ON alerts USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre_gin ON alerts USING GIN (mitre);
CREATE INDEX IF NOT EXISTS idx_sigma_rules_tags_gin ON sigma_rules USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_sigma_rules_references_gin ON sigma_rules USING GIN (references);
CREATE INDEX IF NOT EXISTS idx_detections_matched_gin ON detections USING GIN (matched);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_events_process_name_trgm ON events USING GIN (process_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_events_command_line_trgm ON events USING GIN (command_line gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_alerts_title_trgm ON alerts USING GIN (title gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_alerts_description_trgm ON alerts USING GIN (description gin_trgm_ops);

-- Create views for common queries
CREATE OR REPLACE VIEW v_agent_summary AS
SELECT 
    a.id,
    a.hostname,
    a.ip_address,
    a.os,
    a.status,
    a.last_seen,
    COUNT(DISTINCT e.id) as total_events,
    COUNT(DISTINCT al.id) as total_alerts,
    COUNT(DISTINCT CASE WHEN al.severity = 'critical' THEN al.id END) as critical_alerts,
    COUNT(DISTINCT CASE WHEN al.severity = 'high' THEN al.id END) as high_alerts
FROM agents a
LEFT JOIN events e ON a.id = e.agent_id
LEFT JOIN alerts al ON a.id = al.agent_id
GROUP BY a.id, a.hostname, a.ip_address, a.os, a.status, a.last_seen;

CREATE OR REPLACE VIEW v_alert_summary AS
SELECT 
    a.id,
    a.title,
    a.severity,
    a.status,
    a.rule_name,
    a.agent_id,
    ag.hostname as agent_hostname,
    a.created_at,
    COUNT(ae.event_id) as event_count
FROM alerts a
LEFT JOIN agents ag ON a.agent_id = ag.id
LEFT JOIN alert_events ae ON a.id = ae.alert_id
GROUP BY a.id, a.title, a.severity, a.status, a.rule_name, a.agent_id, ag.hostname, a.created_at;

CREATE OR REPLACE VIEW v_event_summary AS
SELECT 
    e.id,
    e.event_type,
    e.agent_id,
    a.hostname as agent_hostname,
    e.process_name,
    e.command_line,
    e.user_name,
    e.severity,
    e.timestamp,
    e.created_at
FROM events e
LEFT JOIN agents a ON e.agent_id = a.id;

-- Create functions for common operations
CREATE OR REPLACE FUNCTION get_agent_events_count(agent_uuid text, days integer DEFAULT 7)
RETURNS integer AS $$
BEGIN
    RETURN (
        SELECT COUNT(*)
        FROM events
        WHERE agent_id = agent_uuid
        AND created_at >= NOW() - INTERVAL '1 day' * days
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_agent_alerts_count(agent_uuid text, days integer DEFAULT 7)
RETURNS integer AS $$
BEGIN
    RETURN (
        SELECT COUNT(*)
        FROM alerts
        WHERE agent_id = agent_uuid
        AND created_at >= NOW() - INTERVAL '1 day' * days
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_top_processes_by_agent(agent_uuid text, limit_count integer DEFAULT 10)
RETURNS TABLE(process_name text, event_count bigint) AS $$
BEGIN
    RETURN QUERY
    SELECT e.process_name, COUNT(*)::bigint as event_count
    FROM events e
    WHERE e.agent_id = agent_uuid
    AND e.process_name IS NOT NULL
    GROUP BY e.process_name
    ORDER BY event_count DESC
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql;

-- Create sample data
INSERT INTO agents (id, hostname, ip_address, os, os_version, agent_version, status, last_seen, created_at, updated_at)
VALUES 
    ('sample-agent-001', 'DESKTOP-WIN10-01', '192.168.1.100', 'Windows', '10.0.19041', '1.0.0', 'active', NOW(), NOW(), NOW()),
    ('sample-agent-002', 'UBUNTU-SRV-01', '192.168.1.101', 'Linux', 'Ubuntu 20.04', '1.0.0', 'active', NOW(), NOW(), NOW()),
    ('sample-agent-003', 'DESKTOP-WIN11-01', '192.168.1.102', 'Windows', '11.0.22000', '1.0.0', 'inactive', NOW() - INTERVAL '2 hours', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Insert sample Sigma rules
INSERT INTO sigma_rules (id, title, description, author, level, status, filename, enabled, created_at, updated_at)
VALUES 
    ('rule-001', 'Suspicious PowerShell Activity', 'Detects suspicious PowerShell command execution', 'EDR Security Team', 'high', 'stable', 'powershell_suspicious.yml', true, NOW(), NOW()),
    ('rule-002', 'Mimikatz Credential Dumping Detection', 'Detects Mimikatz credential dumping tool execution', 'EDR Security Team', 'critical', 'stable', 'mimikatz_detection.yml', true, NOW(), NOW()),
    ('rule-003', 'Lateral Movement via PsExec', 'Detects lateral movement using PsExec or similar tools', 'EDR Security Team', 'high', 'stable', 'lateral_movement_psexec.yml', true, NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Insert sample events
INSERT INTO events (id, agent_id, event_type, event_data, process_id, process_name, command_line, user_name, severity, timestamp, created_at)
VALUES 
    (uuid_generate_v4(), 'sample-agent-001', 'process', '{"EventID": 4688}', '1234', 'powershell.exe', 'powershell.exe -ExecutionPolicy Bypass -File C:\temp\script.ps1', 'SYSTEM', 3, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour'),
    (uuid_generate_v4(), 'sample-agent-001', 'network', '{"EventID": 5156}', '5678', 'chrome.exe', 'chrome.exe --no-sandbox', 'user1', 1, NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes'),
    (uuid_generate_v4(), 'sample-agent-002', 'logon', '{"EventID": 4624}', '9012', 'sshd', '/usr/sbin/sshd -D', 'admin', 2, NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '15 minutes')
ON CONFLICT (id) DO NOTHING;

-- Insert sample alerts
INSERT INTO alerts (id, title, description, severity, status, rule_id, rule_name, agent_id, tags, mitre, created_at, updated_at)
VALUES 
    (uuid_generate_v4(), 'Suspicious PowerShell Execution Detected', 'PowerShell executed with bypass execution policy', 'high', 'open', 'rule-001', 'Suspicious PowerShell Activity', 'sample-agent-001', ARRAY['powershell', 'execution'], ARRAY['T1059.001'], NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour'),
    (uuid_generate_v4(), 'Multiple Failed Login Attempts', 'Multiple failed SSH login attempts detected', 'medium', 'investigating', 'rule-004', 'Brute Force Detection', 'sample-agent-002', ARRAY['authentication', 'brute_force'], ARRAY['T1110'], NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes')
ON CONFLICT (id) DO NOTHING;

-- Create triggers for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add triggers to tables that have updated_at column
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name 
        FROM information_schema.columns 
        WHERE column_name = 'updated_at' 
        AND table_schema = 'public'
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trigger_update_%s_updated_at ON %s', t, t);
        EXECUTE format('CREATE TRIGGER trigger_update_%s_updated_at
                       BEFORE UPDATE ON %s
                       FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()', t, t);
    END LOOP;
END;
$$;

-- Create materialized views for analytics
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_event_stats AS
SELECT 
    DATE(created_at) as event_date,
    agent_id,
    event_type,
    COUNT(*) as event_count,
    AVG(severity) as avg_severity
FROM events
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at), agent_id, event_type;

CREATE UNIQUE INDEX ON mv_daily_event_stats (event_date, agent_id, event_type);

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_alert_trends AS
SELECT 
    DATE(created_at) as alert_date,
    severity,
    status,
    COUNT(*) as alert_count
FROM alerts
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at), severity, status;

CREATE UNIQUE INDEX ON mv_alert_trends (alert_date, severity, status);

-- Create refresh function for materialized views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_event_stats;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_alert_trends;
END;
$$ LANGUAGE plpgsql;

-- Set up automatic refresh of materialized views (requires pg_cron extension)
-- SELECT cron.schedule('refresh-analytics', '0 2 * * *', 'SELECT refresh_analytics_views();');

-- Grant permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO edr_user;
GRANT INSERT, UPDATE, DELETE ON events, alerts, agents, processes, process_trees, detections TO edr_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO edr_user;

-- Create database maintenance procedures
CREATE OR REPLACE FUNCTION cleanup_old_events(days_to_keep integer DEFAULT 90)
RETURNS integer AS $$
DECLARE
    deleted_count integer;
BEGIN
    DELETE FROM events 
    WHERE created_at < NOW() - INTERVAL '1 day' * days_to_keep;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION cleanup_old_detections(days_to_keep integer DEFAULT 90)
RETURNS integer AS $$
DECLARE
    deleted_count integer;
BEGIN
    DELETE FROM detections 
    WHERE created_at < NOW() - INTERVAL '1 day' * days_to_keep;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Optimize database
ANALYZE;
