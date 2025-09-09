-- ===============================================
-- EDR SYSTEM - OPTIMIZED DATABASE SCHEMA
-- Comprehensive schema for enterprise EDR system
-- ===============================================

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- ===============================================
-- OPTIMIZED CORE TABLES
-- ===============================================

-- Optimized Agents table with comprehensive endpoint information
CREATE TABLE IF NOT EXISTS optimized_agents (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR NOT NULL,
    ip_address VARCHAR,
    mac_address VARCHAR,
    os VARCHAR,
    os_version VARCHAR,
    os_build VARCHAR,
    architecture VARCHAR,
    agent_version VARCHAR,
    status VARCHAR DEFAULT 'active',
    last_seen TIMESTAMP WITH TIME ZONE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Geographic and Network Info
    location VARCHAR,
    timezone VARCHAR,
    domain VARCHAR,
    workgroup VARCHAR,
    
    -- Hardware Info
    cpu VARCHAR,
    memory_mb BIGINT,
    disk_space_gb BIGINT,
    
    -- Security Context
    antivirus_product VARCHAR,
    firewall_status VARCHAR,
    compliance_status VARCHAR,
    risk_score INTEGER DEFAULT 0,
    
    -- Metadata
    tags TEXT[],
    environment VARCHAR,
    owner VARCHAR,
    department VARCHAR,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Optimized Events table with normalized fields
CREATE TABLE IF NOT EXISTS optimized_events (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    event_type VARCHAR,
    event_category VARCHAR,
    
    -- Process Information
    process_id VARCHAR,
    process_name VARCHAR,
    process_path VARCHAR,
    command_line TEXT,
    parent_process_id VARCHAR,
    parent_process_name VARCHAR,
    user_name VARCHAR,
    user_domain VARCHAR,
    
    -- File Information
    file_name VARCHAR,
    file_path VARCHAR,
    file_hash VARCHAR,
    file_size BIGINT,
    
    -- Network Information
    source_ip VARCHAR,
    source_port INTEGER,
    destination_ip VARCHAR,
    destination_port INTEGER,
    protocol VARCHAR,
    
    -- Additional Metadata
    raw_data JSONB,
    
    -- Classification
    severity INTEGER DEFAULT 1,
    threat_level VARCHAR,
    is_alerted BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
) PARTITION BY RANGE (created_at);

-- Optimized Alerts table with enhanced metadata
CREATE TABLE IF NOT EXISTS optimized_alerts (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR NOT NULL,
    description TEXT,
    severity VARCHAR,
    threat_level VARCHAR,
    status VARCHAR DEFAULT 'open',
    
    -- Rule Information
    rule_id VARCHAR,
    rule_name VARCHAR,
    rule_type VARCHAR,
    
    -- Agent and Event Info
    agent_id VARCHAR NOT NULL,
    event_count INTEGER DEFAULT 1,
    
    -- Classification
    tags TEXT[],
    mitre TEXT[],
    tactics TEXT[],
    techniques TEXT[],
    
    -- Investigation
    assigned_to VARCHAR,
    investigation TEXT,
    resolution TEXT,
    false_positive BOOLEAN DEFAULT FALSE,
    
    -- Confidence and Risk
    confidence_score DECIMAL(3,2),
    risk_score INTEGER,
    
    -- Timestamps
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
) PARTITION BY RANGE (created_at);

-- ===============================================
-- SPECIALIZED EDR TABLES
-- ===============================================

-- Network Connections tracking
CREATE TABLE IF NOT EXISTS network_connections (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    event_id VARCHAR,
    process_id VARCHAR,
    process_name VARCHAR,
    protocol VARCHAR,
    source_ip VARCHAR,
    source_port INTEGER,
    destination_ip VARCHAR,
    destination_port INTEGER,
    direction VARCHAR,
    status VARCHAR,
    bytes_sent BIGINT,
    bytes_received BIGINT,
    duration_seconds INTEGER,
    destination_country VARCHAR,
    is_malicious BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
);

-- File Operations tracking
CREATE TABLE IF NOT EXISTS file_operations (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    event_id VARCHAR,
    process_id VARCHAR,
    process_name VARCHAR,
    operation VARCHAR,
    file_path VARCHAR,
    file_name VARCHAR,
    file_size BIGINT,
    file_hash VARCHAR,
    file_type VARCHAR,
    permissions VARCHAR,
    owner VARCHAR,
    is_suspicious BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
);

-- Registry Operations (Windows specific)
CREATE TABLE IF NOT EXISTS registry_operations (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    event_id VARCHAR,
    process_id VARCHAR,
    process_name VARCHAR,
    operation VARCHAR,
    key_path VARCHAR,
    value_name VARCHAR,
    value_type VARCHAR,
    value_data TEXT,
    old_value TEXT,
    is_persistence BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
);

-- User Activities tracking
CREATE TABLE IF NOT EXISTS user_activities (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    event_id VARCHAR,
    activity_type VARCHAR,
    username VARCHAR,
    domain VARCHAR,
    source_ip VARCHAR,
    logon_type INTEGER,
    auth_method VARCHAR,
    session_id VARCHAR,
    failure_reason VARCHAR,
    is_privileged BOOLEAN DEFAULT FALSE,
    is_successful BOOLEAN,
    risk_score INTEGER DEFAULT 0,
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
);

-- Threat Intelligence IOCs
CREATE TABLE IF NOT EXISTS threat_intelligences (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_type VARCHAR,
    ioc_value VARCHAR UNIQUE,
    threat_type VARCHAR,
    severity VARCHAR,
    source VARCHAR,
    description TEXT,
    references TEXT[],
    ttps TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IOC Matches tracking
CREATE TABLE IF NOT EXISTS ioc_matches (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    threat_intelligence_id VARCHAR NOT NULL,
    event_id VARCHAR,
    match_type VARCHAR,
    match_context VARCHAR,
    confidence_score DECIMAL(3,2),
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id),
    FOREIGN KEY (threat_intelligence_id) REFERENCES threat_intelligences(id)
);

-- Configuration Changes tracking
CREATE TABLE IF NOT EXISTS configuration_changes (
    id VARCHAR PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR NOT NULL,
    change_type VARCHAR,
    component VARCHAR,
    action VARCHAR,
    old_value TEXT,
    new_value TEXT,
    changed_by VARCHAR,
    source VARCHAR,
    is_critical BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    FOREIGN KEY (agent_id) REFERENCES optimized_agents(id)
);

-- ===============================================
-- PARTITIONS FOR LARGE TABLES
-- ===============================================

-- Events partitions (daily partitions for high volume)
CREATE TABLE IF NOT EXISTS optimized_events_y2025m09 PARTITION OF optimized_events 
FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');

CREATE TABLE IF NOT EXISTS optimized_events_y2025m10 PARTITION OF optimized_events 
FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE TABLE IF NOT EXISTS optimized_events_y2025m11 PARTITION OF optimized_events 
FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

-- Alerts partitions (monthly partitions)
CREATE TABLE IF NOT EXISTS optimized_alerts_y2025m09 PARTITION OF optimized_alerts 
FOR VALUES FROM ('2025-09-01') TO ('2025-10-01');

CREATE TABLE IF NOT EXISTS optimized_alerts_y2025m10 PARTITION OF optimized_alerts 
FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE TABLE IF NOT EXISTS optimized_alerts_y2025m11 PARTITION OF optimized_alerts 
FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

-- ===============================================
-- OPTIMIZED INDEXES FOR EDR PERFORMANCE
-- ===============================================

-- Agent indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_agents_status_last_seen ON optimized_agents(status, last_seen DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_agents_hostname_status ON optimized_agents(hostname, status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_agents_ip_gin ON optimized_agents USING GIN (ip_address gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_agents_environment ON optimized_agents(environment, status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_agents_risk_score ON optimized_agents(risk_score DESC) WHERE risk_score > 50;

-- Event indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_agent_time ON optimized_events(agent_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_category_severity ON optimized_events(event_category, severity DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_threat_level ON optimized_events(threat_level) WHERE threat_level IN ('high', 'critical');
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_process_gin ON optimized_events USING GIN (process_name gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_file_hash ON optimized_events(file_hash) WHERE file_hash IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_network ON optimized_events(source_ip, destination_ip) WHERE source_ip IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_events_alerted ON optimized_events(is_alerted, created_at DESC) WHERE is_alerted = true;

-- Alert indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_alerts_agent_severity ON optimized_alerts(agent_id, severity, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_alerts_status_open ON optimized_alerts(status, created_at DESC) WHERE status != 'resolved';
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_alerts_threat_level ON optimized_alerts(threat_level, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_alerts_assigned ON optimized_alerts(assigned_to, status) WHERE assigned_to IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_alerts_mitre_gin ON optimized_alerts USING GIN (mitre);

-- Network connection indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_agent_time ON network_connections(agent_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_destination ON network_connections(destination_ip, destination_port);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_malicious ON network_connections(is_malicious, timestamp DESC) WHERE is_malicious = true;

-- File operation indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_agent_time ON file_operations(agent_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_hash ON file_operations(file_hash) WHERE file_hash IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_suspicious ON file_operations(is_suspicious, timestamp DESC) WHERE is_suspicious = true;

-- User activity indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_agent_time ON user_activities(agent_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_failed_login ON user_activities(is_successful, timestamp DESC) WHERE is_successful = false;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_privileged ON user_activities(is_privileged, timestamp DESC) WHERE is_privileged = true;

-- Threat intelligence indexes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_ioc_value ON threat_intelligences(ioc_value);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_type_active ON threat_intelligences(ioc_type, is_active) WHERE is_active = true;

-- IOC match indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_matches_agent_time ON ioc_matches(agent_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_matches_confidence ON ioc_matches(confidence_score DESC) WHERE confidence_score > 0.8;

-- ===============================================
-- MATERIALIZED VIEWS FOR PERFORMANCE
-- ===============================================

-- Agent Dashboard View
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_agent_dashboard AS
SELECT 
    a.id,
    a.hostname,
    a.ip_address,
    a.os,
    a.status,
    a.last_seen,
    a.risk_score,
    a.environment,
    COUNT(DISTINCT e.id) as total_events_30d,
    COUNT(DISTINCT al.id) as total_alerts_30d,
    COUNT(DISTINCT CASE WHEN al.severity = 'critical' THEN al.id END) as critical_alerts,
    COUNT(DISTINCT CASE WHEN al.severity = 'high' THEN al.id END) as high_alerts,
    COUNT(DISTINCT CASE WHEN al.status = 'open' THEN al.id END) as open_alerts,
    MAX(e.timestamp) as last_event_time,
    MAX(al.created_at) as last_alert_time
FROM optimized_agents a
LEFT JOIN optimized_events e ON a.id = e.agent_id 
    AND e.created_at >= NOW() - INTERVAL '30 days'
LEFT JOIN optimized_alerts al ON a.id = al.agent_id 
    AND al.created_at >= NOW() - INTERVAL '30 days'
GROUP BY a.id, a.hostname, a.ip_address, a.os, a.status, a.last_seen, a.risk_score, a.environment;

-- Create unique index for materialized view refresh
CREATE UNIQUE INDEX ON mv_agent_dashboard (id);

-- Threat Intelligence Summary View
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_threat_summary AS
SELECT 
    ti.ioc_type,
    ti.threat_type,
    ti.severity,
    COUNT(*) as ioc_count,
    COUNT(DISTINCT im.agent_id) as affected_agents_7d,
    MAX(im.timestamp) as last_match,
    AVG(im.confidence_score) as avg_confidence
FROM threat_intelligences ti
LEFT JOIN ioc_matches im ON ti.id = im.threat_intelligence_id 
    AND im.created_at >= NOW() - INTERVAL '7 days'
WHERE ti.is_active = true
GROUP BY ti.ioc_type, ti.threat_type, ti.severity;

-- Security Metrics View
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_security_metrics AS
SELECT 
    DATE_TRUNC('hour', created_at) as hour,
    COUNT(*) as total_events,
    COUNT(CASE WHEN severity >= 7 THEN 1 END) as high_severity_events,
    COUNT(CASE WHEN threat_level = 'critical' THEN 1 END) as critical_events,
    COUNT(DISTINCT agent_id) as active_agents,
    AVG(CASE 
        WHEN threat_level = 'critical' THEN 4 
        WHEN threat_level = 'high' THEN 3 
        WHEN threat_level = 'medium' THEN 2 
        ELSE 1 END) as avg_threat_score
FROM optimized_events 
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', created_at)
ORDER BY hour DESC;

-- ===============================================
-- FUNCTIONS AND PROCEDURES
-- ===============================================

-- Function to refresh all materialized views
CREATE OR REPLACE FUNCTION refresh_edr_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_agent_dashboard;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_summary;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_security_metrics;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old partitions
CREATE OR REPLACE FUNCTION cleanup_old_partitions()
RETURNS void AS $$
DECLARE
    partition_name text;
BEGIN
    -- Drop partitions older than 90 days
    FOR partition_name IN 
        SELECT schemaname||'.'||tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'optimized_events_y%' 
        AND tablename < 'optimized_events_y' || to_char(NOW() - INTERVAL '90 days', 'YYYYMM')
    LOOP
        EXECUTE 'DROP TABLE IF EXISTS ' || partition_name;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Function to create new partitions automatically
CREATE OR REPLACE FUNCTION create_monthly_partitions()
RETURNS void AS $$
DECLARE
    start_date date;
    end_date date;
    partition_name text;
BEGIN
    -- Create partitions for next 3 months
    FOR i IN 0..2 LOOP
        start_date := date_trunc('month', NOW() + (i || ' months')::interval);
        end_date := start_date + interval '1 month';
        
        -- Events partition
        partition_name := 'optimized_events_y' || to_char(start_date, 'YYYYMM');
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF optimized_events FOR VALUES FROM (%L) TO (%L)',
                      partition_name, start_date, end_date);
        
        -- Alerts partition
        partition_name := 'optimized_alerts_y' || to_char(start_date, 'YYYYMM');
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF optimized_alerts FOR VALUES FROM (%L) TO (%L)',
                      partition_name, start_date, end_date);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ===============================================
-- INITIAL DATA AND TRIGGERS
-- ===============================================

-- Create trigger for updated_at timestamp
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply triggers to tables with updated_at
CREATE TRIGGER set_timestamp_optimized_agents
    BEFORE UPDATE ON optimized_agents
    FOR EACH ROW
    EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_optimized_alerts
    BEFORE UPDATE ON optimized_alerts
    FOR EACH ROW
    EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_threat_intelligences
    BEFORE UPDATE ON threat_intelligences
    FOR EACH ROW
    EXECUTE PROCEDURE trigger_set_timestamp();

-- ===============================================
-- SAMPLE THREAT INTELLIGENCE DATA
-- ===============================================

INSERT INTO threat_intelligences (ioc_type, ioc_value, threat_type, severity, source, description, ttps) 
VALUES 
    ('ip', '192.168.1.100', 'c2', 'high', 'internal_detection', 'Suspicious C2 communication', ARRAY['T1071.001']),
    ('hash', 'e3b0c44298fc1c149afbf4c8996fb924', 'malware', 'critical', 'virustotal', 'Known malware hash', ARRAY['T1055', 'T1059']),
    ('domain', 'malicious.com', 'phishing', 'medium', 'threat_feed', 'Phishing domain', ARRAY['T1566'])
ON CONFLICT (ioc_value) DO NOTHING;

-- ===============================================
-- PERFORMANCE TUNING SETTINGS
-- ===============================================

-- PostgreSQL performance settings (apply via postgresql.conf)
-- shared_buffers = 256MB
-- effective_cache_size = 1GB  
-- maintenance_work_mem = 64MB
-- checkpoint_completion_target = 0.9
-- wal_buffers = 16MB
-- default_statistics_target = 100
-- random_page_cost = 1.1
-- effective_io_concurrency = 200
-- work_mem = 4MB

-- Enable query plan caching
-- plan_cache_mode = auto

-- ===============================================
-- MAINTENANCE SCHEDULED TASKS
-- ===============================================

-- Schedule materialized view refresh (run every 5 minutes)
-- SELECT cron.schedule('refresh-edr-views', '*/5 * * * *', 'SELECT refresh_edr_views();');

-- Schedule partition maintenance (run daily)
-- SELECT cron.schedule('partition-maintenance', '0 2 * * *', 'SELECT create_monthly_partitions(); SELECT cleanup_old_partitions();');

-- ===============================================
-- COMPLETION MESSAGE
-- ===============================================

SELECT 'EDR Optimized Database Schema Created Successfully!' as status;
