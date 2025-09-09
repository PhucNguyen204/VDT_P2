package database

import (
	"fmt"
	"time"

	"edr-server/internal/config"
	"edr-server/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OptimizedDBConfig holds optimized database configuration
type OptimizedDBConfig struct {
	MaxIdleConns       int
	MaxOpenConns       int
	ConnMaxLifetime    time.Duration
	ConnMaxIdleTime    time.Duration
	LogLevel           logger.LogLevel
	SlowThreshold      time.Duration
	EnablePartitioning bool
	EnableReadReplicas bool
}

// DefaultOptimizedConfig returns default optimized configuration for EDR system
func DefaultOptimizedConfig() OptimizedDBConfig {
	return OptimizedDBConfig{
		MaxIdleConns:       25,            // Tăng từ 10
		MaxOpenConns:       200,           // Tăng từ 100 cho high-throughput EDR
		ConnMaxLifetime:    2 * time.Hour, // Giảm từ 1 hour
		ConnMaxIdleTime:    15 * time.Minute,
		LogLevel:           logger.Warn, // Giảm logging để tăng performance
		SlowThreshold:      200 * time.Millisecond,
		EnablePartitioning: true,
		EnableReadReplicas: false, // Có thể enable sau
	}
}

// InitOptimizedDB khởi tạo database với configuration tối ưu cho EDR
func InitOptimizedDB(cfg config.DatabaseConfig, optimizedCfg OptimizedDBConfig) (*gorm.DB, error) {
	// Build DSN với các tối ưu PostgreSQL
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=Asia/Ho_Chi_Minh "+
			"application_name=edr-server "+
			"connect_timeout=10 "+
			"statement_timeout=30000 "+
			"lock_timeout=5000",
		cfg.Host, cfg.Username, cfg.Password, cfg.Database, cfg.Port, cfg.SSLMode,
	)

	// GORM configuration với optimizations
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(optimizedCfg.LogLevel),
		NowFunc: func() time.Time {
			return time.Now().UTC() // Force UTC for consistency
		},
		PrepareStmt:                              true,  // Enable prepared statements
		DisableForeignKeyConstraintWhenMigrating: false, // Keep constraints for data integrity
		SkipDefaultTransaction:                   true,  // Disable auto-transactions for better performance
	}

	// Custom slow query logger
	if optimizedCfg.SlowThreshold > 0 {
		gormConfig.Logger = logger.Default.LogMode(optimizedCfg.LogLevel)
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("không thể kết nối database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Optimized connection pool configuration
	sqlDB.SetMaxIdleConns(optimizedCfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(optimizedCfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(optimizedCfg.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(optimizedCfg.ConnMaxIdleTime)

	// PostgreSQL-specific optimizations
	if err := applyPostgreSQLOptimizations(db); err != nil {
		return nil, fmt.Errorf("failed to apply PostgreSQL optimizations: %w", err)
	}

	// Auto migrate với optimized models
	if err := migrateOptimizedSchemas(db); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Create optimized indexes
	if err := createOptimizedIndexes(db); err != nil {
		return nil, fmt.Errorf("index creation failed: %w", err)
	}

	// Setup partitioning for large tables
	if optimizedCfg.EnablePartitioning {
		if err := setupPartitioning(db); err != nil {
			return nil, fmt.Errorf("partitioning setup failed: %w", err)
		}
	}

	return db, nil
}

// applyPostgreSQLOptimizations applies PostgreSQL-specific optimizations
func applyPostgreSQLOptimizations(db *gorm.DB) error {
	optimizations := []string{
		// Enable extensions
		"CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"",
		"CREATE EXTENSION IF NOT EXISTS \"pg_trgm\"",
		"CREATE EXTENSION IF NOT EXISTS \"btree_gin\"",
		"CREATE EXTENSION IF NOT EXISTS \"pg_stat_statements\"",

		// Connection optimizations
		"SET shared_preload_libraries = 'pg_stat_statements'",
		"SET max_connections = 200",
		"SET shared_buffers = '256MB'",
		"SET effective_cache_size = '1GB'",
		"SET maintenance_work_mem = '64MB'",
		"SET checkpoint_completion_target = 0.9",
		"SET wal_buffers = '16MB'",
		"SET default_statistics_target = 100",
		"SET random_page_cost = 1.1",
		"SET effective_io_concurrency = 200",

		// Query optimization
		"SET work_mem = '4MB'",
		"SET enable_partitionwise_join = on",
		"SET enable_partitionwise_aggregate = on",
		"SET jit = on",
	}

	for _, sql := range optimizations {
		if err := db.Exec(sql).Error; err != nil {
			// Log warning but continue (some settings may not be available)
			fmt.Printf("Warning: Failed to apply optimization '%s': %v\n", sql, err)
		}
	}

	return nil
}

// migrateOptimizedSchemas migrates all optimized models
func migrateOptimizedSchemas(db *gorm.DB) error {
	// Migrate optimized models
	optimizedModels := []interface{}{
		&models.OptimizedAgent{},
		&models.OptimizedEvent{},
		&models.OptimizedAlert{},
		&models.NetworkConnection{},
		&models.FileOperation{},
		&models.RegistryOperation{},
		&models.UserActivity{},
		&models.ThreatIntelligence{},
		&models.IOCMatch{},
		&models.ConfigurationChange{},

		// Keep existing models for backward compatibility
		&models.Agent{},
		&models.Event{},
		&models.Alert{},
		&models.Process{},
		&models.ProcessTree{},
		&models.SigmaRule{},
		&models.Detection{},
	}

	// Enable auto-migration in transaction for consistency
	return db.Transaction(func(tx *gorm.DB) error {
		for _, model := range optimizedModels {
			if err := tx.AutoMigrate(model); err != nil {
				return fmt.Errorf("failed to migrate %T: %w", model, err)
			}
		}
		return nil
	})
}

// createOptimizedIndexes creates performance-optimized indexes
func createOptimizedIndexes(db *gorm.DB) error {
	indexes := []string{
		// ========== OPTIMIZED AGENT INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_agents_status_last_seen ON optimized_agents(status, last_seen DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_agents_hostname_status ON optimized_agents(hostname, status)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_agents_ip_address ON optimized_agents USING GIN (ip_address gin_trgm_ops)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_agents_environment_status ON optimized_agents(environment, status)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_agents_risk_score ON optimized_agents(risk_score DESC) WHERE risk_score > 50",

		// ========== OPTIMIZED EVENT INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_agent_timestamp ON optimized_events(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_category_severity ON optimized_events(event_category, severity DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_threat_level ON optimized_events(threat_level) WHERE threat_level IN ('high', 'critical')",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_process_name ON optimized_events USING GIN (process_name gin_trgm_ops)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_file_hash ON optimized_events(file_hash) WHERE file_hash IS NOT NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_network_ips ON optimized_events(source_ip, destination_ip) WHERE source_ip IS NOT NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_events_alerted ON optimized_events(is_alerted, timestamp DESC) WHERE is_alerted = true",

		// ========== OPTIMIZED ALERT INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_agent_severity ON optimized_alerts(agent_id, severity, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_status_severity ON optimized_alerts(status, severity) WHERE status != 'resolved'",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_threat_level ON optimized_alerts(threat_level, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_assigned ON optimized_alerts(assigned_to, status) WHERE assigned_to IS NOT NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_false_positive ON optimized_alerts(false_positive, created_at DESC) WHERE false_positive = false",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_mitre_gin ON optimized_alerts USING GIN (mitre)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_optimized_alerts_tactics_gin ON optimized_alerts USING GIN (tactics)",

		// ========== NETWORK CONNECTION INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_connections_agent_timestamp ON network_connections(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_connections_destination ON network_connections(destination_ip, destination_port)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_connections_malicious ON network_connections(is_malicious, timestamp DESC) WHERE is_malicious = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_network_connections_protocol_port ON network_connections(protocol, destination_port)",

		// ========== FILE OPERATION INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_operations_agent_timestamp ON file_operations(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_operations_hash ON file_operations(file_hash) WHERE file_hash IS NOT NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_operations_suspicious ON file_operations(is_suspicious, timestamp DESC) WHERE is_suspicious = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_operations_path_gin ON file_operations USING GIN (file_path gin_trgm_ops)",

		// ========== REGISTRY OPERATION INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_registry_operations_agent_timestamp ON registry_operations(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_registry_operations_persistence ON registry_operations(is_persistence, timestamp DESC) WHERE is_persistence = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_registry_operations_key_gin ON registry_operations USING GIN (key_path gin_trgm_ops)",

		// ========== USER ACTIVITY INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_agent_timestamp ON user_activities(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_username_type ON user_activities(username, activity_type)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_failed_logins ON user_activities(is_successful, timestamp DESC) WHERE is_successful = false",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_privileged ON user_activities(is_privileged, timestamp DESC) WHERE is_privileged = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_activities_source_ip ON user_activities(source_ip) WHERE source_ip IS NOT NULL",

		// ========== THREAT INTELLIGENCE INDEXES ==========
		"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_ioc_value ON threat_intelligences(ioc_value)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_type_active ON threat_intelligences(ioc_type, is_active) WHERE is_active = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_severity ON threat_intelligences(severity, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intelligence_ttps_gin ON threat_intelligences USING GIN (ttps)",

		// ========== IOC MATCH INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_matches_agent_timestamp ON ioc_matches(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_matches_threat_intel ON ioc_matches(threat_intelligence_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_matches_confidence ON ioc_matches(confidence_score DESC) WHERE confidence_score > 0.8",

		// ========== CONFIGURATION CHANGE INDEXES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_config_changes_agent_timestamp ON configuration_changes(agent_id, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_config_changes_critical ON configuration_changes(is_critical, timestamp DESC) WHERE is_critical = true",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_config_changes_type ON configuration_changes(change_type, timestamp DESC)",

		// ========== COMPOUND INDEXES FOR COMMON QUERIES ==========
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_agent_category_time ON events(agent_id, event_type, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_agent_status_time ON alerts(agent_id, status, created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_processes_agent_parent ON processes(agent_id, parent_pid, start_time DESC)",
	}

	for _, indexSQL := range indexes {
		if err := db.Exec(indexSQL).Error; err != nil {
			// Log warning but continue (index might already exist)
			fmt.Printf("Warning: Failed to create index: %s - Error: %v\n", indexSQL, err)
		}
	}

	return nil
}

// setupPartitioning creates table partitions for large tables
func setupPartitioning(db *gorm.DB) error {
	partitioningSQL := []string{
		// Partition events table by date (daily partitions)
		`CREATE TABLE IF NOT EXISTS optimized_events_y2025m09 PARTITION OF optimized_events 
		 FOR VALUES FROM ('2025-09-01') TO ('2025-10-01')`,

		`CREATE TABLE IF NOT EXISTS optimized_events_y2025m10 PARTITION OF optimized_events 
		 FOR VALUES FROM ('2025-10-01') TO ('2025-11-01')`,

		// Partition alerts table by date (monthly partitions)
		`CREATE TABLE IF NOT EXISTS optimized_alerts_y2025m09 PARTITION OF optimized_alerts 
		 FOR VALUES FROM ('2025-09-01') TO ('2025-10-01')`,

		`CREATE TABLE IF NOT EXISTS optimized_alerts_y2025m10 PARTITION OF optimized_alerts 
		 FOR VALUES FROM ('2025-10-01') TO ('2025-11-01')`,
	}

	for _, sql := range partitioningSQL {
		if err := db.Exec(sql).Error; err != nil {
			fmt.Printf("Warning: Partitioning SQL failed: %s - Error: %v\n", sql, err)
		}
	}

	return nil
}

// CreateOptimizedViews creates materialized views for common aggregations
func CreateOptimizedViews(db *gorm.DB) error {
	views := []string{
		// Agent dashboard view
		`CREATE MATERIALIZED VIEW IF NOT EXISTS mv_agent_dashboard AS
		SELECT 
			a.id,
			a.hostname,
			a.ip_address,
			a.os,
			a.status,
			a.last_seen,
			a.risk_score,
			COUNT(DISTINCT e.id) as total_events,
			COUNT(DISTINCT al.id) as total_alerts,
			COUNT(DISTINCT CASE WHEN al.severity = 'critical' THEN al.id END) as critical_alerts,
			COUNT(DISTINCT CASE WHEN al.severity = 'high' THEN al.id END) as high_alerts,
			COUNT(DISTINCT CASE WHEN al.status = 'open' THEN al.id END) as open_alerts,
			MAX(e.timestamp) as last_event_time,
			MAX(al.created_at) as last_alert_time
		FROM optimized_agents a
		LEFT JOIN optimized_events e ON a.id = e.agent_id AND e.created_at >= NOW() - INTERVAL '30 days'
		LEFT JOIN optimized_alerts al ON a.id = al.agent_id AND al.created_at >= NOW() - INTERVAL '30 days'
		GROUP BY a.id, a.hostname, a.ip_address, a.os, a.status, a.last_seen, a.risk_score`,

		// Threat intelligence summary
		`CREATE MATERIALIZED VIEW IF NOT EXISTS mv_threat_summary AS
		SELECT 
			ti.ioc_type,
			ti.threat_type,
			ti.severity,
			COUNT(*) as ioc_count,
			COUNT(DISTINCT im.agent_id) as affected_agents,
			MAX(im.timestamp) as last_match,
			AVG(im.confidence_score) as avg_confidence
		FROM threat_intelligences ti
		LEFT JOIN ioc_matches im ON ti.id = im.threat_intelligence_id AND im.created_at >= NOW() - INTERVAL '7 days'
		WHERE ti.is_active = true
		GROUP BY ti.ioc_type, ti.threat_type, ti.severity`,

		// Security metrics view
		`CREATE MATERIALIZED VIEW IF NOT EXISTS mv_security_metrics AS
		SELECT 
			DATE_TRUNC('hour', created_at) as hour,
			COUNT(*) as total_events,
			COUNT(CASE WHEN severity >= 7 THEN 1 END) as high_severity_events,
			COUNT(DISTINCT agent_id) as active_agents,
			AVG(CASE WHEN threat_level = 'high' THEN 1 WHEN threat_level = 'critical' THEN 2 ELSE 0 END) as threat_score
		FROM optimized_events 
		WHERE created_at >= NOW() - INTERVAL '24 hours'
		GROUP BY DATE_TRUNC('hour', created_at)
		ORDER BY hour DESC`,
	}

	for _, viewSQL := range views {
		if err := db.Exec(viewSQL).Error; err != nil {
			fmt.Printf("Warning: Failed to create view: %v\n", err)
		}
	}

	// Create refresh function for materialized views
	refreshFunction := `
	CREATE OR REPLACE FUNCTION refresh_edr_views()
	RETURNS void AS $$
	BEGIN
		REFRESH MATERIALIZED VIEW CONCURRENTLY mv_agent_dashboard;
		REFRESH MATERIALIZED VIEW CONCURRENTLY mv_threat_summary;
		REFRESH MATERIALIZED VIEW CONCURRENTLY mv_security_metrics;
	END;
	$$ LANGUAGE plpgsql;`

	if err := db.Exec(refreshFunction).Error; err != nil {
		fmt.Printf("Warning: Failed to create refresh function: %v\n", err)
	}

	return nil
}

// OptimizedRepository extends Repository with optimized methods
type OptimizedRepository struct {
	*Repository
	db *gorm.DB
}

// NewOptimizedRepository creates optimized repository
func NewOptimizedRepository(db *gorm.DB) *OptimizedRepository {
	return &OptimizedRepository{
		Repository: NewRepository(db),
		db:         db,
	}
}

// GetAgentDashboard returns optimized agent dashboard data
func (r *OptimizedRepository) GetAgentDashboard() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := r.db.Table("mv_agent_dashboard").Find(&results).Error
	return results, err
}

// GetThreatSummary returns threat intelligence summary
func (r *OptimizedRepository) GetThreatSummary() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := r.db.Table("mv_threat_summary").Find(&results).Error
	return results, err
}

// GetSecurityMetrics returns security metrics for the last 24 hours
func (r *OptimizedRepository) GetSecurityMetrics() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := r.db.Table("mv_security_metrics").Find(&results).Error
	return results, err
}

// RefreshViews refreshes all materialized views
func (r *OptimizedRepository) RefreshViews() error {
	return r.db.Exec("SELECT refresh_edr_views()").Error
}
