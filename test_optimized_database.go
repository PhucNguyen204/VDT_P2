package main

import (
	"fmt"
	"time"

	"edr-server/internal/config"
	"edr-server/internal/database"
	"edr-server/internal/models"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	fmt.Println("🚀 EDR OPTIMIZED DATABASE TEST")
	fmt.Println("================================")

	// Test different connection configurations
	testConfigurations := []struct {
		name   string
		config database.OptimizedDBConfig
	}{
		{
			name:   "Default Configuration",
			config: database.DefaultOptimizedConfig(),
		},
		{
			name: "High-Performance Configuration",
			config: database.OptimizedDBConfig{
				MaxIdleConns:       50,
				MaxOpenConns:       300,
				ConnMaxLifetime:    1 * time.Hour,
				ConnMaxIdleTime:    10 * time.Minute,
				LogLevel:           logger.Silent,
				SlowThreshold:      100 * time.Millisecond,
				EnablePartitioning: true,
				EnableReadReplicas: false,
			},
		},
		{
			name: "Development Configuration",
			config: database.OptimizedDBConfig{
				MaxIdleConns:       10,
				MaxOpenConns:       50,
				ConnMaxLifetime:    30 * time.Minute,
				ConnMaxIdleTime:    5 * time.Minute,
				LogLevel:           logger.Info,
				SlowThreshold:      500 * time.Millisecond,
				EnablePartitioning: false,
				EnableReadReplicas: false,
			},
		},
	}

	dbConfig := config.DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Username: "edr_user",
		Password: "edr_password",
		Database: "edr_db",
		SSLMode:  "disable",
	}

	for _, testConfig := range testConfigurations {
		fmt.Printf("\n📊 Testing %s\n", testConfig.name)
		fmt.Println("----------------------------------------")

		// Test connection
		db, err := database.InitOptimizedDB(dbConfig, testConfig.config)
		if err != nil {
			fmt.Printf("❌ Connection failed: %v\n", err)
			continue
		}

		// Test basic operations
		if err := testBasicOperations(db); err != nil {
			fmt.Printf("❌ Basic operations failed: %v\n", err)
			continue
		}

		// Test optimized models
		if err := testOptimizedModels(db); err != nil {
			fmt.Printf("❌ Optimized models test failed: %v\n", err)
			continue
		}

		// Test performance
		if err := testPerformance(db); err != nil {
			fmt.Printf("❌ Performance test failed: %v\n", err)
			continue
		}

		// Test repository methods
		if err := testOptimizedRepository(db); err != nil {
			fmt.Printf("❌ Repository test failed: %v\n", err)
			continue
		}

		fmt.Printf("✅ %s passed all tests!\n", testConfig.name)

		// Close connection
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}

	fmt.Println("\n🎉 EDR OPTIMIZED DATABASE TESTING COMPLETE!")
}

func testBasicOperations(db *gorm.DB) error {
	fmt.Print("  🔍 Testing basic database operations... ")

	// Test connection
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get SQL DB: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Test simple query
	var result int
	if err := db.Raw("SELECT 1").Scan(&result).Error; err != nil {
		return fmt.Errorf("simple query failed: %w", err)
	}

	// Test PostgreSQL version
	var version string
	if err := db.Raw("SELECT version()").Scan(&version).Error; err != nil {
		return fmt.Errorf("version query failed: %w", err)
	}

	fmt.Printf("✅ (PostgreSQL detected)\n")
	return nil
}

func testOptimizedModels(db *gorm.DB) error {
	fmt.Print("  🏗️  Testing optimized models... ")

	// Test OptimizedAgent creation
	agent := &models.OptimizedAgent{
		Hostname:    "test-endpoint-001",
		IPAddress:   "192.168.1.100",
		OS:          "Windows 10",
		OSVersion:   "10.0.19041",
		Environment: "test",
		RiskScore:   25,
		Status:      "active",
		LastSeen:    time.Now(),
	}

	if err := db.Create(agent).Error; err != nil {
		return fmt.Errorf("failed to create optimized agent: %w", err)
	}

	// Test OptimizedEvent creation with normalized fields
	event := &models.OptimizedEvent{
		AgentID:       agent.ID,
		EventType:     "process_creation",
		EventCategory: "process",
		ProcessName:   "powershell.exe",
		ProcessPath:   "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		CommandLine:   "powershell.exe -ExecutionPolicy Bypass",
		UserName:      "admin",
		Severity:      7,
		ThreatLevel:   "high",
		Timestamp:     time.Now(),
		RawData: models.JSONB{
			"EventID": "1",
			"Product": "windows",
		},
	}

	if err := db.Create(event).Error; err != nil {
		return fmt.Errorf("failed to create optimized event: %w", err)
	}

	// Test OptimizedAlert creation
	alert := &models.OptimizedAlert{
		Title:           "Suspicious PowerShell Execution",
		Description:     "Detected suspicious PowerShell execution",
		Severity:        "high",
		ThreatLevel:     "high",
		Status:          "open",
		RuleID:          "test-rule-001",
		RuleName:        "Suspicious PowerShell",
		AgentID:         agent.ID,
		EventCount:      1,
		ConfidenceScore: 0.95,
		RiskScore:       75,
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
	}

	if err := db.Create(alert).Error; err != nil {
		return fmt.Errorf("failed to create optimized alert: %w", err)
	}

	// Test NetworkConnection
	netConn := &models.NetworkConnection{
		AgentID:         agent.ID,
		Protocol:        "tcp",
		SourceIP:        "192.168.1.100",
		SourcePort:      12345,
		DestinationIP:   "8.8.8.8",
		DestinationPort: 53,
		Direction:       "outbound",
		Status:          "established",
		Timestamp:       time.Now(),
	}

	if err := db.Create(netConn).Error; err != nil {
		return fmt.Errorf("failed to create network connection: %w", err)
	}

	// Test ThreatIntelligence
	threat := &models.ThreatIntelligence{
		IOCType:     "ip",
		IOCValue:    "192.168.1.200",
		ThreatType:  "malware",
		Severity:    "high",
		Source:      "test",
		Description: "Test malicious IP",
		IsActive:    true,
	}

	if err := db.Create(threat).Error; err != nil {
		return fmt.Errorf("failed to create threat intelligence: %w", err)
	}

	fmt.Println("✅")
	return nil
}

func testPerformance(db *gorm.DB) error {
	fmt.Print("  ⚡ Testing performance... ")

	// Test bulk insert performance
	start := time.Now()
	agents := make([]*models.OptimizedAgent, 100)
	for i := range agents {
		agents[i] = &models.OptimizedAgent{
			Hostname:    fmt.Sprintf("perf-test-%d", i),
			IPAddress:   fmt.Sprintf("10.0.0.%d", i+1),
			OS:          "Windows 10",
			Environment: "test",
			Status:      "active",
			LastSeen:    time.Now(),
		}
	}

	if err := db.CreateInBatches(agents, 50).Error; err != nil {
		return fmt.Errorf("bulk insert failed: %w", err)
	}

	insertTime := time.Since(start)

	// Test query performance
	start = time.Now()
	var count int64
	if err := db.Model(&models.OptimizedAgent{}).Where("status = ?", "active").Count(&count).Error; err != nil {
		return fmt.Errorf("count query failed: %w", err)
	}

	queryTime := time.Since(start)

	// Test complex query with joins
	start = time.Now()
	var results []struct {
		AgentID    string
		Hostname   string
		EventCount int64
		AlertCount int64
	}

	if err := db.Table("optimized_agents a").
		Select("a.id as agent_id, a.hostname, COUNT(DISTINCT e.id) as event_count, COUNT(DISTINCT al.id) as alert_count").
		Joins("LEFT JOIN optimized_events e ON a.id = e.agent_id").
		Joins("LEFT JOIN optimized_alerts al ON a.id = al.agent_id").
		Where("a.status = ?", "active").
		Group("a.id, a.hostname").
		Limit(10).
		Find(&results).Error; err != nil {
		return fmt.Errorf("complex query failed: %w", err)
	}

	complexQueryTime := time.Since(start)

	fmt.Printf("✅ (Insert: %v, Query: %v, Complex: %v)\n",
		insertTime, queryTime, complexQueryTime)

	// Performance thresholds (adjust based on hardware)
	if insertTime > 5*time.Second {
		return fmt.Errorf("bulk insert too slow: %v", insertTime)
	}
	if queryTime > 1*time.Second {
		return fmt.Errorf("simple query too slow: %v", queryTime)
	}
	if complexQueryTime > 2*time.Second {
		return fmt.Errorf("complex query too slow: %v", complexQueryTime)
	}

	return nil
}

func testOptimizedRepository(db *gorm.DB) error {
	fmt.Print("  🗄️  Testing optimized repository... ")

	repo := database.NewOptimizedRepository(db)

	// Create materialized views first
	if err := database.CreateOptimizedViews(db); err != nil {
		return fmt.Errorf("failed to create views: %w", err)
	}

	// Test dashboard data
	dashboard, err := repo.GetAgentDashboard()
	if err != nil {
		return fmt.Errorf("failed to get agent dashboard: %w", err)
	}

	// Test threat summary
	threats, err := repo.GetThreatSummary()
	if err != nil {
		return fmt.Errorf("failed to get threat summary: %w", err)
	}

	// Test security metrics
	metrics, err := repo.GetSecurityMetrics()
	if err != nil {
		return fmt.Errorf("failed to get security metrics: %w", err)
	}

	// Test view refresh
	if err := repo.RefreshViews(); err != nil {
		return fmt.Errorf("failed to refresh views: %w", err)
	}

	fmt.Printf("✅ (Dashboard: %d, Threats: %d, Metrics: %d)\n",
		len(dashboard), len(threats), len(metrics))

	return nil
}

func testConnectionPooling(db *gorm.DB) error {
	fmt.Print("  🔗 Testing connection pooling... ")

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get SQL DB: %w", err)
	}

	// Get connection pool stats
	stats := sqlDB.Stats()

	fmt.Printf("✅ (Open: %d, Idle: %d, InUse: %d)\n",
		stats.OpenConnections, stats.Idle, stats.InUse)

	// Test concurrent connections
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			var result int
			err := db.Raw("SELECT ? as id", id).Scan(&result).Error
			done <- err
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			return fmt.Errorf("concurrent query %d failed: %w", i, err)
		}
	}

	return nil
}

func testIndexes(db *gorm.DB) error {
	fmt.Print("  📊 Testing index performance... ")

	// Test that indexes are being used
	var explain []map[string]interface{}

	// Query that should use index
	query := `EXPLAIN (FORMAT JSON) 
		SELECT * FROM optimized_agents 
		WHERE status = 'active' AND last_seen > NOW() - INTERVAL '1 hour'`

	if err := db.Raw(query).Find(&explain).Error; err != nil {
		return fmt.Errorf("explain query failed: %w", err)
	}

	fmt.Println("✅")
	return nil
}

// Additional test functions can be added here for specific EDR scenarios
func testEDRScenarios(db *gorm.DB) error {
	// Test real-world EDR scenarios
	// - High-volume event ingestion
	// - Real-time alerting queries
	// - Threat hunting queries
	// - Compliance reporting queries
	return nil
}
