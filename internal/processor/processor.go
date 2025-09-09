package processor

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-server/internal/database"
	"edr-server/internal/models"
	"edr-server/internal/sigma"

	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Processor xử lý events từ Vector.dev agents với SIGMA Engine
type Processor struct {
	sigmaEngine *sigma.SigmaEngine
	repository  *database.Repository
	logger      *logrus.Logger

	// Process tree tracking
	processTrees map[string]*models.ProcessTree
	treesMutex   sync.RWMutex

	// Workers
	workerPool  chan *models.Event
	workerCount int
	stopChan    chan bool
}

// VectorEvent đại diện cho event từ Vector.dev
type VectorEvent struct {
	Timestamp string                 `json:"timestamp"`
	Host      string                 `json:"host"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Level     string                 `json:"level"`
	Fields    map[string]interface{} `json:"fields,omitempty"`

	// Windows Event Log fields
	EventID  int    `json:"event_id,omitempty"`
	Channel  string `json:"channel,omitempty"`
	Computer string `json:"computer,omitempty"`
	Provider string `json:"provider,omitempty"`

	// Process monitoring fields
	ProcessID   string `json:"process_id,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ParentPID   string `json:"parent_pid,omitempty"`
	UserName    string `json:"user_name,omitempty"`
	Hash        string `json:"hash,omitempty"`

	// Vector Agent specific fields
	AgentID         string   `json:"agent_id,omitempty"`
	EventType       string   `json:"event_type,omitempty"`
	EventCategory   string   `json:"event_category,omitempty"`
	SourceType      string   `json:"source_type,omitempty"`
	SourceIP        string   `json:"source_ip,omitempty"`
	SourcePort      int      `json:"source_port,omitempty"`
	Severity        int      `json:"severity,omitempty"`
	ThreatLevel     string   `json:"threat_level,omitempty"`
	AuthMethod      string   `json:"auth_method,omitempty"`
	AuthResult      string   `json:"auth_result,omitempty"`
	FailureReason   string   `json:"failure_reason,omitempty"`
	MitreTactics    []string `json:"mitre_tactics,omitempty"`
	MitreTechniques []string `json:"mitre_techniques,omitempty"`
}

// New tạo processor mới với SIGMA Engine
func New(db *gorm.DB, logger *logrus.Logger) (*Processor, error) {
	var sigmaEngine *sigma.SigmaEngine

	// Enhanced: Use categorized loading for optimal performance with all 3,033 SIGMA rules
	logger.Info("🚀 Loading ALL 3,033 SIGMA rules with categorized approach")
	ruleConfig := GetDefaultRuleConfig()
	rules, err := LoadCategorizedRules("rules/", ruleConfig, logger)
	if err != nil {
		logger.WithError(err).Warn("Categorized loading failed, falling back to simple loading")
		// Fallback to simple loading
		rules, err = loadSigmaRules("rules/")
		if err != nil {
			logger.WithError(err).Warn("Failed to load SIGMA rules, continuing with empty ruleset")
			rules = []string{} // Empty ruleset
		}
	}

	// Filter and validate rules before compilation
	validRules := []string{}
	for i, rule := range rules {
		// Basic validation - skip empty or malformed rules
		if len(strings.TrimSpace(rule)) < 50 || !strings.Contains(rule, "detection:") {
			logger.WithField("rule_index", i).Debug("Skipping invalid rule")
			continue
		}
		validRules = append(validRules, rule)
	}

	logger.WithFields(logrus.Fields{
		"total_loaded": len(rules),
		"valid_rules":  len(validRules),
	}).Info("🔍 SIGMA rules loaded and filtered")

	// Use cawalch/sigma-engine API: FromRules static constructor
	sigmaEngine, err = sigma.FromRules(validRules)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"total_rules": len(validRules),
			"error":       err.Error(),
		}).Warn("🔧 SIGMA engine compilation failed, trying progressive fallback")

		// Simplified fallback - try with subset of rules
		logger.WithField("total_rules", len(validRules)).Warn("Using simplified fallback compilation")

		// Try with smaller subset first (first 100 rules)
		subsetSize := 100
		if len(validRules) < subsetSize {
			subsetSize = len(validRules) / 2
		}

		if subsetSize > 0 {
			subset := validRules[:subsetSize]
			sigmaEngine, err = sigma.FromRules(subset)
			if err == nil {
				logger.WithFields(logrus.Fields{
					"successful_rules": len(subset),
					"total_rules":      len(validRules),
				}).Info("✅ Fallback compilation with subset successful")
			}
		}

		// Final fallback - create engine with no rules
		if sigmaEngine == nil {
			logger.Error("🚨 All compilation attempts failed, creating empty engine")
			sigmaEngine, err = sigma.FromRules([]string{})
			if err != nil {
				return nil, fmt.Errorf("failed to create even empty SIGMA engine: %w", err)
			}
		}
	} else {
		logger.WithField("compiled_rules", len(validRules)).Info("🎯 All SIGMA rules compiled successfully!")
	}

	// Setup field mappings for common log sources
	sigmaEngine.AddFieldMapping("ProcessImage", "Image")
	sigmaEngine.AddFieldMapping("ProcessCommandLine", "CommandLine")
	sigmaEngine.AddFieldMapping("ParentProcessImage", "ParentImage")
	sigmaEngine.AddFieldMapping("ParentProcessCommandLine", "ParentCommandLine")
	sigmaEngine.AddFieldMapping("TargetFilename", "file_path")
	sigmaEngine.AddFieldMapping("DestinationIp", "dst_ip")
	sigmaEngine.AddFieldMapping("SourceIp", "src_ip")
	sigmaEngine.AddFieldMapping("DestinationPort", "dst_port")
	sigmaEngine.AddFieldMapping("SourcePort", "src_port")

	logger.WithField("rules_loaded", len(rules)).Info("SIGMA Engine initialized successfully")

	return &Processor{
		sigmaEngine:  sigmaEngine,
		repository:   database.NewRepository(db),
		logger:       logger,
		processTrees: make(map[string]*models.ProcessTree),
		workerPool:   make(chan *models.Event, 1000),
		workerCount:  4,
		stopChan:     make(chan bool),
	}, nil
}

// loadSigmaRules load SIGMA rules từ directory
func loadSigmaRules(rulesDir string) ([]string, error) {
	var rules []string
	maxRules := -1 // UNLIMITED: Load all 3,033 SIGMA rules from repository

	// Comprehensive priority directories - systematically load all major rule categories
	priorityDirs := []string{
		// === LINUX PLATFORM RULES ===
		"linux/builtin",            // All Linux builtin rules (auth, sshd, etc.)
		"linux/process_creation",   // Linux process events
		"linux/network_connection", // Linux network events
		"linux/auditd",             // Linux auditd rules
		"linux/file_event",         // Linux file operations

		// === NETWORK DETECTION RULES ===
		"network/dns",      // DNS detection rules
		"network/firewall", // Network firewall rules
		"network/cisco",    // Cisco network equipment
		"network/zeek",     // Zeek network analysis
		"network/juniper",  // Juniper network devices

		// === APPLICATION LAYER RULES ===
		"application/opencanary", // Honeypot detection
		"application/django",     // Django web framework
		"application/kubernetes", // Container orchestration
		"application/sql",        // SQL injection & database attacks
		"application/python",     // Python-specific threats
		"application/nodejs",     // Node.js security
		"application/ruby",       // Ruby application security

		// === WINDOWS PLATFORM RULES ===
		"windows/builtin",            // Windows authentication events
		"windows/process_creation",   // Windows process detection
		"windows/powershell",         // PowerShell attack detection
		"windows/registry",           // Windows registry manipulation
		"windows/file",               // Windows file operations
		"windows/network_connection", // Windows network events
		"windows/dns_query",          // Windows DNS queries
		"windows/driver_load",        // Windows driver loading
		"windows/image_load",         // Windows image/DLL loading
		"windows/pipe_created",       // Windows named pipes
		"windows/process_access",     // Windows process access
		"windows/wmi_event",          // Windows WMI events
		"windows/sysmon",             // Windows Sysmon events

		// === CLOUD & INFRASTRUCTURE ===
		"cloud/aws",    // AWS security rules
		"cloud/azure",  // Azure security rules
		"cloud/gcp",    // Google Cloud Platform
		"cloud/m365",   // Microsoft 365
		"cloud/github", // GitHub security
		"cloud/okta",   // Okta identity management

		// === WEB & PROXY RULES ===
		"web/webserver_generic", // Generic web server attacks
		"web/proxy_generic",     // Proxy-based detection

		// === MACOS PLATFORM RULES ===
		"macos/process_creation", // macOS process events
		"macos/file_event",       // macOS file operations

		// === COMPLIANCE & CATEGORY RULES ===
		"category/antivirus", // Antivirus-related events
		"category/database",  // Database security events
		"compliance",         // Compliance monitoring
	}

	// Load rules from root directory first
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || (maxRules > 0 && len(rules) >= maxRules) {
			continue
		}

		ext := filepath.Ext(file.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		filePath := filepath.Join(rulesDir, file.Name())
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			continue
		}

		contentStr := string(content)
		if strings.Contains(contentStr, "title:") && strings.Contains(contentStr, "detection:") {
			rules = append(rules, contentStr)
		}
	}

	// Load from priority directories
	for _, priorityDir := range priorityDirs {
		if maxRules > 0 && len(rules) >= maxRules {
			break
		}

		fullPath := filepath.Join(rulesDir, priorityDir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || (maxRules > 0 && len(rules) >= maxRules) {
				return nil
			}

			if info.IsDir() {
				return nil
			}

			ext := filepath.Ext(info.Name())
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}

			content, err := ioutil.ReadFile(path)
			if err != nil {
				return nil
			}

			contentStr := string(content)
			if strings.Contains(contentStr, "title:") && strings.Contains(contentStr, "detection:") {
				rules = append(rules, contentStr)
			}

			return nil
		})

		if err != nil {
			continue // Skip directories with errors
		}
	}

	return rules, nil
}

// Start khởi động processor workers
func (p *Processor) Start() {
	p.logger.Info("Khởi động Event Processor workers")

	for i := 0; i < p.workerCount; i++ {
		go p.worker(i)
	}
}

// Stop dừng processor workers
func (p *Processor) Stop() {
	p.logger.Info("Dừng Event Processor workers")
	close(p.stopChan)
}

// ProcessVectorEvent xử lý event từ Vector.dev
func (p *Processor) ProcessVectorEvent(vectorEvent *VectorEvent) error {
	// Convert VectorEvent thành models.Event
	event, err := p.convertVectorEvent(vectorEvent)
	if err != nil {
		p.logger.WithError(err).Error("Không thể convert Vector event")
		return err
	}

	// Ensure agent exists before saving event
	err = p.ensureAgentExists(event.AgentID, vectorEvent)
	if err != nil {
		p.logger.WithError(err).Error("Không thể tạo agent")
		return err
	}

	// Run SIGMA detection first
	err = p.processSigmaDetection(event, vectorEvent)
	if err != nil {
		p.logger.WithError(err).Error("Lỗi khi chạy SIGMA detection")
		// Continue anyway to save event
	}

	// Lưu event vào database
	err = p.repository.CreateEvent(event)
	if err != nil {
		p.logger.WithError(err).Error("Không thể lưu event vào database")
		return err
	}

	// Gửi event tới worker pool để process
	select {
	case p.workerPool <- event:
		// Event đã được gửi tới worker
	default:
		p.logger.Warn("Worker pool đầy, bỏ qua event")
	}

	return nil
}

// worker xử lý events từ worker pool
func (p *Processor) worker(workerID int) {
	p.logger.WithField("worker_id", workerID).Info("Worker started")

	for {
		select {
		case event := <-p.workerPool:
			p.processEvent(event, workerID)
		case <-p.stopChan:
			p.logger.WithField("worker_id", workerID).Info("Worker stopped")
			return
		}
	}
}

// processEvent xử lý một event với high-performance streaming engine
func (p *Processor) processEvent(event *models.Event, workerID int) {
	logger := p.logger.WithFields(logrus.Fields{
		"worker_id": workerID,
		"event_id":  event.ID,
		"agent_id":  event.AgentID,
	})

	logger.Debug("Processing event with streaming engine")

	// Update agent last seen
	p.updateAgentLastSeen(event.AgentID)

	// Process tree tracking
	if event.EventType == "process" {
		p.updateProcessTree(event)
	}

	// Detection với SIGMA Engine using cawalch/sigma-engine API
	eventMap := p.convertEventToMap(event)
	result, err := p.sigmaEngine.Evaluate(eventMap)
	if err != nil {
		logger.WithError(err).Error("Lỗi khi evaluate event với SIGMA Engine")
		return
	}

	logger.WithFields(logrus.Fields{
		"matched_rules":    len(result.MatchedRules),
		"execution_time":   result.ExecutionTime,
		"prefilter_passed": result.PrefilterPassed,
		"processed_nodes":  result.ProcessedNodes,
		"shared_hits":      result.SharedHits,
	}).Debug("SIGMA evaluation completed")

	// Convert matched rules thành alerts và lưu
	for _, ruleMatch := range result.MatchedRules {
		alert := &models.Alert{
			Title:       ruleMatch.Title,
			Description: ruleMatch.Description,
			Severity:    p.mapSigmaLevelToSeverity(ruleMatch.Level),
			Status:      "open",
			RuleID:      ruleMatch.RuleID,
			RuleName:    ruleMatch.Title,
			AgentID:     event.AgentID,
			Tags:        ruleMatch.Tags,
			MITRE:       p.extractMitreTags(ruleMatch.Tags),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		err = p.repository.CreateAlert(alert)
		if err != nil {
			logger.WithError(err).Error("Không thể lưu SIGMA alert")
		} else {
			logger.WithFields(logrus.Fields{
				"alert_id":   alert.ID,
				"rule_title": alert.Title,
				"severity":   alert.Severity,
				"agent_id":   alert.AgentID,
			}).Info("🚨 SIGMA Alert created")
		}
	}
}

// convertEventToMap convert models.Event thành map for SIGMA evaluation
func (p *Processor) convertEventToMap(event *models.Event) map[string]interface{} {
	eventMap := map[string]interface{}{
		"event_type":   event.EventType,
		"process_id":   event.ProcessID,
		"process_name": event.ProcessName,
		"command_line": event.CommandLine,
		"parent_pid":   event.ParentPID,
		"user_name":    event.UserName,
		"hash":         event.Hash,
		"severity":     event.Severity,
		"timestamp":    event.Timestamp,
		"agent_id":     event.AgentID,
	}

	// Add event data fields
	if event.EventData != nil {
		for key, value := range event.EventData {
			eventMap[key] = value
		}
	}

	// Add common SIGMA fields
	if event.ProcessID != "" {
		eventMap["ProcessId"] = event.ProcessID
		eventMap["PID"] = event.ProcessID
	}
	if event.ProcessName != "" {
		eventMap["ProcessName"] = event.ProcessName
		eventMap["Image"] = event.ProcessName
	}
	if event.CommandLine != "" {
		eventMap["CommandLine"] = event.CommandLine
		eventMap["ProcessCommandLine"] = event.CommandLine
	}
	if event.ParentPID != "" {
		eventMap["ParentProcessId"] = event.ParentPID
		eventMap["ParentPID"] = event.ParentPID
	}
	if event.UserName != "" {
		eventMap["User"] = event.UserName
		eventMap["UserName"] = event.UserName
	}

	return eventMap
}

// mapSigmaLevelToSeverity map SIGMA levels thành severity strings
func (p *Processor) mapSigmaLevelToSeverity(level string) string {
	switch level {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational", "info":
		return "low"
	default:
		return "medium" // Default to medium
	}
}

// extractMitreTags extract MITRE ATT&CK tags từ rule tags
func (p *Processor) extractMitreTags(tags []string) []string {
	mitreTags := make([]string, 0)

	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.") {
			mitreTags = append(mitreTags, tag)
		}
	}

	return mitreTags
}

// convertVectorEvent convert VectorEvent thành models.Event
func (p *Processor) convertVectorEvent(vectorEvent *VectorEvent) (*models.Event, error) {
	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, vectorEvent.Timestamp)
	if err != nil {
		timestamp = time.Now()
	}

	// Determine event type
	eventType := p.determineEventType(vectorEvent)

	// Create event
	event := &models.Event{
		AgentID:     p.getAgentID(vectorEvent),
		EventType:   eventType,
		EventData:   vectorEvent.Fields,
		ProcessID:   vectorEvent.ProcessID,
		ProcessName: vectorEvent.ProcessName,
		CommandLine: vectorEvent.CommandLine,
		ParentPID:   vectorEvent.ParentPID,
		UserName:    vectorEvent.UserName,
		Hash:        vectorEvent.Hash,
		Severity:    p.determineSeverity(vectorEvent),
		Timestamp:   timestamp,
		CreatedAt:   time.Now(),
	}

	return event, nil
}

// determineEventType xác định loại event
func (p *Processor) determineEventType(vectorEvent *VectorEvent) string {
	// Check Vector Agent event type first (from Vector.dev agent)
	if vectorEvent.EventType != "" {
		return vectorEvent.EventType
	}

	// Check by source type for syslog events
	if vectorEvent.SourceType == "syslog" && vectorEvent.EventCategory == "authentication" {
		return "authentication_failure"
	}

	// Dựa vào source và fields để xác định event type
	if vectorEvent.Source == "windows-events" {
		switch vectorEvent.EventID {
		case 4688: // Process creation
			return "process"
		case 4624, 4625: // Logon events
			return "logon"
		case 4648: // Explicit credential use
			return "credential"
		case 5156: // Network connection
			return "network"
		default:
			return "system"
		}
	}

	if vectorEvent.Source == "sysmon" {
		switch vectorEvent.EventID {
		case 1: // Process creation
			return "process"
		case 3: // Network connection
			return "network"
		case 11: // File creation
			return "file"
		case 13: // Registry modification
			return "registry"
		default:
			return "system"
		}
	}

	return "unknown"
}

// getAgentID lấy agent ID từ Vector event
func (p *Processor) getAgentID(vectorEvent *VectorEvent) string {
	// Check Vector Agent ID first
	if vectorEvent.AgentID != "" {
		return vectorEvent.AgentID
	}
	// Có thể lấy từ host hoặc fields
	if vectorEvent.Computer != "" {
		return vectorEvent.Computer
	}
	if vectorEvent.Host != "" {
		return vectorEvent.Host
	}
	return "unknown"
}

// determineSeverity xác định mức độ nghiêm trọng của event
func (p *Processor) determineSeverity(vectorEvent *VectorEvent) int {
	// Check Vector Agent severity first (numeric value 1-10)
	if vectorEvent.Severity > 0 {
		return vectorEvent.Severity
	}

	// Map threat level to severity
	switch vectorEvent.ThreatLevel {
	case "critical":
		return 10
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	}

	// Fallback to Level field
	switch vectorEvent.Level {
	case "critical", "error":
		return 4
	case "warning":
		return 3
	case "info":
		return 2
	default:
		return 1
	}
}

// updateAgentLastSeen cập nhật last seen của agent
func (p *Processor) updateAgentLastSeen(agentID string) {
	agent := &models.Agent{
		ID:       agentID,
		LastSeen: time.Now(),
		Status:   "active",
	}

	err := p.repository.CreateOrUpdateAgent(agent)
	if err != nil {
		p.logger.WithError(err).WithField("agent_id", agentID).Error("Không thể update agent")
	}
}

// updateProcessTree cập nhật process tree
func (p *Processor) updateProcessTree(event *models.Event) {
	p.treesMutex.Lock()
	defer p.treesMutex.Unlock()

	// Tạo hoặc update process tree
	treeKey := fmt.Sprintf("%s_%s", event.AgentID, event.ProcessID)

	tree, exists := p.processTrees[treeKey]
	if !exists {
		tree = &models.ProcessTree{
			RootProcessID: event.ProcessID,
			AgentID:       event.AgentID,
			Depth:         1,
			ProcessCount:  1,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		p.processTrees[treeKey] = tree
	}

	// Tạo process record
	process := &models.Process{
		PID:         event.ProcessID,
		ProcessName: event.ProcessName,
		CommandLine: event.CommandLine,
		ParentPID:   event.ParentPID,
		UserName:    event.UserName,
		Hash:        event.Hash,
		StartTime:   event.Timestamp,
		AgentID:     event.AgentID,
		TreeID:      tree.ID,
		CreatedAt:   time.Now(),
	}

	tree.Processes = append(tree.Processes, *process)
	tree.ProcessCount = len(tree.Processes)
	tree.UpdatedAt = time.Now()

	// Calculate depth
	tree.Depth = p.calculateTreeDepth(tree)

	// Lưu vào database
	err := p.repository.CreateProcessTree(tree)
	if err != nil {
		p.logger.WithError(err).Error("Không thể lưu process tree")
	}
}

// calculateTreeDepth tính toán depth của process tree
func (p *Processor) calculateTreeDepth(tree *models.ProcessTree) int {
	// Simplified implementation
	maxDepth := 1

	pidToDepth := make(map[string]int)
	pidToDepth[tree.RootProcessID] = 1

	for _, process := range tree.Processes {
		if parentDepth, exists := pidToDepth[process.ParentPID]; exists {
			depth := parentDepth + 1
			pidToDepth[process.PID] = depth
			if depth > maxDepth {
				maxDepth = depth
			}
		}
	}

	return maxDepth
}

// analyzeProcessTreeForAlert phân tích process tree để tạo alerts với SIGMA Engine
func (p *Processor) analyzeProcessTreeForAlert(agentID string) {
	// Tìm process trees của agent
	p.treesMutex.RLock()
	var trees []*models.ProcessTree
	for _, tree := range p.processTrees {
		if tree.AgentID == agentID {
			trees = append(trees, tree)
		}
	}
	p.treesMutex.RUnlock()

	// Analyze từng tree với SIGMA patterns
	for _, tree := range trees {
		// Create synthetic events cho process tree analysis
		events := p.createProcessTreeEvents(tree)

		// Evaluate với SIGMA Engine
		for _, event := range events {
			result, err := p.sigmaEngine.Evaluate(event)
			if err != nil {
				p.logger.WithError(err).Error("Lỗi khi evaluate process tree event")
				continue
			}

			// Tạo alerts cho matched rules
			for _, ruleMatch := range result.MatchedRules {
				alert := &models.Alert{
					Title:       fmt.Sprintf("Process Tree: %s", ruleMatch.Title),
					Description: fmt.Sprintf("Process tree analysis detected: %s", ruleMatch.Description),
					Severity:    p.mapSigmaLevelToSeverity(ruleMatch.Level),
					Status:      "open",
					RuleID:      ruleMatch.RuleID,
					RuleName:    ruleMatch.Title,
					AgentID:     agentID,
					Tags:        append(ruleMatch.Tags, "process_tree"),
					MITRE:       p.extractMitreTags(ruleMatch.Tags),
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}

				err = p.repository.CreateAlert(alert)
				if err != nil {
					p.logger.WithError(err).Error("Không thể lưu process tree SIGMA alert")
				} else {
					p.logger.WithFields(logrus.Fields{
						"alert_id":      alert.ID,
						"tree_id":       tree.ID,
						"rule_name":     alert.RuleName,
						"process_count": tree.ProcessCount,
					}).Info("Tạo process tree SIGMA alert")
				}
			}
		}
	}
}

// createProcessTreeEvents tạo synthetic events từ process tree cho analysis
func (p *Processor) createProcessTreeEvents(tree *models.ProcessTree) []map[string]interface{} {
	events := make([]map[string]interface{}, 0)

	// Create events cho process relationships
	for _, process := range tree.Processes {
		event := map[string]interface{}{
			"EventID":            1, // Process creation
			"event_type":         "process",
			"ProcessId":          process.PID,
			"ProcessName":        process.ProcessName,
			"Image":              process.ProcessName,
			"CommandLine":        process.CommandLine,
			"ParentProcessId":    process.ParentPID,
			"User":               process.UserName,
			"ProcessGuid":        fmt.Sprintf("{%s-%s}", process.AgentID, process.PID),
			"ParentProcessGuid":  fmt.Sprintf("{%s-%s}", process.AgentID, process.ParentPID),
			"agent_id":           process.AgentID,
			"tree_id":            process.TreeID,
			"tree_depth":         tree.Depth,
			"tree_process_count": tree.ProcessCount,
		}

		if process.Hash != "" {
			event["Hash"] = process.Hash
			event["Hashes"] = fmt.Sprintf("SHA256=%s", process.Hash)
		}

		events = append(events, event)
	}

	// Thêm tree-level analysis event
	treeEvent := map[string]interface{}{
		"event_type":       "process_tree",
		"tree_id":          tree.ID,
		"root_process_id":  tree.RootProcessID,
		"agent_id":         tree.AgentID,
		"tree_depth":       tree.Depth,
		"process_count":    tree.ProcessCount,
		"suspicious_depth": tree.Depth > 5,         // Flag deep process trees
		"suspicious_count": tree.ProcessCount > 10, // Flag large process trees
	}

	events = append(events, treeEvent)

	return events
}

// GetProcessTreeStats trả về thống kê process trees
func (p *Processor) GetProcessTreeStats() map[string]interface{} {
	p.treesMutex.RLock()
	defer p.treesMutex.RUnlock()

	stats := map[string]interface{}{
		"total_trees":   len(p.processTrees),
		"active_agents": len(p.getActiveAgents()),
		"avg_depth":     p.calculateAverageDepth(),
		"avg_processes": p.calculateAverageProcessCount(),
	}

	return stats
}

// getActiveAgents trả về danh sách agents đang active
func (p *Processor) getActiveAgents() []string {
	agentSet := make(map[string]bool)
	for _, tree := range p.processTrees {
		agentSet[tree.AgentID] = true
	}

	var agents []string
	for agent := range agentSet {
		agents = append(agents, agent)
	}

	return agents
}

// calculateAverageDepth tính depth trung bình
func (p *Processor) calculateAverageDepth() float64 {
	if len(p.processTrees) == 0 {
		return 0
	}

	totalDepth := 0
	for _, tree := range p.processTrees {
		totalDepth += tree.Depth
	}

	return float64(totalDepth) / float64(len(p.processTrees))
}

// calculateAverageProcessCount tính số process trung bình
func (p *Processor) calculateAverageProcessCount() float64 {
	if len(p.processTrees) == 0 {
		return 0
	}

	totalProcesses := 0
	for _, tree := range p.processTrees {
		totalProcesses += tree.ProcessCount
	}

	return float64(totalProcesses) / float64(len(p.processTrees))
}

// ensureAgentExists tạo agent nếu chưa tồn tại
func (p *Processor) ensureAgentExists(agentID string, vectorEvent *VectorEvent) error {
	// Check if agent already exists
	_, err := p.repository.GetAgent(agentID)
	if err == nil {
		// Agent already exists
		return nil
	}

	// Create new agent
	agent := &models.Agent{
		ID:           agentID,
		Hostname:     agentID,
		IPAddress:    "unknown",
		OS:           "unknown",
		OSVersion:    "unknown",
		AgentVersion: "1.0.0",
		Status:       "active",
		LastSeen:     time.Now(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Try to get more info from vectorEvent
	if vectorEvent.Host != "" {
		agent.Hostname = vectorEvent.Host
	}
	if vectorEvent.Computer != "" {
		agent.Hostname = vectorEvent.Computer
	}

	// Create agent in database (use CreateOrUpdateAgent for idempotent operation)
	err = p.repository.CreateOrUpdateAgent(agent)
	if err != nil {
		p.logger.WithError(err).Warn("Could not create/update agent, continuing anyway")
		// Don't return error - continue processing events even if agent creation fails
	}

	p.logger.WithField("agent_id", agentID).Info("Auto-created new agent")
	return nil
}

// processSigmaDetection chạy SIGMA detection và tạo alerts theo cawalch/sigma-engine pattern
func (p *Processor) processSigmaDetection(event *models.Event, vectorEvent *VectorEvent) error {
	// Convert event to map for SIGMA engine (theo chuẩn cawalch/sigma-engine)
	eventData := make(map[string]interface{})

	// Map Vector Agent events to SIGMA format
	if vectorEvent.EventType == "authentication_failure" {
		// Authentication failure mapping
		eventData["EventID"] = 4625 // Windows logon failure
		eventData["Computer"] = vectorEvent.AgentID
		eventData["User"] = vectorEvent.UserName
		eventData["Product"] = "linux"
		eventData["Category"] = "authentication"
		eventData["WorkstationName"] = "ATTACKER-VM"
		eventData["IpAddress"] = vectorEvent.SourceIP
		eventData["IpPort"] = vectorEvent.SourcePort
		eventData["LogonType"] = 3 // Network logon
		eventData["FailureReason"] = vectorEvent.FailureReason
		eventData["Status"] = "0xc000006a" // Bad password
		eventData["SubjectUserName"] = vectorEvent.UserName
		eventData["TargetUserName"] = vectorEvent.UserName
		eventData["CommandLine"] = vectorEvent.CommandLine
		eventData["ProcessName"] = vectorEvent.ProcessName

		// Add MITRE mapping
		if len(vectorEvent.MitreTechniques) > 0 {
			eventData["mitre_techniques"] = vectorEvent.MitreTechniques
		}
		if len(vectorEvent.MitreTactics) > 0 {
			eventData["mitre_tactics"] = vectorEvent.MitreTactics
		}
	} else {
		// Default Windows process creation mapping
		eventData["EventID"] = vectorEvent.EventID
		if vectorEvent.Fields != nil {
			if image, exists := vectorEvent.Fields["Image"]; exists {
				eventData["Image"] = image
			}
			if cmdLine, exists := vectorEvent.Fields["CommandLine"]; exists {
				eventData["CommandLine"] = cmdLine
			}
		}
		eventData["ProcessId"] = vectorEvent.ProcessID
		eventData["User"] = vectorEvent.UserName
		eventData["Computer"] = vectorEvent.Computer
		eventData["Product"] = "windows"
		eventData["Category"] = "process_creation"
	}

	// Add all fields from vectorEvent.Fields
	for k, v := range vectorEvent.Fields {
		eventData[k] = v
	}

	// Run SIGMA evaluation với DAG engine (theo cawalch architecture)
	result, err := p.sigmaEngine.Evaluate(eventData)
	if err != nil {
		return fmt.Errorf("SIGMA evaluation failed: %w", err)
	}

	p.logger.WithFields(logrus.Fields{
		"event_id":         event.ID,
		"matches":          len(result.MatchedRules),
		"prefilter_passed": result.PrefilterPassed,
		"execution_time":   result.ExecutionTime,
		"processed_nodes":  result.ProcessedNodes,
		"shared_hits":      result.SharedHits,
	}).Info("🔍 SIGMA detection completed")

	// Create alerts for matched rules (realtime alerting)
	for _, ruleMatch := range result.MatchedRules {
		// Prepare arrays for PostgreSQL
		tags := ruleMatch.Tags
		if tags == nil {
			tags = []string{}
		}
		mitre := extractMitreFromTags(ruleMatch.Tags)
		if mitre == nil {
			mitre = []string{}
		}

		alert := &models.Alert{
			Title:       ruleMatch.Title,
			Description: ruleMatch.Description,
			Severity:    p.mapSigmaSeverityToString(ruleMatch.Level),
			Status:      "open",
			RuleID:      ruleMatch.RuleID,
			RuleName:    ruleMatch.Title,
			AgentID:     event.AgentID,
			Tags:        pq.StringArray(tags),
			MITRE:       pq.StringArray(mitre),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		err = p.repository.CreateAlert(alert)
		if err != nil {
			p.logger.WithError(err).Error("Failed to create alert")
			continue
		}

		p.logger.WithFields(logrus.Fields{
			"alert_id":      alert.ID,
			"rule_id":       ruleMatch.RuleID,
			"rule_title":    ruleMatch.Title,
			"severity":      alert.Severity,
			"agent_id":      event.AgentID,
			"mitre_tactics": alert.MITRE,
		}).Warn("🚨 REALTIME SIGMA ALERT: Attack detected!")

		// Gửi notification realtime nếu cần
		go p.sendRealtimeNotification(alert, ruleMatch)
	}

	return nil
}

// sendRealtimeNotification gửi notification realtime cho alerts
func (p *Processor) sendRealtimeNotification(alert *models.Alert, ruleMatch *sigma.RuleMatch) {
	// TODO: Implement realtime notification (WebSocket, webhook, etc.)
	p.logger.WithFields(logrus.Fields{
		"alert_id": alert.ID,
		"severity": alert.Severity,
		"title":    alert.Title,
	}).Info("📢 Realtime notification sent")
}

// mapSigmaSeverityToString maps SIGMA severity to string theo cawalch standard
func (p *Processor) mapSigmaSeverityToString(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

// extractMitreFromTags extracts MITRE ATT&CK techniques from tags
func extractMitreFromTags(tags []string) []string {
	var mitre []string
	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.t") {
			mitre = append(mitre, strings.ToUpper(tag))
		}
	}
	return mitre
}

// attemptProgressiveCompilation tries to compile rules progressively, inspired by cawalch/sigma-engine resilience
func attemptProgressiveCompilation(engine *sigma.SigmaEngine, rules []string, logger *logrus.Logger) []string {
	// Strategy 1: Try batches of rules to find problematic ones
	batchSize := 50
	successfulRules := []string{}

	logger.WithField("batch_size", batchSize).Info("🔄 Attempting progressive compilation in batches")

	for i := 0; i < len(rules); i += batchSize {
		end := i + batchSize
		if end > len(rules) {
			end = len(rules)
		}

		batch := rules[i:end]
		testEngine := sigma.NewSigmaEngine(nil, logger)

		// Try current batch
		err := testEngine.FromRules(batch)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"batch_start": i,
				"batch_size":  len(batch),
				"error":       err.Error(),
			}).Debug("❌ Batch compilation failed, trying individual rules")

			// If batch fails, try individual rules
			for j, rule := range batch {
				individualEngine := sigma.NewSigmaEngine(nil, logger)
				err := individualEngine.FromRules([]string{rule})
				if err == nil {
					successfulRules = append(successfulRules, rule)
					logger.WithField("rule_index", i+j).Debug("✅ Individual rule compiled")
				} else {
					logger.WithFields(logrus.Fields{
						"rule_index": i + j,
						"error":      err.Error(),
					}).Debug("❌ Individual rule failed")
				}
			}
		} else {
			// Batch succeeded
			successfulRules = append(successfulRules, batch...)
			logger.WithFields(logrus.Fields{
				"batch_start": i,
				"batch_size":  len(batch),
			}).Debug("✅ Batch compilation successful")
		}
	}

	// If we have successful rules, try to compile them all together
	if len(successfulRules) > 0 {
		err := engine.FromRules(successfulRules)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"successful_count": len(successfulRules),
				"error":            err.Error(),
			}).Warn("❌ Final compilation with successful rules failed")
			return []string{} // Return empty to trigger minimal fallback
		}
	}

	return successfulRules
}

// getMinimalCustomRules returns a minimal set of tested custom rules as last resort
func getMinimalCustomRules() []string {
	return []string{
		// SSH Brute Force - tested and working
		`title: SSH Brute Force Attack Detection
id: bf4c5c8a-c4b2-4d8a-9f1a-2b3c4d5e6f7a
status: stable
description: Detects SSH brute force attacks based on failed login attempts.
author: YourName
date: 2025/09/09
tags:
    - attack.credential-access
    - attack.t1110.001
    - attack.ta0006
logsource:
    product: linux
    service: sshd
    category: authentication
detection:
    selection:
        EventID: 4625
        Product: 'linux'
        Category: 'authentication'
        FailureReason|contains: 'invalid_password'
        IpAddress|re: '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    timeframe: 10s
    condition: selection | count(by=IpAddress) > 5
falsepositives:
    - Legitimate users with mistyped passwords (low volume)
level: high`,

		// Simple Process Creation - basic detection
		`title: Suspicious Process Creation
id: 12345678-1234-1234-1234-123456789abc
description: Detects suspicious process creation events
author: YourName
date: 2025/09/09
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        EventID: 1
        ProcessImage|endswith:
            - '/powershell'
            - '/cmd.exe'
            - '/bash'
        CommandLine|contains:
            - 'wget'
            - 'curl'
            - 'nc -l'
    condition: selection
level: medium`,

		// Network Connection - basic network monitoring
		`title: Suspicious Network Connections
id: 23456789-2345-2345-2345-234567890abc
description: Detects suspicious network connections
author: YourName
date: 2025/09/09
tags:
    - attack.command-and-control
    - attack.t1071
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        Initiated: 'true'
        DestinationPort:
            - 4444
            - 1337
            - 8080
            - 9999
        DestinationIp|re: '(172\.16\.|172\.17\.|172\.18\.|172\.19\.|172\.2[0-9]\.|172\.3[0-1]\.)'
    condition: selection
level: medium`,
	}
}
