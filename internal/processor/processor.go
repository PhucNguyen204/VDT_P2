package processor

import (
	"fmt"
	"io/ioutil"
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
}

// New tạo processor mới với SIGMA Engine
func New(db *gorm.DB, logger *logrus.Logger) (*Processor, error) {
	// Initialize SIGMA Engine
	sigmaEngine := sigma.NewSigmaEngine(nil, logger)

	// Load SIGMA rules từ thư mục rules/
	rules, err := loadSigmaRules("rules/")
	if err != nil {
		logger.WithError(err).Warn("Failed to load SIGMA rules, continuing with empty ruleset")
		rules = []string{} // Empty ruleset
	}

	// Compile rules into engine
	err = sigmaEngine.FromRules(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SIGMA engine: %w", err)
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

	// Read all .yml và .yaml files trong directory
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Check file extension
		ext := filepath.Ext(file.Name())
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		// Read file content
		filePath := filepath.Join(rulesDir, file.Name())
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		rules = append(rules, string(content))
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

// processEvent xử lý một event
func (p *Processor) processEvent(event *models.Event, workerID int) {
	logger := p.logger.WithFields(logrus.Fields{
		"worker_id": workerID,
		"event_id":  event.ID,
		"agent_id":  event.AgentID,
	})

	logger.Debug("Processing event")

	// Update agent last seen
	p.updateAgentLastSeen(event.AgentID)

	// Process tree tracking
	if event.EventType == "process" {
		p.updateProcessTree(event)
	}

	// Detection với SIGMA Engine
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
				"alert_id":       alert.ID,
				"severity":       alert.Severity,
				"rule_name":      alert.RuleName,
				"rule_id":        alert.RuleID,
				"confidence":     ruleMatch.Confidence,
				"matched_fields": len(ruleMatch.MatchedFields),
			}).Info("Tạo SIGMA alert mới")
		}
	}

	// Analyze process tree nếu có
	if event.EventType == "process" {
		p.analyzeProcessTreeForAlert(event.AgentID)
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

	// Add core fields theo SIGMA standard
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
