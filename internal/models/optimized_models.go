package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// JSONB custom type to handle scanning issues
type JSONB map[string]interface{}

func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("cannot scan %T into JSONB", value)
	}

	if len(bytes) == 0 {
		*j = nil
		return nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		return err
	}
	*j = data
	return nil
}

// ============ ENHANCED CORE MODELS ============

// Agent with enhanced information for enterprise EDR
type OptimizedAgent struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	Hostname     string    `json:"hostname" gorm:"not null;index"`
	IPAddress    string    `json:"ip_address" gorm:"index"`
	MACAddress   string    `json:"mac_address"`
	OS           string    `json:"os" gorm:"index"`
	OSVersion    string    `json:"os_version"`
	OSBuild      string    `json:"os_build"`
	Architecture string    `json:"architecture"`
	AgentVersion string    `json:"agent_version"`
	Status       string    `json:"status" gorm:"default:active;index"`
	LastSeen     time.Time `json:"last_seen" gorm:"index"`
	FirstSeen    time.Time `json:"first_seen"`

	// Geographic and Network Info
	Location  string `json:"location"`
	Timezone  string `json:"timezone"`
	Domain    string `json:"domain"`
	Workgroup string `json:"workgroup"`

	// Hardware Info
	CPU       string `json:"cpu"`
	Memory    int64  `json:"memory_mb"`
	DiskSpace int64  `json:"disk_space_gb"`

	// Security Context
	AntivirusProduct string `json:"antivirus_product"`
	FirewallStatus   string `json:"firewall_status"`
	Compliance       string `json:"compliance_status"`
	RiskScore        int    `json:"risk_score" gorm:"default:0"`

	// Metadata
	Tags        pq.StringArray `json:"tags" gorm:"type:text[]"`
	Environment string         `json:"environment"` // production, staging, development
	Owner       string         `json:"owner"`
	Department  string         `json:"department"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NetworkConnection table for network activity tracking
type NetworkConnection struct {
	ID              string    `json:"id" gorm:"primaryKey"`
	AgentID         string    `json:"agent_id" gorm:"not null;index"`
	EventID         string    `json:"event_id"`
	ProcessID       string    `json:"process_id"`
	ProcessName     string    `json:"process_name"`
	Protocol        string    `json:"protocol" gorm:"index"`
	SourceIP        string    `json:"source_ip" gorm:"index"`
	SourcePort      int       `json:"source_port"`
	DestinationIP   string    `json:"destination_ip" gorm:"index"`
	DestinationPort int       `json:"destination_port" gorm:"index"`
	Direction       string    `json:"direction"` // inbound, outbound
	Status          string    `json:"status"`    // established, closed, etc.
	BytesSent       int64     `json:"bytes_sent"`
	BytesReceived   int64     `json:"bytes_received"`
	Duration        int       `json:"duration_seconds"`
	Country         string    `json:"destination_country"`
	IsMalicious     bool      `json:"is_malicious" gorm:"default:false;index"`
	Timestamp       time.Time `json:"timestamp" gorm:"index"`
	CreatedAt       time.Time `json:"created_at"`

	// Relationships
	Agent OptimizedAgent `json:"agent" gorm:"foreignKey:AgentID"`
}

// FileOperation table for file system activity
type FileOperation struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	AgentID      string    `json:"agent_id" gorm:"not null;index"`
	EventID      string    `json:"event_id"`
	ProcessID    string    `json:"process_id"`
	ProcessName  string    `json:"process_name"`
	Operation    string    `json:"operation" gorm:"index"` // create, delete, modify, read, execute
	FilePath     string    `json:"file_path" gorm:"index"`
	FileName     string    `json:"file_name" gorm:"index"`
	FileSize     int64     `json:"file_size"`
	FileHash     string    `json:"file_hash" gorm:"index"`
	FileType     string    `json:"file_type"`
	Permissions  string    `json:"permissions"`
	Owner        string    `json:"owner"`
	IsSuspicious bool      `json:"is_suspicious" gorm:"default:false;index"`
	Timestamp    time.Time `json:"timestamp" gorm:"index"`
	CreatedAt    time.Time `json:"created_at"`

	// Relationships
	Agent OptimizedAgent `json:"agent" gorm:"foreignKey:AgentID"`
}

// RegistryOperation table for Windows registry changes
type RegistryOperation struct {
	ID            string    `json:"id" gorm:"primaryKey"`
	AgentID       string    `json:"agent_id" gorm:"not null;index"`
	EventID       string    `json:"event_id"`
	ProcessID     string    `json:"process_id"`
	ProcessName   string    `json:"process_name"`
	Operation     string    `json:"operation" gorm:"index"` // create, delete, modify, query
	KeyPath       string    `json:"key_path" gorm:"index"`
	ValueName     string    `json:"value_name"`
	ValueType     string    `json:"value_type"`
	ValueData     string    `json:"value_data"`
	OldValue      string    `json:"old_value"`
	IsPersistence bool      `json:"is_persistence" gorm:"default:false;index"`
	Timestamp     time.Time `json:"timestamp" gorm:"index"`
	CreatedAt     time.Time `json:"created_at"`

	// Relationships
	Agent OptimizedAgent `json:"agent" gorm:"foreignKey:AgentID"`
}

// UserActivity table for authentication and user actions
type UserActivity struct {
	ID            string    `json:"id" gorm:"primaryKey"`
	AgentID       string    `json:"agent_id" gorm:"not null;index"`
	EventID       string    `json:"event_id"`
	ActivityType  string    `json:"activity_type" gorm:"index"` // login, logout, failed_login, privilege_escalation
	Username      string    `json:"username" gorm:"index"`
	Domain        string    `json:"domain"`
	SourceIP      string    `json:"source_ip" gorm:"index"`
	LogonType     int       `json:"logon_type"`
	AuthMethod    string    `json:"auth_method"`
	SessionID     string    `json:"session_id"`
	FailureReason string    `json:"failure_reason"`
	IsPrivileged  bool      `json:"is_privileged" gorm:"default:false;index"`
	IsSuccessful  bool      `json:"is_successful" gorm:"index"`
	RiskScore     int       `json:"risk_score" gorm:"default:0"`
	Timestamp     time.Time `json:"timestamp" gorm:"index"`
	CreatedAt     time.Time `json:"created_at"`

	// Relationships
	Agent OptimizedAgent `json:"agent" gorm:"foreignKey:AgentID"`
}

// ThreatIntelligence table for IOC tracking
type ThreatIntelligence struct {
	ID          string         `json:"id" gorm:"primaryKey"`
	IOCType     string         `json:"ioc_type" gorm:"index"` // ip, domain, hash, url
	IOCValue    string         `json:"ioc_value" gorm:"uniqueIndex"`
	ThreatType  string         `json:"threat_type" gorm:"index"` // malware, phishing, c2, etc.
	Severity    string         `json:"severity" gorm:"index"`
	Source      string         `json:"source"`
	Description string         `json:"description"`
	References  pq.StringArray `json:"references" gorm:"type:text[]"`
	TTPs        pq.StringArray `json:"ttps" gorm:"type:text[]"` // MITRE ATT&CK TTPs
	IsActive    bool           `json:"is_active" gorm:"default:true;index"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// IOCMatch table for tracking when IOCs are detected
type IOCMatch struct {
	ID                   string    `json:"id" gorm:"primaryKey"`
	AgentID              string    `json:"agent_id" gorm:"not null;index"`
	ThreatIntelligenceID string    `json:"threat_intelligence_id" gorm:"not null;index"`
	EventID              string    `json:"event_id"`
	MatchType            string    `json:"match_type"`    // exact, fuzzy, regex
	MatchContext         string    `json:"match_context"` // where the IOC was found
	ConfidenceScore      float64   `json:"confidence_score"`
	Timestamp            time.Time `json:"timestamp" gorm:"index"`
	CreatedAt            time.Time `json:"created_at"`

	// Relationships
	Agent              OptimizedAgent     `json:"agent" gorm:"foreignKey:AgentID"`
	ThreatIntelligence ThreatIntelligence `json:"threat_intelligence" gorm:"foreignKey:ThreatIntelligenceID"`
}

// ConfigurationChange table for system configuration tracking
type ConfigurationChange struct {
	ID         string    `json:"id" gorm:"primaryKey"`
	AgentID    string    `json:"agent_id" gorm:"not null;index"`
	ChangeType string    `json:"change_type" gorm:"index"` // service, software, policy, etc.
	Component  string    `json:"component"`
	Action     string    `json:"action"` // install, uninstall, start, stop, modify
	OldValue   string    `json:"old_value"`
	NewValue   string    `json:"new_value"`
	ChangedBy  string    `json:"changed_by"`
	Source     string    `json:"source"` // manual, automatic, group_policy
	IsCritical bool      `json:"is_critical" gorm:"default:false;index"`
	Timestamp  time.Time `json:"timestamp" gorm:"index"`
	CreatedAt  time.Time `json:"created_at"`

	// Relationships
	Agent OptimizedAgent `json:"agent" gorm:"foreignKey:AgentID"`
}

// ============ ENHANCED EVENT MODEL ============

// OptimizedEvent with normalized fields instead of JSONB
type OptimizedEvent struct {
	ID            string `json:"id" gorm:"primaryKey"`
	AgentID       string `json:"agent_id" gorm:"not null;index"`
	EventType     string `json:"event_type" gorm:"index"`
	EventCategory string `json:"event_category" gorm:"index"` // process, network, file, registry, auth

	// Process Information
	ProcessID         string `json:"process_id" gorm:"index"`
	ProcessName       string `json:"process_name" gorm:"index"`
	ProcessPath       string `json:"process_path"`
	CommandLine       string `json:"command_line"`
	ParentProcessID   string `json:"parent_process_id"`
	ParentProcessName string `json:"parent_process_name"`
	UserName          string `json:"user_name" gorm:"index"`
	UserDomain        string `json:"user_domain"`

	// File Information
	FileName string `json:"file_name"`
	FilePath string `json:"file_path"`
	FileHash string `json:"file_hash" gorm:"index"`
	FileSize int64  `json:"file_size"`

	// Network Information
	SourceIP        string `json:"source_ip" gorm:"index"`
	SourcePort      int    `json:"source_port"`
	DestinationIP   string `json:"destination_ip" gorm:"index"`
	DestinationPort int    `json:"destination_port"`
	Protocol        string `json:"protocol"`

	// Additional Metadata (for complex data that needs JSONB)
	RawData JSONB `json:"raw_data" gorm:"type:jsonb"`

	// Classification
	Severity    int    `json:"severity" gorm:"default:1;index"`
	ThreatLevel string `json:"threat_level" gorm:"index"` // low, medium, high, critical
	IsAlerted   bool   `json:"is_alerted" gorm:"default:false;index"`

	// Timestamps
	Timestamp time.Time `json:"timestamp" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`

	// Relationships
	Agent OptimizedAgent `json:"agent" gorm:"foreignKey:AgentID"`
}

// Enhanced Alert with more metadata
type OptimizedAlert struct {
	ID          string `json:"id" gorm:"primaryKey"`
	Title       string `json:"title" gorm:"not null"`
	Description string `json:"description"`
	Severity    string `json:"severity" gorm:"index"`
	ThreatLevel string `json:"threat_level" gorm:"index"`
	Status      string `json:"status" gorm:"default:open;index"`

	// Rule Information
	RuleID   string `json:"rule_id" gorm:"index"`
	RuleName string `json:"rule_name" gorm:"index"`
	RuleType string `json:"rule_type"` // sigma, custom, ml

	// Agent and Event Info
	AgentID    string `json:"agent_id" gorm:"not null;index"`
	EventCount int    `json:"event_count" gorm:"default:1"`

	// Classification
	Tags       pq.StringArray `json:"tags" gorm:"type:text[]"`
	MITRE      pq.StringArray `json:"mitre" gorm:"type:text[]"`
	Tactics    pq.StringArray `json:"tactics" gorm:"type:text[]"`
	Techniques pq.StringArray `json:"techniques" gorm:"type:text[]"`

	// Investigation
	AssignedTo    string `json:"assigned_to"`
	Investigation string `json:"investigation"`
	Resolution    string `json:"resolution"`
	FalsePositive bool   `json:"false_positive" gorm:"default:false;index"`

	// Confidence and Risk
	ConfidenceScore float64 `json:"confidence_score"`
	RiskScore       int     `json:"risk_score"`

	// Timestamps
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	AcknowledgedAt *time.Time `json:"acknowledged_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`

	// Relationships
	Agent  OptimizedAgent   `json:"agent" gorm:"foreignKey:AgentID"`
	Events []OptimizedEvent `json:"events" gorm:"many2many:alert_events;"`
}

// UUID generation for all models
func (oa *OptimizedAgent) BeforeCreate(tx *gorm.DB) error {
	if oa.ID == "" {
		oa.ID = uuid.New().String()
	}
	return nil
}

func (nc *NetworkConnection) BeforeCreate(tx *gorm.DB) error {
	if nc.ID == "" {
		nc.ID = uuid.New().String()
	}
	return nil
}

func (fo *FileOperation) BeforeCreate(tx *gorm.DB) error {
	if fo.ID == "" {
		fo.ID = uuid.New().String()
	}
	return nil
}

func (ro *RegistryOperation) BeforeCreate(tx *gorm.DB) error {
	if ro.ID == "" {
		ro.ID = uuid.New().String()
	}
	return nil
}

func (ua *UserActivity) BeforeCreate(tx *gorm.DB) error {
	if ua.ID == "" {
		ua.ID = uuid.New().String()
	}
	return nil
}

func (ti *ThreatIntelligence) BeforeCreate(tx *gorm.DB) error {
	if ti.ID == "" {
		ti.ID = uuid.New().String()
	}
	return nil
}

func (im *IOCMatch) BeforeCreate(tx *gorm.DB) error {
	if im.ID == "" {
		im.ID = uuid.New().String()
	}
	return nil
}

func (cc *ConfigurationChange) BeforeCreate(tx *gorm.DB) error {
	if cc.ID == "" {
		cc.ID = uuid.New().String()
	}
	return nil
}

func (oe *OptimizedEvent) BeforeCreate(tx *gorm.DB) error {
	if oe.ID == "" {
		oe.ID = uuid.New().String()
	}
	return nil
}

func (oa *OptimizedAlert) BeforeCreate(tx *gorm.DB) error {
	if oa.ID == "" {
		oa.ID = uuid.New().String()
	}
	return nil
}
