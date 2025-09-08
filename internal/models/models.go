package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Agent đại diện cho một endpoint agent
type Agent struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	Hostname     string    `json:"hostname" gorm:"not null"`
	IPAddress    string    `json:"ip_address"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	AgentVersion string    `json:"agent_version"`
	Status       string    `json:"status" gorm:"default:active"` // active, inactive, offline
	LastSeen     time.Time `json:"last_seen"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// BeforeCreate tự động tạo UUID cho Agent
func (a *Agent) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return nil
}

// Event đại diện cho một log event từ endpoint
type Event struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	AgentID     string                 `json:"agent_id" gorm:"not null;index"`
	EventType   string                 `json:"event_type"` // process, network, file, registry, etc.
	EventData   map[string]interface{} `json:"event_data" gorm:"type:jsonb"`
	ProcessID   string                 `json:"process_id"`
	ProcessName string                 `json:"process_name"`
	CommandLine string                 `json:"command_line"`
	ParentPID   string                 `json:"parent_pid"`
	UserName    string                 `json:"user_name"`
	Hash        string                 `json:"hash"`
	Severity    int                    `json:"severity" gorm:"default:1"`
	Timestamp   time.Time              `json:"timestamp"`
	CreatedAt   time.Time              `json:"created_at"`

	// Relationships
	Agent  Agent   `json:"agent" gorm:"foreignKey:AgentID"`
	Alerts []Alert `json:"alerts" gorm:"many2many:alert_events;"`
}

// BeforeCreate tự động tạo UUID cho Event
func (e *Event) BeforeCreate(tx *gorm.DB) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	return nil
}

// Alert đại diện cho một cảnh báo được tạo từ Sigma rules
type Alert struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	Title       string    `json:"title" gorm:"not null"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`                   // low, medium, high, critical
	Status      string    `json:"status" gorm:"default:open"` // open, investigating, resolved, false_positive
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	AgentID     string    `json:"agent_id"`
	Tags        pq.StringArray `json:"tags" gorm:"type:text[]"`
	MITRE       pq.StringArray `json:"mitre" gorm:"type:text[]"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationships
	Events []Event `json:"events" gorm:"many2many:alert_events;"`
	Agent  Agent   `json:"agent" gorm:"foreignKey:AgentID"`
}

// BeforeCreate tự động tạo UUID cho Alert
func (a *Alert) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return nil
}

// Process đại diện cho thông tin process
type Process struct {
	ID          string     `json:"id" gorm:"primaryKey"`
	PID         string     `json:"pid" gorm:"not null"`
	ProcessName string     `json:"process_name"`
	CommandLine string     `json:"command_line"`
	ParentPID   string     `json:"parent_pid"`
	UserName    string     `json:"user_name"`
	Hash        string     `json:"hash"`
	StartTime   time.Time  `json:"start_time"`
	EndTime     *time.Time `json:"end_time"`
	AgentID     string     `json:"agent_id"`
	TreeID      string     `json:"tree_id"` // Reference to ProcessTree
	CreatedAt   time.Time  `json:"created_at"`

	// Relationships
	Agent       Agent       `json:"agent" gorm:"foreignKey:AgentID"`
	ProcessTree ProcessTree `json:"process_tree" gorm:"foreignKey:TreeID"`
	Children    []Process   `json:"children" gorm:"-"`
	Parent      *Process    `json:"parent" gorm:"-"`
}

// BeforeCreate tự động tạo UUID cho Process
func (p *Process) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}

// ProcessTree đại diện cho cây process
type ProcessTree struct {
	ID            string    `json:"id" gorm:"primaryKey"`
	RootProcessID string    `json:"root_process_id" gorm:"not null"`
	AgentID       string    `json:"agent_id"`
	Depth         int       `json:"depth"`
	ProcessCount  int       `json:"process_count"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`

	// Relationships
	Agent     Agent     `json:"agent" gorm:"foreignKey:AgentID"`
	Processes []Process `json:"processes" gorm:"foreignKey:TreeID"`
}

// BeforeCreate tự động tạo UUID cho ProcessTree
func (pt *ProcessTree) BeforeCreate(tx *gorm.DB) error {
	if pt.ID == "" {
		pt.ID = uuid.New().String()
	}
	return nil
}

// SigmaRule đại diện cho một Sigma rule
type SigmaRule struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Title       string                 `json:"title" gorm:"not null"`
	Description string                 `json:"description"`
	Author      string                 `json:"author"`
	References  []string               `json:"references" gorm:"type:text[]"`
	Tags        []string               `json:"tags" gorm:"type:text[]"`
	Logsource   map[string]interface{} `json:"logsource" gorm:"type:jsonb"`
	Detection   map[string]interface{} `json:"detection" gorm:"type:jsonb"`
	Level       string                 `json:"level"`  // low, medium, high, critical
	Status      string                 `json:"status"` // experimental, test, stable
	Date        string                 `json:"date"`
	Filename    string                 `json:"filename"`
	Enabled     bool                   `json:"enabled" gorm:"default:true"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// BeforeCreate tự động tạo UUID cho SigmaRule
func (sr *SigmaRule) BeforeCreate(tx *gorm.DB) error {
	if sr.ID == "" {
		sr.ID = uuid.New().String()
	}
	return nil
}

// Detection đại diện cho một detection match
type Detection struct {
	ID        string                 `json:"id" gorm:"primaryKey"`
	RuleID    string                 `json:"rule_id" gorm:"not null"`
	EventID   string                 `json:"event_id" gorm:"not null"`
	AgentID   string                 `json:"agent_id"`
	Matched   map[string]interface{} `json:"matched" gorm:"type:jsonb"`
	Score     float64                `json:"score"`
	CreatedAt time.Time              `json:"created_at"`

	// Relationships
	Rule  SigmaRule `json:"rule" gorm:"foreignKey:RuleID"`
	Event Event     `json:"event" gorm:"foreignKey:EventID"`
	Agent Agent     `json:"agent" gorm:"foreignKey:AgentID"`
}

// BeforeCreate tự động tạo UUID cho Detection
func (d *Detection) BeforeCreate(tx *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}
