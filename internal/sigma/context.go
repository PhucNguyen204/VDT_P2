package sigma

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Context-aware matching system based on cawalch/sigma-engine

// MatcherContext - Context for pattern matching with state preservation
type MatcherContext struct {
	// Core context
	EventID   string    `json:"event_id"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`

	// Event context
	EventType      string          `json:"event_type"`
	EventCategory  string          `json:"event_category"`
	ProcessContext *ProcessContext `json:"process_context,omitempty"`
	NetworkContext *NetworkContext `json:"network_context,omitempty"`
	FileContext    *FileContext    `json:"file_context,omitempty"`
	UserContext    *UserContext    `json:"user_context,omitempty"`

	// Matching context
	RuleChain    []string               `json:"rule_chain"`
	MatchHistory []*MatchRecord         `json:"match_history"`
	Variables    map[string]interface{} `json:"variables"`
	State        map[string]interface{} `json:"state"`

	// Performance context
	ExecutionDepth int      `json:"execution_depth"`
	CacheEnabled   bool     `json:"cache_enabled"`
	Optimizations  []string `json:"optimizations"`

	// Metadata
	Metadata map[string]string `json:"metadata"`
	Tags     []string          `json:"tags"`

	// Context control
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// ProcessContext - Process-related context information
type ProcessContext struct {
	ProcessID       int               `json:"process_id"`
	ParentProcessID int               `json:"parent_process_id"`
	ProcessName     string            `json:"process_name"`
	ProcessPath     string            `json:"process_path"`
	CommandLine     string            `json:"command_line"`
	User            string            `json:"user"`
	ProcessTree     []*ProcessInfo    `json:"process_tree,omitempty"`
	StartTime       time.Time         `json:"start_time"`
	Environment     map[string]string `json:"environment,omitempty"`
}

// NetworkContext - Network-related context information
type NetworkContext struct {
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      int    `json:"source_port"`
	DestinationPort int    `json:"destination_port"`
	Protocol        string `json:"protocol"`
	BytesSent       int64  `json:"bytes_sent"`
	BytesReceived   int64  `json:"bytes_received"`
	ConnectionState string `json:"connection_state"`
	Direction       string `json:"direction"`
}

// FileContext - File-related context information
type FileContext struct {
	FilePath     string    `json:"file_path"`
	FileName     string    `json:"file_name"`
	FileSize     int64     `json:"file_size"`
	FileHash     string    `json:"file_hash"`
	FileType     string    `json:"file_type"`
	Operation    string    `json:"operation"`
	Permissions  string    `json:"permissions"`
	CreatedTime  time.Time `json:"created_time"`
	ModifiedTime time.Time `json:"modified_time"`
	AccessedTime time.Time `json:"accessed_time"`
}

// UserContext - User-related context information
type UserContext struct {
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	Domain      string    `json:"domain"`
	Groups      []string  `json:"groups"`
	Privileges  []string  `json:"privileges"`
	SessionType string    `json:"session_type"`
	LoginTime   time.Time `json:"login_time"`
	LoginType   string    `json:"login_type"`
}

// ProcessInfo - Information about a process in the tree
type ProcessInfo struct {
	ProcessID       int            `json:"process_id"`
	ParentProcessID int            `json:"parent_process_id"`
	ProcessName     string         `json:"process_name"`
	ProcessPath     string         `json:"process_path"`
	StartTime       time.Time      `json:"start_time"`
	Children        []*ProcessInfo `json:"children,omitempty"`
}

// MatchRecord - Record of a pattern match
type MatchRecord struct {
	RuleID       string                 `json:"rule_id"`
	PatternID    string                 `json:"pattern_id"`
	MatchedValue interface{}            `json:"matched_value"`
	MatchType    string                 `json:"match_type"`
	Timestamp    time.Time              `json:"timestamp"`
	Confidence   float64                `json:"confidence"`
	Context      map[string]interface{} `json:"context"`
}

// ContextualMatcher - Matcher with context awareness
type ContextualMatcher struct {
	baseMatcher  *AdvancedMatcher
	contextStore *ContextStore
	stateManager *StateManager
	correlator   *EventCorrelator
	config       *ContextualMatcherConfig
	hooks        *HookManager
	metrics      *ContextualMatcherMetrics
	mu           sync.RWMutex
}

// ContextualMatcherConfig - Configuration for contextual matcher
type ContextualMatcherConfig struct {
	EnableStateTracking   bool          `json:"enable_state_tracking"`
	EnableCorrelation     bool          `json:"enable_correlation"`
	EnableProcessTree     bool          `json:"enable_process_tree"`
	EnableUserTracking    bool          `json:"enable_user_tracking"`
	EnableNetworkTracking bool          `json:"enable_network_tracking"`
	StateRetentionTime    time.Duration `json:"state_retention_time"`
	MaxContextDepth       int           `json:"max_context_depth"`
	MaxStateSize          int           `json:"max_state_size"`
	CorrelationWindowSize time.Duration `json:"correlation_window_size"`
}

// ContextualMatcherMetrics - Metrics for contextual matching
type ContextualMatcherMetrics struct {
	ContextsCreated     int64   `json:"contexts_created"`
	ContextsDestroyed   int64   `json:"contexts_destroyed"`
	StateUpdates        int64   `json:"state_updates"`
	CorrelationMatches  int64   `json:"correlation_matches"`
	ProcessTreeBuilds   int64   `json:"process_tree_builds"`
	AverageContextDepth float64 `json:"average_context_depth"`
	MemoryUsage         int64   `json:"memory_usage"`
	mu                  sync.RWMutex
}

// ContextStore - Store for maintaining context information
type ContextStore struct {
	contexts      map[string]*MatcherContext
	sessionIndex  map[string][]*MatcherContext
	agentIndex    map[string][]*MatcherContext
	timeIndex     map[int64][]*MatcherContext
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	retentionTime time.Duration
}

// StateManager - Manages state transitions and persistence
type StateManager struct {
	states      map[string]*ContextState
	transitions map[string]*StateTransition
	rules       []*StateRule
	persistence StatePersistence
	mu          sync.RWMutex
}

// ContextState - State information for context
type ContextState struct {
	StateID       string                 `json:"state_id"`
	ContextID     string                 `json:"context_id"`
	CurrentState  string                 `json:"current_state"`
	PreviousState string                 `json:"previous_state"`
	Variables     map[string]interface{} `json:"variables"`
	Timestamp     time.Time              `json:"timestamp"`
	TTL           time.Duration          `json:"ttl"`
	Metadata      map[string]string      `json:"metadata"`
}

// StateTransition - Defines state transition rules
type StateTransition struct {
	FromState string                 `json:"from_state"`
	ToState   string                 `json:"to_state"`
	Condition string                 `json:"condition"`
	Action    string                 `json:"action"`
	Variables map[string]interface{} `json:"variables"`
}

// StateRule - Rules for state management
type StateRule struct {
	RuleID       string             `json:"rule_id"`
	Pattern      string             `json:"pattern"`
	StateChanges []*StateTransition `json:"state_changes"`
	Conditions   []string           `json:"conditions"`
	Actions      []string           `json:"actions"`
}

// EventCorrelator - Correlates events across time and context
type EventCorrelator struct {
	correlationRules []*CorrelationRule
	timeWindows      map[string]*TimeWindow
	eventBuffer      *EventBuffer
	correlationIndex map[string][]*MatcherContext
	mu               sync.RWMutex
}

// CorrelationRule - Rule for event correlation
type CorrelationRule struct {
	RuleID      string        `json:"rule_id"`
	Pattern     string        `json:"pattern"`
	TimeWindow  time.Duration `json:"time_window"`
	MaxEvents   int           `json:"max_events"`
	GroupBy     []string      `json:"group_by"`
	Aggregation string        `json:"aggregation"`
	Threshold   interface{}   `json:"threshold"`
}

// TimeWindow - Time-based correlation window
type TimeWindow struct {
	Start  time.Time         `json:"start"`
	End    time.Time         `json:"end"`
	Events []*MatcherContext `json:"events"`
	Size   int               `json:"size"`
}

// EventBuffer - Buffer for event correlation
type EventBuffer struct {
	events       []*MatcherContext
	maxSize      int
	currentIndex int
	mu           sync.RWMutex
}

// StatePersistence - Interface for state persistence
type StatePersistence interface {
	SaveState(state *ContextState) error
	LoadState(stateID string) (*ContextState, error)
	DeleteState(stateID string) error
	ListStates(contextID string) ([]*ContextState, error)
}

// NewMatcherContext - Create new matcher context
func NewMatcherContext(eventID, sessionID, agentID string) *MatcherContext {
	ctx, cancel := context.WithCancel(context.Background())

	return &MatcherContext{
		EventID:       eventID,
		SessionID:     sessionID,
		AgentID:       agentID,
		Timestamp:     time.Now(),
		RuleChain:     make([]string, 0),
		MatchHistory:  make([]*MatchRecord, 0),
		Variables:     make(map[string]interface{}),
		State:         make(map[string]interface{}),
		Optimizations: make([]string, 0),
		Metadata:      make(map[string]string),
		Tags:          make([]string, 0),
		CacheEnabled:  true,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// NewContextualMatcher - Create new contextual matcher
func NewContextualMatcher(baseMatcher *AdvancedMatcher, config *ContextualMatcherConfig) *ContextualMatcher {
	if config == nil {
		config = DefaultContextualMatcherConfig()
	}

	return &ContextualMatcher{
		baseMatcher:  baseMatcher,
		contextStore: NewContextStore(config.StateRetentionTime),
		stateManager: NewStateManager(),
		correlator:   NewEventCorrelator(),
		config:       config,
		hooks:        NewHookManager(),
		metrics:      &ContextualMatcherMetrics{},
	}
}

// DefaultContextualMatcherConfig - Default configuration
func DefaultContextualMatcherConfig() *ContextualMatcherConfig {
	return &ContextualMatcherConfig{
		EnableStateTracking:   true,
		EnableCorrelation:     true,
		EnableProcessTree:     true,
		EnableUserTracking:    true,
		EnableNetworkTracking: true,
		StateRetentionTime:    24 * time.Hour,
		MaxContextDepth:       10,
		MaxStateSize:          1000,
		CorrelationWindowSize: 5 * time.Minute,
	}
}

// NewContextStore - Create new context store
func NewContextStore(retentionTime time.Duration) *ContextStore {
	store := &ContextStore{
		contexts:      make(map[string]*MatcherContext),
		sessionIndex:  make(map[string][]*MatcherContext),
		agentIndex:    make(map[string][]*MatcherContext),
		timeIndex:     make(map[int64][]*MatcherContext),
		retentionTime: retentionTime,
	}

	// Start cleanup routine
	store.cleanupTicker = time.NewTicker(time.Hour)
	go store.cleanupExpired()

	return store
}

// NewStateManager - Create new state manager
func NewStateManager() *StateManager {
	return &StateManager{
		states:      make(map[string]*ContextState),
		transitions: make(map[string]*StateTransition),
		rules:       make([]*StateRule, 0),
	}
}

// NewEventCorrelator - Create new event correlator
func NewEventCorrelator() *EventCorrelator {
	return &EventCorrelator{
		correlationRules: make([]*CorrelationRule, 0),
		timeWindows:      make(map[string]*TimeWindow),
		eventBuffer:      NewEventBuffer(10000),
		correlationIndex: make(map[string][]*MatcherContext),
	}
}

// NewEventBuffer - Create new event buffer
func NewEventBuffer(maxSize int) *EventBuffer {
	return &EventBuffer{
		events:  make([]*MatcherContext, maxSize),
		maxSize: maxSize,
	}
}

// Context store methods

// StoreContext - Store context in the store
func (cs *ContextStore) StoreContext(ctx *MatcherContext) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.contexts[ctx.EventID] = ctx

	// Update indexes
	cs.sessionIndex[ctx.SessionID] = append(cs.sessionIndex[ctx.SessionID], ctx)
	cs.agentIndex[ctx.AgentID] = append(cs.agentIndex[ctx.AgentID], ctx)

	timeKey := ctx.Timestamp.Unix() / 3600 // Hour-based indexing
	cs.timeIndex[timeKey] = append(cs.timeIndex[timeKey], ctx)
}

// GetContext - Get context by event ID
func (cs *ContextStore) GetContext(eventID string) (*MatcherContext, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	ctx, exists := cs.contexts[eventID]
	return ctx, exists
}

// GetContextsBySession - Get contexts by session ID
func (cs *ContextStore) GetContextsBySession(sessionID string) []*MatcherContext {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	contexts := cs.sessionIndex[sessionID]
	result := make([]*MatcherContext, len(contexts))
	copy(result, contexts)
	return result
}

// GetContextsByAgent - Get contexts by agent ID
func (cs *ContextStore) GetContextsByAgent(agentID string) []*MatcherContext {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	contexts := cs.agentIndex[agentID]
	result := make([]*MatcherContext, len(contexts))
	copy(result, contexts)
	return result
}

// cleanupExpired - Clean up expired contexts
func (cs *ContextStore) cleanupExpired() {
	for range cs.cleanupTicker.C {
		cs.mu.Lock()

		cutoff := time.Now().Add(-cs.retentionTime)

		for eventID, ctx := range cs.contexts {
			if ctx.Timestamp.Before(cutoff) {
				delete(cs.contexts, eventID)
				cs.removeFromIndexes(ctx)
			}
		}

		cs.mu.Unlock()
	}
}

// removeFromIndexes - Remove context from all indexes
func (cs *ContextStore) removeFromIndexes(ctx *MatcherContext) {
	// Remove from session index
	if sessions, exists := cs.sessionIndex[ctx.SessionID]; exists {
		for i, c := range sessions {
			if c.EventID == ctx.EventID {
				cs.sessionIndex[ctx.SessionID] = append(sessions[:i], sessions[i+1:]...)
				break
			}
		}
	}

	// Remove from agent index
	if agents, exists := cs.agentIndex[ctx.AgentID]; exists {
		for i, c := range agents {
			if c.EventID == ctx.EventID {
				cs.agentIndex[ctx.AgentID] = append(agents[:i], agents[i+1:]...)
				break
			}
		}
	}

	// Remove from time index
	timeKey := ctx.Timestamp.Unix() / 3600
	if times, exists := cs.timeIndex[timeKey]; exists {
		for i, c := range times {
			if c.EventID == ctx.EventID {
				cs.timeIndex[timeKey] = append(times[:i], times[i+1:]...)
				break
			}
		}
	}
}

// Context methods

// SetVariable - Set variable in context
func (mc *MatcherContext) SetVariable(key string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.Variables[key] = value
}

// GetVariable - Get variable from context
func (mc *MatcherContext) GetVariable(key string) (interface{}, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	value, exists := mc.Variables[key]
	return value, exists
}

// SetState - Set state in context
func (mc *MatcherContext) SetState(key string, value interface{}) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.State[key] = value
}

// GetState - Get state from context
func (mc *MatcherContext) GetState(key string) (interface{}, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	value, exists := mc.State[key]
	return value, exists
}

// AddMatchRecord - Add match record to history
func (mc *MatcherContext) AddMatchRecord(record *MatchRecord) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.MatchHistory = append(mc.MatchHistory, record)
}

// GetMatchHistory - Get match history
func (mc *MatcherContext) GetMatchHistory() []*MatchRecord {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	history := make([]*MatchRecord, len(mc.MatchHistory))
	copy(history, mc.MatchHistory)
	return history
}

// AddRuleToChain - Add rule to execution chain
func (mc *MatcherContext) AddRuleToChain(ruleID string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.RuleChain = append(mc.RuleChain, ruleID)
}

// IsInRuleChain - Check if rule is in execution chain
func (mc *MatcherContext) IsInRuleChain(ruleID string) bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	for _, id := range mc.RuleChain {
		if id == ruleID {
			return true
		}
	}
	return false
}

// Context - Get underlying context
func (mc *MatcherContext) Context() context.Context {
	return mc.ctx
}

// Cancel - Cancel context
func (mc *MatcherContext) Cancel() {
	if mc.cancel != nil {
		mc.cancel()
	}
}

// Clone - Create a copy of the context
func (mc *MatcherContext) Clone() *MatcherContext {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	clone := &MatcherContext{
		EventID:        mc.EventID + "_clone",
		SessionID:      mc.SessionID,
		AgentID:        mc.AgentID,
		Timestamp:      time.Now(),
		EventType:      mc.EventType,
		EventCategory:  mc.EventCategory,
		ExecutionDepth: mc.ExecutionDepth + 1,
		CacheEnabled:   mc.CacheEnabled,
		Variables:      make(map[string]interface{}),
		State:          make(map[string]interface{}),
		Metadata:       make(map[string]string),
		Tags:           make([]string, len(mc.Tags)),
		RuleChain:      make([]string, len(mc.RuleChain)),
		MatchHistory:   make([]*MatchRecord, len(mc.MatchHistory)),
		Optimizations:  make([]string, len(mc.Optimizations)),
	}

	// Copy maps and slices
	for k, v := range mc.Variables {
		clone.Variables[k] = v
	}
	for k, v := range mc.State {
		clone.State[k] = v
	}
	for k, v := range mc.Metadata {
		clone.Metadata[k] = v
	}
	copy(clone.Tags, mc.Tags)
	copy(clone.RuleChain, mc.RuleChain)
	copy(clone.MatchHistory, mc.MatchHistory)
	copy(clone.Optimizations, mc.Optimizations)

	// Copy context structures if they exist
	if mc.ProcessContext != nil {
		clone.ProcessContext = &ProcessContext{}
		*clone.ProcessContext = *mc.ProcessContext
	}
	if mc.NetworkContext != nil {
		clone.NetworkContext = &NetworkContext{}
		*clone.NetworkContext = *mc.NetworkContext
	}
	if mc.FileContext != nil {
		clone.FileContext = &FileContext{}
		*clone.FileContext = *mc.FileContext
	}
	if mc.UserContext != nil {
		clone.UserContext = &UserContext{}
		*clone.UserContext = *mc.UserContext
	}

	ctx, cancel := context.WithCancel(context.Background())
	clone.ctx = ctx
	clone.cancel = cancel

	return clone
}

// String - String representation for debugging
func (mc *MatcherContext) String() string {
	return fmt.Sprintf("MatcherContext{EventID: %s, SessionID: %s, AgentID: %s, Timestamp: %v}",
		mc.EventID, mc.SessionID, mc.AgentID, mc.Timestamp)
}
