package sigma

import (
	"sync"
	"time"
)

// NodeType định nghĩa các loại DAG nodes
type NodeType string

const (
	NodeTypeAnd       NodeType = "and"
	NodeTypeOr        NodeType = "or"
	NodeTypeNot       NodeType = "not"
	NodeTypePrimitive NodeType = "primitive"
	NodeTypeShared    NodeType = "shared"
)

// PrimitiveType định nghĩa các loại primitive operations
type PrimitiveType string

const (
	PrimitiveEquals     PrimitiveType = "equals"
	PrimitiveContains   PrimitiveType = "contains"
	PrimitiveStartsWith PrimitiveType = "startswith"
	PrimitiveEndsWith   PrimitiveType = "endswith"
	PrimitiveRegex      PrimitiveType = "regex"
	PrimitiveIn         PrimitiveType = "in"
	PrimitiveGreater    PrimitiveType = "greater"
	PrimitiveLess       PrimitiveType = "less"
	PrimitiveExists     PrimitiveType = "exists"
)

// CompilationPhase định nghĩa các phase của compilation
type CompilationPhase string

const (
	PhaseParseYAML    CompilationPhase = "parse_yaml"
	PhaseValidation   CompilationPhase = "validation"
	PhaseOptimization CompilationPhase = "optimization"
	PhaseDAGBuild     CompilationPhase = "dag_build"
	PhasePrefilter    CompilationPhase = "prefilter"
)

// EventContext context cho event evaluation
type EventContext struct {
	Event          map[string]interface{} `json:"event"`
	Timestamp      time.Time              `json:"timestamp"`
	Source         string                 `json:"source"`
	ProcessedBy    string                 `json:"processed_by"`
	CorrelationID  string                 `json:"correlation_id"`
	Priority       int                    `json:"priority"`
	Metadata       map[string]interface{} `json:"metadata"`
	CacheEnabled   bool                   `json:"cache_enabled"`
	TracingEnabled bool                   `json:"tracing_enabled"`
}

// ExecutionContext context cho DAG execution
type ExecutionContext struct {
	Event       map[string]interface{} `json:"event"`
	Cache       map[string]interface{} `json:"cache"`
	SharedState map[string]interface{} `json:"shared_state"`
	Results     map[string]bool        `json:"results"`
	StartTime   time.Time              `json:"start_time"`
	Timeout     time.Duration          `json:"timeout"`
	TraceID     string                 `json:"trace_id"`
	Depth       int                    `json:"depth"`
	MaxDepth    int                    `json:"max_depth"`
	NodesRan    int                    `json:"nodes_ran"`
	SharedHits  int                    `json:"shared_hits"`
}

// MatchConfidence độ tin cậy của match
type MatchConfidence float64

const (
	ConfidenceLow    MatchConfidence = 0.3
	ConfidenceMedium MatchConfidence = 0.6
	ConfidenceHigh   MatchConfidence = 0.8
	ConfidenceMax    MatchConfidence = 1.0
)

// RuleLevel mức độ rule
type RuleLevel string

const (
	LevelLow      RuleLevel = "low"
	LevelMedium   RuleLevel = "medium"
	LevelHigh     RuleLevel = "high"
	LevelCritical RuleLevel = "critical"
)

// RuleStatus trạng thái rule
type RuleStatus string

const (
	StatusStable       RuleStatus = "stable"
	StatusTest         RuleStatus = "test"
	StatusExperimental RuleStatus = "experimental"
	StatusDeprecated   RuleStatus = "deprecated"
)

// FieldType loại field trong event
type FieldType string

const (
	FieldTypeString FieldType = "string"
	FieldTypeInt    FieldType = "int"
	FieldTypeFloat  FieldType = "float"
	FieldTypeBool   FieldType = "bool"
	FieldTypeIP     FieldType = "ip"
	FieldTypeTime   FieldType = "time"
	FieldTypeArray  FieldType = "array"
	FieldTypeObject FieldType = "object"
)

// EngineMode chế độ hoạt động của engine
type EngineMode string

const (
	ModeRealtime  EngineMode = "realtime"
	ModeBatch     EngineMode = "batch"
	ModeStreaming EngineMode = "streaming"
	ModeAnalysis  EngineMode = "analysis"
)

// OptimizationStrategy chiến lược optimization
type OptimizationStrategy string

const (
	StrategyNone       OptimizationStrategy = "none"
	StrategyBasic      OptimizationStrategy = "basic"
	StrategyAggressive OptimizationStrategy = "aggressive"
	StrategyCustom     OptimizationStrategy = "custom"
)

// ProcessingPriority độ ưu tiên processing
type ProcessingPriority int

const (
	PriorityLow      ProcessingPriority = 1
	PriorityNormal   ProcessingPriority = 5
	PriorityHigh     ProcessingPriority = 8
	PriorityCritical ProcessingPriority = 10
)

// CacheStrategy chiến lược cache
type CacheStrategy string

const (
	CacheNone     CacheStrategy = "none"
	CacheLRU      CacheStrategy = "lru"
	CacheTTL      CacheStrategy = "ttl"
	CacheAdaptive CacheStrategy = "adaptive"
)

// StreamingMode chế độ streaming
type StreamingMode string

const (
	StreamingPush   StreamingMode = "push"
	StreamingPull   StreamingMode = "pull"
	StreamingHybrid StreamingMode = "hybrid"
)

// BackpressureStrategy chiến lược backpressure
type BackpressureStrategy string

const (
	BackpressureDrop     BackpressureStrategy = "drop"
	BackpressureBuffer   BackpressureStrategy = "buffer"
	BackpressureThrottle BackpressureStrategy = "throttle"
	BackpressureBlock    BackpressureStrategy = "block"
	BackpressureAdaptive BackpressureStrategy = "adaptive"
)

// DetectionResult kết quả detection tổng hợp
type DetectionResult struct {
	RuleMatches     []*RuleMatch           `json:"rule_matches"`
	TotalMatches    int                    `json:"total_matches"`
	HighestSeverity RuleLevel              `json:"highest_severity"`
	ProcessingTime  time.Duration          `json:"processing_time"`
	EventContext    *EventContext          `json:"event_context"`
	Metadata        map[string]interface{} `json:"metadata"`
	Alerts          []*Alert               `json:"alerts"`
	Confidence      MatchConfidence        `json:"confidence"`
	Priority        ProcessingPriority     `json:"priority"`
}

// Alert thông tin cảnh báo
type Alert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Rule        *RuleMatch             `json:"rule"`
	Event       map[string]interface{} `json:"event"`
	Severity    RuleLevel              `json:"severity"`
	Description string                 `json:"description"`
	MITRE       []string               `json:"mitre"`
	Context     *EventContext          `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PerformanceMetrics metrics chi tiết cho performance
type PerformanceMetrics struct {
	// Compilation metrics
	CompilationTime   time.Duration `json:"compilation_time"`
	RulesCompiled     int           `json:"rules_compiled"`
	CompilationErrors int           `json:"compilation_errors"`
	OptimizationTime  time.Duration `json:"optimization_time"`

	// Runtime metrics
	EventsProcessed int64         `json:"events_processed"`
	AverageLatency  time.Duration `json:"average_latency"`
	P50Latency      time.Duration `json:"p50_latency"`
	P95Latency      time.Duration `json:"p95_latency"`
	P99Latency      time.Duration `json:"p99_latency"`
	EventsPerSecond float64       `json:"events_per_second"`

	// Detection metrics
	TotalMatches      int64   `json:"total_matches"`
	MatchRate         float64 `json:"match_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`

	// Resource metrics
	MemoryUsage int64   `json:"memory_usage"`
	CPUUsage    float64 `json:"cpu_usage"`

	// Optimization metrics
	NodesOptimized      int     `json:"nodes_optimized"`
	SharedComputations  int64   `json:"shared_computations"`
	CacheHitRate        float64 `json:"cache_hit_rate"`
	PrefilterEfficiency float64 `json:"prefilter_efficiency"`
}

// StreamingMetrics metrics cho streaming processing
type StreamingMetrics struct {
	// Throughput metrics
	MessagesReceived  int64   `json:"messages_received"`
	MessagesProcessed int64   `json:"messages_processed"`
	MessagesDropped   int64   `json:"messages_dropped"`
	ProcessingRate    float64 `json:"processing_rate"`

	// Latency metrics
	InputLatency      time.Duration `json:"input_latency"`
	ProcessingLatency time.Duration `json:"processing_latency"`
	OutputLatency     time.Duration `json:"output_latency"`
	EndToEndLatency   time.Duration `json:"end_to_end_latency"`

	// Backpressure metrics
	BackpressureEvents int64   `json:"backpressure_events"`
	BufferUtilization  float64 `json:"buffer_utilization"`
	ThrottleEvents     int64   `json:"throttle_events"`

	// Error metrics
	ProcessingErrors int64 `json:"processing_errors"`
	ConnectionErrors int64 `json:"connection_errors"`
	TimeoutErrors    int64 `json:"timeout_errors"`

	// Synchronization
	mu sync.RWMutex
}

// ErrorInfo thông tin lỗi chi tiết
type ErrorInfo struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Component   string                 `json:"component"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
	Severity    string                 `json:"severity"`
	Recoverable bool                   `json:"recoverable"`
}

// Additional types for enhanced architecture

// DAGNode represents a node in the DAG structure
type DAGNode struct {
	ID          string                 `json:"id"`
	Type        DAGNodeType            `json:"type"`
	Operation   DAGOperation           `json:"operation,omitempty"`
	Primitive   *Primitive             `json:"primitive,omitempty"`
	Children    []*DAGNode             `json:"children,omitempty"`
	Parent      *DAGNode               `json:"parent,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Hash        uint64                 `json:"hash"`
	SharedCount int                    `json:"shared_count"`
	Optimized   bool                   `json:"optimized"`
}

// DAGNodeType represents the type of a DAG node
type DAGNodeType string

const (
	NodePrimitive DAGNodeType = "primitive"
	NodeAnd       DAGNodeType = "and"
	NodeOr        DAGNodeType = "or"
	NodeNot       DAGNodeType = "not"
	NodeRoot      DAGNodeType = "root"
)

// DAGOperation represents operations in the DAG
type DAGOperation string

const (
	OpAnd   DAGOperation = "and"
	OpOr    DAGOperation = "or"
	OpNot   DAGOperation = "not"
	OpGroup DAGOperation = "group"
)

// Primitive represents a primitive matching operation
type Primitive struct {
	ID       string                 `json:"id"`
	Type     PrimitiveType          `json:"type"`
	Field    string                 `json:"field"`
	Value    interface{}            `json:"value"`
	Modifier string                 `json:"modifier,omitempty"`
	Negated  bool                   `json:"negated"`
	Pattern  string                 `json:"pattern,omitempty"`
	Literals []string               `json:"literals,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CompiledRule represents a compiled SIGMA rule
type CompiledRule struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Level       string                 `json:"level"`
	Tags        []string               `json:"tags"`
	LogSource   map[string]string      `json:"logsource"`
	Detection   map[string]interface{} `json:"detection"`
	RootNode    *DAGNode               `json:"root_node"`
	Primitives  []*Primitive           `json:"primitives"`
	Hash        uint64                 `json:"hash"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// RuleMatch represents a rule that matched an event
type RuleMatch struct {
	RuleID       string                 `json:"rule_id"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Level        string                 `json:"level"`
	Tags         []string               `json:"tags"`
	MatchedNodes []string               `json:"matched_nodes"`
	Confidence   float64                `json:"confidence"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// StreamingEvent represents an event to be processed by the streaming engine
type StreamingEvent struct {
	EventID     string                 `json:"event_id"`
	Data        map[string]interface{} `json:"data"`
	Timestamp   time.Time              `json:"timestamp"`
	Priority    int                    `json:"priority"`
	Context     string                 `json:"context,omitempty"`
	Metadata    map[string]string      `json:"metadata"`
	RetryCount  int                    `json:"retry_count"`
	ProcessedAt time.Time              `json:"processed_at"`
}

// StreamingResult represents the result of streaming processing
type StreamingResult struct {
	EventID        string             `json:"event_id"`
	Results        []*DetectionResult `json:"results"`
	Timestamp      time.Time          `json:"timestamp"`
	ProcessingTime time.Duration      `json:"processing_time"`
	Error          error              `json:"error,omitempty"`
}

// WorkerBatch represents a batch of work for workers
type WorkerBatch struct {
	Events    []*StreamingEvent `json:"events"`
	BatchID   string            `json:"batch_id"`
	Priority  int               `json:"priority"`
	Timestamp time.Time         `json:"timestamp"`
}

// SharedNode represents a shared DAG node
type SharedNode struct {
	Node     *DAGNode  `json:"node"`
	RuleIDs  []string  `json:"rule_ids"`
	UseCount int       `json:"use_count"`
	LastUsed time.Time `json:"last_used"`
}

// EngineConfig configuration for the SIGMA engine
type EngineConfig struct {
	EnableOptimization       bool          `json:"enable_optimization"`
	EnableParallelProcessing bool          `json:"enable_parallel_processing"`
	EnablePrefilter          bool          `json:"enable_prefilter"`
	EnableSharedComputation  bool          `json:"enable_shared_computation"`
	EnableIR                 bool          `json:"enable_ir"`
	BatchSize                int           `json:"batch_size"`
	WorkerCount              int           `json:"worker_count"`
	PrefilterMinLength       int           `json:"prefilter_min_length"`
	CacheSize                int           `json:"cache_size"`
	Timeout                  time.Duration `json:"timeout"`
	MaxRules                 int           `json:"max_rules"`
	CompilationMode          string        `json:"compilation_mode"`
}

// Placeholder types for components that need full implementation
type Compiler struct{}
type DAGEngine struct{}
type AhoCorasickPrefilter struct{}
type FieldMapper struct {
	mappings map[string]string
}
type StreamingEngine struct{}
type DAGOptimizer struct{}
type AdvancedMatcher struct{}
type Profiler struct{}
type WorkerPool struct{}
type BatchProcessor struct{}
type MatcherCache struct{}
type MatcherHook interface{}
type ModifierFunc func(interface{}) interface{}
type MatcherContext struct{}
type BackpressureManager struct{}
type AdaptiveBatcher struct{}
type ErrorHandler interface{}
type Config struct{}
type StreamingConfig struct{}
type ProfilingConfig struct{}
type MatcherConfig struct{}
type DAGConfig struct{}

// EvaluationResult represents the result of evaluating events
type EvaluationResult struct {
	EventIdx       int           `json:"event_idx"`
	MatchedRules   []*RuleMatch  `json:"matched_rules"`
	ProcessingTime time.Duration `json:"processing_time"`
	Error          error         `json:"error,omitempty"`
}
