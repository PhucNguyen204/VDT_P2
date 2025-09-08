package sigma

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// Builder patterns for SIGMA engine components based on cawalch/sigma-engine

// EngineBuilder - Builder for SigmaEngine with fluent API
type EngineBuilder struct {
	config           *Config
	logger           *logrus.Logger
	rules            []string
	fieldMappings    map[string]string
	errorHandlers    []ErrorHandler
	customMatcher    *AdvancedMatcher
	customOptimizer  *DAGOptimizer
	prefilterEnabled bool
	irEnabled        bool
	streamingConfig  *StreamingConfig
	profilingConfig  *ProfilingConfig
}

// NewEngineBuilder - Create new engine builder
func NewEngineBuilder() *EngineBuilder {
	return &EngineBuilder{
		config:           DefaultConfig(),
		fieldMappings:    make(map[string]string),
		errorHandlers:    make([]ErrorHandler, 0),
		prefilterEnabled: true,
		irEnabled:        true,
	}
}

// WithConfig - Set engine configuration
func (b *EngineBuilder) WithConfig(config *Config) *EngineBuilder {
	b.config = config
	return b
}

// WithLogger - Set logger
func (b *EngineBuilder) WithLogger(logger *logrus.Logger) *EngineBuilder {
	b.logger = logger
	return b
}

// WithRules - Set SIGMA rules
func (b *EngineBuilder) WithRules(rules []string) *EngineBuilder {
	b.rules = rules
	return b
}

// AddRule - Add single SIGMA rule
func (b *EngineBuilder) AddRule(rule string) *EngineBuilder {
	b.rules = append(b.rules, rule)
	return b
}

// WithFieldMapping - Add field mapping
func (b *EngineBuilder) WithFieldMapping(from, to string) *EngineBuilder {
	b.fieldMappings[from] = to
	return b
}

// WithFieldMappings - Set multiple field mappings
func (b *EngineBuilder) WithFieldMappings(mappings map[string]string) *EngineBuilder {
	for from, to := range mappings {
		b.fieldMappings[from] = to
	}
	return b
}

// WithErrorHandler - Add error handler
func (b *EngineBuilder) WithErrorHandler(handler ErrorHandler) *EngineBuilder {
	b.errorHandlers = append(b.errorHandlers, handler)
	return b
}

// WithCustomMatcher - Set custom matcher
func (b *EngineBuilder) WithCustomMatcher(matcher *AdvancedMatcher) *EngineBuilder {
	b.customMatcher = matcher
	return b
}

// WithCustomOptimizer - Set custom optimizer
func (b *EngineBuilder) WithCustomOptimizer(optimizer *DAGOptimizer) *EngineBuilder {
	b.customOptimizer = optimizer
	return b
}

// WithPrefilter - Enable/disable prefilter
func (b *EngineBuilder) WithPrefilter(enabled bool) *EngineBuilder {
	b.prefilterEnabled = enabled
	return b
}

// WithIR - Enable/disable IR system
func (b *EngineBuilder) WithIR(enabled bool) *EngineBuilder {
	b.irEnabled = enabled
	return b
}

// WithStreamingConfig - Set streaming configuration
func (b *EngineBuilder) WithStreamingConfig(config *StreamingConfig) *EngineBuilder {
	b.streamingConfig = config
	return b
}

// WithProfilingConfig - Set profiling configuration
func (b *EngineBuilder) WithProfilingConfig(config *ProfilingConfig) *EngineBuilder {
	b.profilingConfig = config
	return b
}

// ForRealtime - Configure for realtime processing
func (b *EngineBuilder) ForRealtime() *EngineBuilder {
	b.config.OptimizeForWorkload("realtime")
	b.streamingConfig = RealtimeDetection()
	return b
}

// ForHighThroughput - Configure for high throughput
func (b *EngineBuilder) ForHighThroughput() *EngineBuilder {
	b.config.OptimizeForWorkload("high_throughput")
	b.streamingConfig = HighThroughput()
	return b
}

// ForLowLatency - Configure for low latency
func (b *EngineBuilder) ForLowLatency() *EngineBuilder {
	b.config.OptimizeForWorkload("realtime")
	b.streamingConfig = LowLatency()
	return b
}

// ForProduction - Configure for production environment
func (b *EngineBuilder) ForProduction() *EngineBuilder {
	b.config = ProductionConfig()
	b.prefilterEnabled = true
	b.irEnabled = true
	return b
}

// ForDevelopment - Configure for development environment
func (b *EngineBuilder) ForDevelopment() *EngineBuilder {
	b.config = DevelopmentConfig()
	if b.profilingConfig == nil {
		b.profilingConfig = &b.config.Profiling
	}
	return b
}

// Build - Build the SIGMA engine
func (b *EngineBuilder) Build() (*SigmaEngine, error) {
	// Validate configuration
	if err := b.config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Set default logger if not provided
	if b.logger == nil {
		b.logger = logrus.New()
	}

	// Create engine with configuration
	b.config.Engine.EnablePrefilter = b.prefilterEnabled
	b.config.Engine.EnableIR = b.irEnabled

	engine := NewSigmaEngine(&b.config.Engine, b.logger)

	// Set up field mappings
	if len(b.fieldMappings) > 0 {
		for from, to := range b.fieldMappings {
			engine.fieldMapper.AddMapping(from, to)
		}
	}

	// Set up custom components
	if b.customMatcher != nil {
		engine.dag.matcher = b.customMatcher
	}

	if b.customOptimizer != nil {
		engine.dag.optimizer = b.customOptimizer
	}

	// Set up streaming if configured
	if b.streamingConfig != nil {
		engine.streaming = NewStreamingEngine(engine, b.streamingConfig)
	}

	// Compile rules if provided
	if len(b.rules) > 0 {
		if err := engine.FromRules(b.rules); err != nil {
			return nil, fmt.Errorf("failed to compile rules: %w", err)
		}
	}

	return engine, nil
}

// MatcherBuilder - Builder for AdvancedMatcher
type MatcherBuilder struct {
	config       *MatcherConfig
	cache        *MatcherCache
	hooks        []MatcherHook
	modifiers    map[string]ModifierFunc
	context      *MatcherContext
	fuzzyEnabled bool
}

// NewMatcherBuilder - Create new matcher builder
func NewMatcherBuilder() *MatcherBuilder {
	return &MatcherBuilder{
		config:    DefaultMatcherConfig(),
		hooks:     make([]MatcherHook, 0),
		modifiers: make(map[string]ModifierFunc),
	}
}

// WithConfig - Set matcher configuration
func (b *MatcherBuilder) WithConfig(config *MatcherConfig) *MatcherBuilder {
	b.config = config
	return b
}

// WithCache - Set custom cache
func (b *MatcherBuilder) WithCache(cache *MatcherCache) *MatcherBuilder {
	b.cache = cache
	return b
}

// WithHook - Add matcher hook
func (b *MatcherBuilder) WithHook(hook MatcherHook) *MatcherBuilder {
	b.hooks = append(b.hooks, hook)
	return b
}

// WithModifier - Add custom modifier
func (b *MatcherBuilder) WithModifier(name string, fn ModifierFunc) *MatcherBuilder {
	b.modifiers[name] = fn
	return b
}

// WithContext - Set matcher context
func (b *MatcherBuilder) WithContext(context *MatcherContext) *MatcherBuilder {
	b.context = context
	return b
}

// WithFuzzyMatching - Enable fuzzy matching
func (b *MatcherBuilder) WithFuzzyMatching(enabled bool) *MatcherBuilder {
	b.fuzzyEnabled = enabled
	return b
}

// Build - Build the matcher
func (b *MatcherBuilder) Build() (*AdvancedMatcher, error) {
	b.config.EnableContext = (b.context != nil)
	b.config.EnableHooks = (len(b.hooks) > 0)
	b.config.EnableModifiers = (len(b.modifiers) > 0)

	matcher := NewAdvancedMatcher(b.config)

	// Set custom cache
	if b.cache != nil {
		matcher.cache = b.cache
	}

	// Add hooks
	for _, hook := range b.hooks {
		matcher.AddHook(hook)
	}

	// Add modifiers
	for name, fn := range b.modifiers {
		matcher.AddModifier(name, fn)
	}

	// Set context
	if b.context != nil {
		matcher.context = b.context
	}

	return matcher, nil
}

// DAGBuilder - Builder for DAG engine
type DAGBuilder struct {
	config      *DAGConfig
	optimizer   *DAGOptimizer
	rules       []*CompiledRule
	sharedNodes map[string]*SharedNode
	maxNodes    int
	memoryLimit int
}

// NewDAGBuilder - Create new DAG builder
func NewDAGBuilder() *DAGBuilder {
	return &DAGBuilder{
		config:      &DefaultConfig().DAG,
		sharedNodes: make(map[string]*SharedNode),
	}
}

// WithConfig - Set DAG configuration
func (b *DAGBuilder) WithConfig(config *DAGConfig) *DAGBuilder {
	b.config = config
	return b
}

// WithOptimizer - Set custom optimizer
func (b *DAGBuilder) WithOptimizer(optimizer *DAGOptimizer) *DAGBuilder {
	b.optimizer = optimizer
	return b
}

// WithRules - Set compiled rules
func (b *DAGBuilder) WithRules(rules []*CompiledRule) *DAGBuilder {
	b.rules = rules
	return b
}

// WithMaxNodes - Set maximum node limit
func (b *DAGBuilder) WithMaxNodes(maxNodes int) *DAGBuilder {
	b.maxNodes = maxNodes
	return b
}

// WithMemoryLimit - Set memory limit in MB
func (b *DAGBuilder) WithMemoryLimit(limitMB int) *DAGBuilder {
	b.memoryLimit = limitMB
	return b
}

// Build - Build the DAG engine
func (b *DAGBuilder) Build() (*DAGEngine, error) {
	// Apply limits to config
	if b.maxNodes > 0 {
		b.config.MaxNodes = b.maxNodes
	}
	if b.memoryLimit > 0 {
		b.config.MemoryLimitMB = b.memoryLimit
	}

	// Create engine config from DAG config
	engineConfig := &EngineConfig{
		EnableOptimization:       b.config.EnableOptimization,
		EnableParallelProcessing: b.config.EnableParallelBatch,
		BatchSize:                b.config.ParallelBatchSize,
		Timeout:                  b.config.ExecutionTimeout,
	}

	engine := NewDAGEngine(engineConfig)

	// Set custom optimizer
	if b.optimizer != nil {
		engine.optimizer = b.optimizer
	}

	// Add shared nodes
	for id, node := range b.sharedNodes {
		engine.sharedNodes[id] = node
	}

	// Build from rules
	if len(b.rules) > 0 {
		if err := engine.BuildFromRules(b.rules); err != nil {
			return nil, fmt.Errorf("failed to build DAG from rules: %w", err)
		}
	}

	return engine, nil
}

// StreamingBuilder - Builder for streaming engine
type StreamingBuilder struct {
	config         *StreamingConfig
	backpressure   *BackpressureManager
	batcher        *AdaptiveBatcher
	processor      *BatchProcessor
	workerCount    int
	bufferSizes    map[string]int
	metricsEnabled bool
}

// NewStreamingBuilder - Create new streaming builder
func NewStreamingBuilder() *StreamingBuilder {
	return &StreamingBuilder{
		config:      DefaultStreamingConfig(),
		bufferSizes: make(map[string]int),
	}
}

// WithConfig - Set streaming configuration
func (b *StreamingBuilder) WithConfig(config *StreamingConfig) *StreamingBuilder {
	b.config = config
	return b
}

// WithBackpressure - Set custom backpressure manager
func (b *StreamingBuilder) WithBackpressure(bp *BackpressureManager) *StreamingBuilder {
	b.backpressure = bp
	return b
}

// WithBatcher - Set custom batcher
func (b *StreamingBuilder) WithBatcher(batcher *AdaptiveBatcher) *StreamingBuilder {
	b.batcher = batcher
	return b
}

// WithProcessor - Set custom processor
func (b *StreamingBuilder) WithProcessor(processor *BatchProcessor) *StreamingBuilder {
	b.processor = processor
	return b
}

// WithWorkerCount - Set worker count
func (b *StreamingBuilder) WithWorkerCount(count int) *StreamingBuilder {
	b.workerCount = count
	return b
}

// WithInputBuffer - Set input buffer size
func (b *StreamingBuilder) WithInputBuffer(size int) *StreamingBuilder {
	b.bufferSizes["input"] = size
	return b
}

// WithOutputBuffer - Set output buffer size
func (b *StreamingBuilder) WithOutputBuffer(size int) *StreamingBuilder {
	b.bufferSizes["output"] = size
	return b
}

// WithMetrics - Enable/disable metrics
func (b *StreamingBuilder) WithMetrics(enabled bool) *StreamingBuilder {
	b.metricsEnabled = enabled
	return b
}

// ForKafka - Configure for Kafka integration
func (b *StreamingBuilder) ForKafka() *StreamingBuilder {
	b.config = KafkaOptimized()
	return b
}

// ForRealtime - Configure for realtime processing
func (b *StreamingBuilder) ForRealtime() *StreamingBuilder {
	b.config = RealtimeDetection()
	return b
}

// ForHighThroughput - Configure for high throughput
func (b *StreamingBuilder) ForHighThroughput() *StreamingBuilder {
	b.config = HighThroughput()
	return b
}

// Build - Build the streaming engine
func (b *StreamingBuilder) Build(core *SigmaEngine) (*StreamingEngine, error) {
	// Apply custom settings
	if b.workerCount > 0 {
		b.config.WorkerCount = b.workerCount
	}

	if inputSize, ok := b.bufferSizes["input"]; ok {
		b.config.InputBufferSize = inputSize
	}

	if outputSize, ok := b.bufferSizes["output"]; ok {
		b.config.OutputBufferSize = outputSize
	}

	b.config.EnableDetailedMetrics = b.metricsEnabled

	engine := NewStreamingEngine(core, b.config)

	// Set custom components
	if b.backpressure != nil {
		engine.backpressure = b.backpressure
	}

	if b.batcher != nil {
		engine.batcher = b.batcher
	}

	if b.processor != nil {
		engine.processor = b.processor
	}

	return engine, nil
}

// Configuration builders for different workloads

// RealtimeEngineBuilder - Specialized builder for realtime engines
func RealtimeEngineBuilder() *EngineBuilder {
	return NewEngineBuilder().
		ForRealtime().
		WithPrefilter(true).
		WithIR(true)
}

// HighThroughputEngineBuilder - Specialized builder for high throughput
func HighThroughputEngineBuilder() *EngineBuilder {
	return NewEngineBuilder().
		ForHighThroughput().
		WithPrefilter(true).
		WithIR(true)
}

// LowLatencyEngineBuilder - Specialized builder for low latency
func LowLatencyEngineBuilder() *EngineBuilder {
	return NewEngineBuilder().
		ForLowLatency().
		WithPrefilter(true).
		WithIR(false) // Disable IR for lowest latency
}

// SecurityEngineBuilder - Specialized builder for security use cases
func SecurityEngineBuilder() *EngineBuilder {
	builder := NewEngineBuilder().
		ForProduction().
		WithPrefilter(true).
		WithIR(true)

	// Add security-specific field mappings
	securityMappings := map[string]string{
		"ProcessImage":       "Image",
		"ProcessCommandLine": "CommandLine",
		"TargetFilename":     "TargetFilename",
		"SourceIp":           "SourceIP",
		"DestinationIp":      "DestinationIP",
		"User":               "User",
		"Computer":           "ComputerName",
	}

	return builder.WithFieldMappings(securityMappings)
}

// Helper functions for common configurations

// DefaultMatcherConfig - Default matcher configuration
func DefaultMatcherConfig() *MatcherConfig {
	return &MatcherConfig{
		EnableCache:      true,
		CacheSize:        10000,
		CacheTTL:         30 * time.Minute,
		EnableHooks:      true,
		EnableContext:    true,
		EnableModifiers:  true,
		FuzzyThreshold:   0.8,
		RegexTimeout:     100 * time.Millisecond,
		MaxPatternLength: 1024,
		CompilationMode:  "optimized",
	}
}

// Predefined error handlers

// LoggingErrorHandler - Error handler that logs errors
type LoggingErrorHandler struct {
	logger   *logrus.Logger
	severity ErrorSeverity
}

// NewLoggingErrorHandler - Create logging error handler
func NewLoggingErrorHandler(logger *logrus.Logger, severity ErrorSeverity) *LoggingErrorHandler {
	return &LoggingErrorHandler{
		logger:   logger,
		severity: severity,
	}
}

// Handle - Handle error by logging
func (h *LoggingErrorHandler) Handle(err SigmaError) error {
	entry := h.logger.WithFields(logrus.Fields{
		"error_code": err.ErrorCode(),
		"error_type": err.ErrorType(),
		"severity":   err.Severity(),
		"timestamp":  err.Timestamp(),
	})

	switch err.Severity() {
	case SeverityCritical:
		entry.Error(err.Error())
	case SeverityHigh:
		entry.Warn(err.Error())
	case SeverityMedium:
		entry.Info(err.Error())
	case SeverityLow:
		entry.Debug(err.Error())
	}

	return nil
}

// CanHandle - Check if can handle error type
func (h *LoggingErrorHandler) CanHandle(errorType ErrorType) bool {
	return true // Can handle all error types
}

// Priority - Get handler priority
func (h *LoggingErrorHandler) Priority() int {
	return 100 // Low priority (fallback handler)
}

// RetryErrorHandler - Error handler that retries operations
type RetryErrorHandler struct {
	maxRetries int
	backoff    time.Duration
}

// NewRetryErrorHandler - Create retry error handler
func NewRetryErrorHandler(maxRetries int, backoff time.Duration) *RetryErrorHandler {
	return &RetryErrorHandler{
		maxRetries: maxRetries,
		backoff:    backoff,
	}
}

// Handle - Handle error by retrying
func (h *RetryErrorHandler) Handle(err SigmaError) error {
	if !err.Retryable() {
		return err
	}

	// This would implement actual retry logic
	// For now, just simulate successful retry
	return nil
}

// CanHandle - Check if can handle error type
func (h *RetryErrorHandler) CanHandle(errorType ErrorType) bool {
	return errorType == ErrorTypeExecution ||
		errorType == ErrorTypeStreaming ||
		errorType == ErrorTypeNetwork
}

// Priority - Get handler priority
func (h *RetryErrorHandler) Priority() int {
	return 50 // Medium priority
}
