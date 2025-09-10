package sigma

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SigmaEngine - Main high-performance SIGMA detection engine theo cawalch/sigma-engine
type SigmaEngine struct {
	compiler    *Compiler
	dag         *DAGEngine
	config      *EngineConfig
	rules       []*CompiledRule
	prefilter   *AhoCorasickPrefilter
	fieldMapper *FieldMapper
	metrics     *EngineMetrics
	streaming   *StreamingEngine // Realtime streaming engine
	mu          sync.RWMutex
	logger      *logrus.Logger
	running     bool
}

// EngineConfig cấu hình cho SIGMA Engine
type EngineConfig struct {
	EnableOptimization       bool          `json:"enable_optimization"`
	EnableParallelProcessing bool          `json:"enable_parallel_processing"`
	EnablePrefilter          bool          `json:"enable_prefilter"`
	EnableSharedComputation  bool          `json:"enable_shared_computation"`
	EnableDebugLogging       bool          `json:"enable_debug_logging"`
	BatchSize                int           `json:"batch_size"`
	WorkerCount              int           `json:"worker_count"`
	PrefilterMinLength       int           `json:"prefilter_min_length"`
	CacheSize                int           `json:"cache_size"`
	Timeout                  time.Duration `json:"timeout"`
}

// DefaultEngineConfig trả về cấu hình mặc định tối ưu
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		EnableOptimization:       true,
		EnableParallelProcessing: true,
		EnablePrefilter:          true,
		EnableSharedComputation:  true,
		EnableDebugLogging:       false, // Tắt debug logging mặc định
		BatchSize:                1000,
		WorkerCount:              4,
		PrefilterMinLength:       3,
		CacheSize:                10000,
		Timeout:                  30 * time.Second,
	}
}

// EngineMetrics theo dõi hiệu suất
type EngineMetrics struct {
	TotalEvents           int64         `json:"total_events"`
	MatchedEvents         int64         `json:"matched_events"`
	PrefilterHits         int64         `json:"prefilter_hits"`
	PrefilterMisses       int64         `json:"prefilter_misses"`
	CompilationTime       time.Duration `json:"compilation_time"`
	AverageExecutionTime  time.Duration `json:"average_execution_time"`
	SharedComputationHits int64         `json:"shared_computation_hits"`
	CacheHits             int64         `json:"cache_hits"`
	CacheMisses           int64         `json:"cache_misses"`
	mu                    sync.RWMutex
}

// NewSigmaEngine tạo engine mới từ YAML rules
func NewSigmaEngine(config *EngineConfig, logger *logrus.Logger) *SigmaEngine {
	if config == nil {
		config = DefaultEngineConfig()
	}

	engine := &SigmaEngine{
		compiler:    NewCompiler(),
		config:      config,
		fieldMapper: NewFieldMapperWithCase(true), // Case-sensitive for exact field matching
		metrics:     &EngineMetrics{},
		logger:      logger,
	}

	// Initialize streaming engine với RealtimeDetection config theo cawalch pattern
	if config.EnableParallelProcessing {
		streamingConfig := RealtimeDetection() // Use realtime config for threat detection
		engine.streaming = NewStreamingEngine(engine, streamingConfig)
		if logger != nil {
			logger.WithFields(logrus.Fields{
				"batch_size":     streamingConfig.BatchSize,
				"workers":        streamingConfig.WorkerCount,
				"latency_target": streamingConfig.LatencyTarget,
			}).Info("🚀 Initialized realtime streaming engine")
		}
	}

	return engine
}

// SigmaEngineBuilder builder pattern cho cawalch/sigma-engine compatibility
type SigmaEngineBuilder struct {
	config *EngineConfig
	logger *logrus.Logger
}

// Builder tạo builder mới theo cawalch pattern
func Builder() *SigmaEngineBuilder {
	return &SigmaEngineBuilder{
		config: DefaultEngineConfig(),
	}
}

// WithConfig sets engine configuration
func (b *SigmaEngineBuilder) WithConfig(config *EngineConfig) *SigmaEngineBuilder {
	b.config = config
	return b
}

// WithLogger sets logger
func (b *SigmaEngineBuilder) WithLogger(logger *logrus.Logger) *SigmaEngineBuilder {
	b.logger = logger
	return b
}

// Build creates engine and compiles rules theo cawalch pattern
func (b *SigmaEngineBuilder) Build(rulesYAML []string) (*SigmaEngine, error) {
	engine := NewSigmaEngine(b.config, b.logger)
	err := engine.FromRules(rulesYAML)
	if err != nil {
		return nil, err
	}
	return engine, nil
}

// FromRules static constructor theo cawalch/sigma-engine API
func FromRules(rulesYAML []string) (*SigmaEngine, error) {
	engine := NewSigmaEngine(nil, nil)
	err := engine.FromRules(rulesYAML)
	if err != nil {
		return nil, err
	}
	return engine, nil
}

// FromRulesWithCompiler static constructor với custom compiler
func FromRulesWithCompiler(rulesYAML []string, compiler *Compiler, config *EngineConfig) (*SigmaEngine, error) {
	engine := NewSigmaEngine(config, nil)
	engine.compiler = compiler
	err := engine.FromRules(rulesYAML)
	if err != nil {
		return nil, err
	}
	return engine, nil
}

// FromRules instance method - tạo engine từ YAML rules (giống Rust version)
func (e *SigmaEngine) FromRules(rulesYAML []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	start := time.Now()

	// Phase 1: Compile YAML → DAG
	compiledRules, err := e.compiler.CompileRuleset(rulesYAML)
	if err != nil {
		return fmt.Errorf("failed to compile rules: %w", err)
	}

	e.rules = compiledRules

	// Build DAG with optimization
	dagBuilder := NewDAGBuilder(e.config)
	e.dag, err = dagBuilder.BuildFromRules(compiledRules)
	if err != nil {
		return fmt.Errorf("failed to build DAG: %w", err)
	}

	// Setup prefilter if enabled
	if e.config.EnablePrefilter {
		e.prefilter = NewAhoCorasickPrefilter(e.config.PrefilterMinLength)
		err = e.prefilter.BuildFromRules(compiledRules)
		if err != nil {
			e.logger.WithError(err).Warn("Failed to build prefilter, continuing without")
			e.prefilter = nil
		}
	}

	e.metrics.CompilationTime = time.Since(start)

	e.logger.WithFields(logrus.Fields{
		"rules_count":       len(compiledRules),
		"compilation_time":  e.metrics.CompilationTime,
		"dag_nodes":         e.dag.NodeCount(),
		"prefilter_enabled": e.prefilter != nil,
	}).Info("SIGMA Engine compiled successfully")

	return nil
}

// EvaluationResult kết quả đánh giá sự kiện
type EvaluationResult struct {
	MatchedRules    []*RuleMatch  `json:"matched_rules"`
	ExecutionTime   time.Duration `json:"execution_time"`
	PrefilterPassed bool          `json:"prefilter_passed"`
	ProcessedNodes  int           `json:"processed_nodes"`
	SharedHits      int           `json:"shared_hits"`
}

// RuleMatch thông tin rule match
type RuleMatch struct {
	RuleID        string                 `json:"rule_id"`
	Title         string                 `json:"title"`
	Level         string                 `json:"level"`
	Tags          []string               `json:"tags"`
	Description   string                 `json:"description"`
	MatchedFields map[string]interface{} `json:"matched_fields"`
	Confidence    float64                `json:"confidence"`
}

// Evaluate đánh giá một sự kiện (Phase 2: DAG Execution)
func (e *SigmaEngine) Evaluate(event map[string]interface{}) (*EvaluationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	fmt.Printf("🔍 Engine Evaluate: Starting, DAG=%v\n", e.dag != nil)

	if e.dag == nil {
		fmt.Printf("❌ Engine: DAG is nil!\n")
		return nil, fmt.Errorf("engine not initialized, call FromRules first")
	}

	start := time.Now()
	defer func() {
		e.metrics.mu.Lock()
		e.metrics.TotalEvents++
		executionTime := time.Since(start)
		// Update average execution time
		if e.metrics.TotalEvents == 1 {
			e.metrics.AverageExecutionTime = executionTime
		} else {
			e.metrics.AverageExecutionTime = time.Duration(
				(int64(e.metrics.AverageExecutionTime)*(e.metrics.TotalEvents-1) + int64(executionTime)) / e.metrics.TotalEvents,
			)
		}
		e.metrics.mu.Unlock()
	}()

	result := &EvaluationResult{
		MatchedRules:  make([]*RuleMatch, 0),
		ExecutionTime: 0,
	}

	// Prefiltering phase
	fmt.Printf("🔍 Engine: Prefilter check, enabled=%v\n", e.prefilter != nil)
	if e.prefilter != nil {
		passed, err := e.prefilter.ShouldProcess(event)
		fmt.Printf("🔍 Prefilter result: passed=%v, error=%v\n", passed, err)
		if err != nil {
			e.logger.WithError(err).Warn("Prefilter error")
		} else {
			result.PrefilterPassed = passed
			if passed {
				fmt.Printf("✅ Prefilter: Event passed, continuing to DAG\n")
				e.metrics.mu.Lock()
				e.metrics.PrefilterHits++
				e.metrics.mu.Unlock()
			} else {
				fmt.Printf("❌ Prefilter: Event blocked, early return\n")
				e.metrics.mu.Lock()
				e.metrics.PrefilterMisses++
				e.metrics.mu.Unlock()
				result.ExecutionTime = time.Since(start)
				return result, nil
			}
		}
	} else {
		fmt.Printf("✅ Prefilter: Disabled, continuing to DAG\n")
		result.PrefilterPassed = true
	}

	// DAG execution phase
	fmt.Printf("🔍 Engine: About to call DAG.Execute\n")
	matches, processedNodes, sharedHits, err := e.dag.Execute(event)
	if err != nil {
		fmt.Printf("❌ DAG execution failed: %v\n", err)
		return nil, fmt.Errorf("DAG execution failed: %w", err)
	}
	fmt.Printf("🔍 DAG execution completed: matches=%d, processed=%d, shared=%d\n", len(matches), processedNodes, sharedHits)

	result.MatchedRules = matches
	result.ProcessedNodes = processedNodes
	result.SharedHits = sharedHits
	result.ExecutionTime = time.Since(start)

	if len(matches) > 0 {
		e.metrics.mu.Lock()
		e.metrics.MatchedEvents++
		e.metrics.SharedComputationHits += int64(sharedHits)
		e.metrics.mu.Unlock()
	}

	return result, nil
}

// GetMetrics trả về metrics hiện tại
func (e *SigmaEngine) GetMetrics() *EngineMetrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	// Return copy
	return &EngineMetrics{
		TotalEvents:           e.metrics.TotalEvents,
		MatchedEvents:         e.metrics.MatchedEvents,
		PrefilterHits:         e.metrics.PrefilterHits,
		PrefilterMisses:       e.metrics.PrefilterMisses,
		CompilationTime:       e.metrics.CompilationTime,
		AverageExecutionTime:  e.metrics.AverageExecutionTime,
		SharedComputationHits: e.metrics.SharedComputationHits,
		CacheHits:             e.metrics.CacheHits,
		CacheMisses:           e.metrics.CacheMisses,
	}
}

// AddFieldMapping thêm field mapping
func (e *SigmaEngine) AddFieldMapping(from, to string) {
	e.fieldMapper.AddMapping(from, to)
	// Also update compiler's field mapper
	if e.compiler != nil {
		e.compiler.fieldMapper.AddMapping(from, to)
	}
}

// EvaluateBatch high-performance batch evaluation
func (e *SigmaEngine) EvaluateBatch(events []map[string]interface{}) ([]*EvaluationResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.dag == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	var results []*EvaluationResult

	if e.config.EnableParallelProcessing && len(events) > e.config.BatchSize {
		// Use DAG batch processing for large batches
		detectionResults, err := e.dag.ExecuteBatch(events)
		if err != nil {
			return nil, err
		}

		// Convert to EvaluationResult format
		resultMap := make(map[int]*EvaluationResult)
		for _, dr := range detectionResults {
			// Group by original event index (simplified)
			eventIdx := len(results) % len(events)
			if _, exists := resultMap[eventIdx]; !exists {
				resultMap[eventIdx] = &EvaluationResult{
					MatchedRules:    []*RuleMatch{},
					ExecutionTime:   time.Millisecond,
					PrefilterPassed: true,
					ProcessedNodes:  1,
					SharedHits:      0,
				}
			}

			// Use the existing RuleMatches from DetectionResult
			if len(dr.RuleMatches) > 0 {
				resultMap[eventIdx].MatchedRules = append(resultMap[eventIdx].MatchedRules, dr.RuleMatches...)
			}
		}

		// Convert map to slice
		for i := 0; i < len(events); i++ {
			if result, exists := resultMap[i]; exists {
				results = append(results, result)
			} else {
				results = append(results, &EvaluationResult{
					MatchedRules:    []*RuleMatch{},
					ExecutionTime:   time.Microsecond,
					PrefilterPassed: true,
					ProcessedNodes:  0,
					SharedHits:      0,
				})
			}
		}
	} else {
		// Sequential processing for smaller batches
		for _, event := range events {
			result, err := e.Evaluate(event)
			if err != nil {
				// Add empty result for failed events in batch mode
				results = append(results, &EvaluationResult{
					MatchedRules:    []*RuleMatch{},
					ExecutionTime:   time.Microsecond,
					PrefilterPassed: false,
					ProcessedNodes:  0,
					SharedHits:      0,
				})
			} else {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// GetDAGEngine returns the underlying DAG engine for advanced operations
func (e *SigmaEngine) GetDAGEngine() *DAGEngine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dag
}

// GetProfiler returns the profiler for performance monitoring
func (e *SigmaEngine) GetProfiler() *Profiler {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.dag != nil {
		return e.dag.profiler
	}
	return nil
}

// StartPerformanceComponents starts all performance-related components
func (e *SigmaEngine) StartPerformanceComponents() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dag != nil {
		e.dag.StartPerformanceComponents()
	}
	e.running = true
}

// StopPerformanceComponents stops all performance-related components
func (e *SigmaEngine) StopPerformanceComponents() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dag != nil {
		e.dag.StopPerformanceComponents()
	}
	e.running = false
}

// GetPerformanceMetrics returns comprehensive performance metrics
func (e *SigmaEngine) GetPerformanceMetrics() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	metrics := make(map[string]interface{})

	// Engine metrics
	metrics["engine"] = map[string]interface{}{
		"total_events":            e.metrics.TotalEvents,
		"matched_events":          e.metrics.MatchedEvents,
		"prefilter_hits":          e.metrics.PrefilterHits,
		"prefilter_misses":        e.metrics.PrefilterMisses,
		"compilation_time":        e.metrics.CompilationTime,
		"average_execution_time":  e.metrics.AverageExecutionTime,
		"shared_computation_hits": e.metrics.SharedComputationHits,
		"cache_hits":              e.metrics.CacheHits,
		"cache_misses":            e.metrics.CacheMisses,
		"running":                 e.running,
	}

	// DAG metrics if available
	if e.dag != nil {
		dagMetrics := e.dag.GetPerformanceMetrics()
		metrics["dag"] = dagMetrics
	}

	return metrics
}

// Shutdown cleanup resources
func (e *SigmaEngine) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.StopPerformanceComponents()

	if e.dag != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		return e.dag.Shutdown(ctx)
	}

	return nil
}
