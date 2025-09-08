package sigma

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Hook system for extensible processing pipeline based on cawalch/sigma-engine

// HookType - Types of hooks in the processing pipeline
type HookType string

const (
	// Pre-processing hooks
	HookPreCompilation   HookType = "pre_compilation"
	HookPostCompilation  HookType = "post_compilation"
	HookPreOptimization  HookType = "pre_optimization"
	HookPostOptimization HookType = "post_optimization"

	// Runtime hooks
	HookPreExecution  HookType = "pre_execution"
	HookPostExecution HookType = "post_execution"
	HookPreMatch      HookType = "pre_match"
	HookPostMatch     HookType = "post_match"
	HookPreFilter     HookType = "pre_filter"
	HookPostFilter    HookType = "post_filter"

	// Streaming hooks
	HookPreBatch     HookType = "pre_batch"
	HookPostBatch    HookType = "post_batch"
	HookPreStream    HookType = "pre_stream"
	HookPostStream   HookType = "post_stream"
	HookBackpressure HookType = "backpressure"

	// Error hooks
	HookError    HookType = "error"
	HookPanic    HookType = "panic"
	HookRecovery HookType = "recovery"

	// Metrics hooks
	HookMetrics   HookType = "metrics"
	HookProfiling HookType = "profiling"
)

// HookPriority - Priority levels for hooks
type HookPriority int

const (
	PriorityCritical HookPriority = 0
	PriorityHigh     HookPriority = 25
	PriorityMedium   HookPriority = 50
	PriorityLow      HookPriority = 75
	PriorityVeryLow  HookPriority = 100
)

// HookContext - Context passed to hooks
type HookContext struct {
	Type      HookType               `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Request   interface{}            `json:"request,omitempty"`
	Response  interface{}            `json:"response,omitempty"`
	Error     error                  `json:"error,omitempty"`
	Metadata  map[string]string      `json:"metadata"`
	Context   context.Context        `json:"-"`
}

// HookResult - Result from hook execution
type HookResult struct {
	Continue     bool                   `json:"continue"`
	ModifiedData map[string]interface{} `json:"modified_data,omitempty"`
	Error        error                  `json:"error,omitempty"`
	Metadata     map[string]string      `json:"metadata,omitempty"`
}

// Hook - Interface for all hooks
type Hook interface {
	Execute(ctx *HookContext) (*HookResult, error)
	Type() HookType
	Priority() HookPriority
	Name() string
	Enabled() bool
}

// BaseHook - Base implementation for hooks
type BaseHook struct {
	name     string
	hookType HookType
	priority HookPriority
	enabled  bool
}

// Type - Get hook type
func (h *BaseHook) Type() HookType {
	return h.hookType
}

// Priority - Get hook priority
func (h *BaseHook) Priority() HookPriority {
	return h.priority
}

// Name - Get hook name
func (h *BaseHook) Name() string {
	return h.name
}

// Enabled - Check if hook is enabled
func (h *BaseHook) Enabled() bool {
	return h.enabled
}

// SetEnabled - Enable/disable hook
func (h *BaseHook) SetEnabled(enabled bool) {
	h.enabled = enabled
}

// HookManager - Manages hooks and their execution
type HookManager struct {
	hooks   map[HookType][]Hook
	metrics *HookMetrics
	enabled bool
	mu      sync.RWMutex
}

// HookMetrics - Metrics for hook execution
type HookMetrics struct {
	ExecutionCount map[HookType]int64         `json:"execution_count"`
	ExecutionTime  map[HookType]time.Duration `json:"execution_time"`
	ErrorCount     map[HookType]int64         `json:"error_count"`
	SuccessRate    map[HookType]float64       `json:"success_rate"`
	AverageTime    map[HookType]time.Duration `json:"average_time"`
	mu             sync.RWMutex
}

// NewHookManager - Create new hook manager
func NewHookManager() *HookManager {
	return &HookManager{
		hooks: make(map[HookType][]Hook),
		metrics: &HookMetrics{
			ExecutionCount: make(map[HookType]int64),
			ExecutionTime:  make(map[HookType]time.Duration),
			ErrorCount:     make(map[HookType]int64),
			SuccessRate:    make(map[HookType]float64),
			AverageTime:    make(map[HookType]time.Duration),
		},
		enabled: true,
	}
}

// RegisterHook - Register a hook
func (hm *HookManager) RegisterHook(hook Hook) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()

	hookType := hook.Type()

	// Insert hook in priority order
	hooks := hm.hooks[hookType]
	inserted := false

	for i, existingHook := range hooks {
		if hook.Priority() < existingHook.Priority() {
			// Insert at position i
			hooks = append(hooks[:i+1], hooks[i:]...)
			hooks[i] = hook
			inserted = true
			break
		}
	}

	if !inserted {
		hooks = append(hooks, hook)
	}

	hm.hooks[hookType] = hooks
	return nil
}

// UnregisterHook - Unregister a hook by name
func (hm *HookManager) UnregisterHook(hookType HookType, name string) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hooks := hm.hooks[hookType]
	for i, hook := range hooks {
		if hook.Name() == name {
			// Remove hook
			hm.hooks[hookType] = append(hooks[:i], hooks[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("hook '%s' not found for type '%s'", name, hookType)
}

// ExecuteHooks - Execute all hooks for a type
func (hm *HookManager) ExecuteHooks(hookType HookType, ctx *HookContext) error {
	if !hm.enabled {
		return nil
	}

	hm.mu.RLock()
	hooks := hm.hooks[hookType]
	hm.mu.RUnlock()

	if len(hooks) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		hm.updateMetrics(hookType, time.Since(start), nil)
	}()

	ctx.Type = hookType
	ctx.Timestamp = time.Now()

	for _, hook := range hooks {
		if !hook.Enabled() {
			continue
		}

		hookStart := time.Now()
		result, err := hook.Execute(ctx)
		hookDuration := time.Since(hookStart)

		hm.updateHookMetrics(hook, hookDuration, err)

		if err != nil {
			hm.updateMetrics(hookType, time.Since(start), err)
			return fmt.Errorf("hook '%s' failed: %w", hook.Name(), err)
		}

		if result != nil {
			if !result.Continue {
				break
			}

			// Apply modified data
			if result.ModifiedData != nil {
				for key, value := range result.ModifiedData {
					ctx.Data[key] = value
				}
			}

			// Apply metadata
			if result.Metadata != nil {
				for key, value := range result.Metadata {
					ctx.Metadata[key] = value
				}
			}
		}
	}

	return nil
}

// Specific hook implementations

// MatcherHook - Hook for matcher operations
type MatcherHook interface {
	Hook
	OnPreMatch(ctx *MatcherContext, pattern string, value interface{}) error
	OnPostMatch(ctx *MatcherContext, pattern string, value interface{}, matched bool) error
	OnMatchError(ctx *MatcherContext, pattern string, value interface{}, err error) error
}

// BaseMatcherHook - Base implementation for matcher hooks
type BaseMatcherHook struct {
	*BaseHook
}

// Execute - Execute matcher hook
func (h *BaseMatcherHook) Execute(ctx *HookContext) (*HookResult, error) {
	// Default implementation
	return &HookResult{Continue: true}, nil
}

// LoggingHook - Hook that logs operations
type LoggingHook struct {
	*BaseHook
	logger interface{} // Logger interface
}

// NewLoggingHook - Create logging hook
func NewLoggingHook(name string, hookType HookType, logger interface{}) *LoggingHook {
	return &LoggingHook{
		BaseHook: &BaseHook{
			name:     name,
			hookType: hookType,
			priority: PriorityLow,
			enabled:  true,
		},
		logger: logger,
	}
}

// Execute - Execute logging hook
func (h *LoggingHook) Execute(ctx *HookContext) (*HookResult, error) {
	// Log the operation (simplified implementation)
	fmt.Printf("[HOOK:%s] %s at %v\n", h.hookType, h.name, ctx.Timestamp)
	return &HookResult{Continue: true}, nil
}

// MetricsHook - Hook that collects metrics
type MetricsHook struct {
	*BaseHook
	collector MetricsCollector
}

// MetricsCollector - Interface for metrics collection
type MetricsCollector interface {
	CollectMetric(name string, value interface{}, tags map[string]string)
}

// NewMetricsHook - Create metrics hook
func NewMetricsHook(name string, hookType HookType, collector MetricsCollector) *MetricsHook {
	return &MetricsHook{
		BaseHook: &BaseHook{
			name:     name,
			hookType: hookType,
			priority: PriorityMedium,
			enabled:  true,
		},
		collector: collector,
	}
}

// Execute - Execute metrics hook
func (h *MetricsHook) Execute(ctx *HookContext) (*HookResult, error) {
	if h.collector != nil {
		tags := map[string]string{
			"hook_type": string(h.hookType),
			"hook_name": h.name,
		}
		h.collector.CollectMetric("hook_execution", 1, tags)
	}
	return &HookResult{Continue: true}, nil
}

// ValidationHook - Hook that validates data
type ValidationHook struct {
	*BaseHook
	validators []Validator
}

// Validator - Interface for data validation
type Validator interface {
	Validate(data interface{}) error
}

// NewValidationHook - Create validation hook
func NewValidationHook(name string, hookType HookType, validators []Validator) *ValidationHook {
	return &ValidationHook{
		BaseHook: &BaseHook{
			name:     name,
			hookType: hookType,
			priority: PriorityHigh,
			enabled:  true,
		},
		validators: validators,
	}
}

// Execute - Execute validation hook
func (h *ValidationHook) Execute(ctx *HookContext) (*HookResult, error) {
	for _, validator := range h.validators {
		if err := validator.Validate(ctx.Data); err != nil {
			return &HookResult{
				Continue: false,
				Error:    fmt.Errorf("validation failed: %w", err),
			}, err
		}
	}
	return &HookResult{Continue: true}, nil
}

// TransformationHook - Hook that transforms data
type TransformationHook struct {
	*BaseHook
	transformer Transformer
}

// Transformer - Interface for data transformation
type Transformer interface {
	Transform(data interface{}) (interface{}, error)
}

// NewTransformationHook - Create transformation hook
func NewTransformationHook(name string, hookType HookType, transformer Transformer) *TransformationHook {
	return &TransformationHook{
		BaseHook: &BaseHook{
			name:     name,
			hookType: hookType,
			priority: PriorityMedium,
			enabled:  true,
		},
		transformer: transformer,
	}
}

// Execute - Execute transformation hook
func (h *TransformationHook) Execute(ctx *HookContext) (*HookResult, error) {
	if h.transformer != nil {
		transformed, err := h.transformer.Transform(ctx.Data)
		if err != nil {
			return &HookResult{
				Continue: false,
				Error:    err,
			}, err
		}

		return &HookResult{
			Continue:     true,
			ModifiedData: map[string]interface{}{"transformed": transformed},
		}, nil
	}

	return &HookResult{Continue: true}, nil
}

// CachingHook - Hook that implements caching
type CachingHook struct {
	*BaseHook
	cache Cache
}

// Cache - Interface for caching operations
type Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Delete(key string)
}

// NewCachingHook - Create caching hook
func NewCachingHook(name string, hookType HookType, cache Cache) *CachingHook {
	return &CachingHook{
		BaseHook: &BaseHook{
			name:     name,
			hookType: hookType,
			priority: PriorityHigh,
			enabled:  true,
		},
		cache: cache,
	}
}

// Execute - Execute caching hook
func (h *CachingHook) Execute(ctx *HookContext) (*HookResult, error) {
	if h.cache == nil {
		return &HookResult{Continue: true}, nil
	}

	// Generate cache key from context
	cacheKey := h.generateCacheKey(ctx)

	// Check cache for existing result
	if cached, found := h.cache.Get(cacheKey); found {
		return &HookResult{
			Continue:     true,
			ModifiedData: map[string]interface{}{"cached_result": cached},
		}, nil
	}

	// Continue execution and cache result
	return &HookResult{Continue: true}, nil
}

// generateCacheKey - Generate cache key from context
func (h *CachingHook) generateCacheKey(ctx *HookContext) string {
	return fmt.Sprintf("%s:%s:%d", h.hookType, h.name, ctx.Timestamp.Unix())
}

// SecurityHook - Hook for security operations
type SecurityHook struct {
	*BaseHook
	securityChecker SecurityChecker
}

// SecurityChecker - Interface for security checks
type SecurityChecker interface {
	CheckSecurity(data interface{}) (bool, error)
}

// NewSecurityHook - Create security hook
func NewSecurityHook(name string, hookType HookType, checker SecurityChecker) *SecurityHook {
	return &SecurityHook{
		BaseHook: &BaseHook{
			name:     name,
			hookType: hookType,
			priority: PriorityCritical,
			enabled:  true,
		},
		securityChecker: checker,
	}
}

// Execute - Execute security hook
func (h *SecurityHook) Execute(ctx *HookContext) (*HookResult, error) {
	if h.securityChecker != nil {
		secure, err := h.securityChecker.CheckSecurity(ctx.Data)
		if err != nil {
			return &HookResult{
				Continue: false,
				Error:    fmt.Errorf("security check failed: %w", err),
			}, err
		}

		if !secure {
			return &HookResult{
				Continue: false,
				Error:    fmt.Errorf("security check failed: data not secure"),
			}, nil
		}
	}

	return &HookResult{Continue: true}, nil
}

// Utility functions

// updateMetrics - Update hook execution metrics
func (hm *HookManager) updateMetrics(hookType HookType, duration time.Duration, err error) {
	hm.metrics.mu.Lock()
	defer hm.metrics.mu.Unlock()

	hm.metrics.ExecutionCount[hookType]++
	hm.metrics.ExecutionTime[hookType] += duration

	if err != nil {
		hm.metrics.ErrorCount[hookType]++
	}

	// Calculate success rate
	total := hm.metrics.ExecutionCount[hookType]
	errors := hm.metrics.ErrorCount[hookType]
	hm.metrics.SuccessRate[hookType] = float64(total-errors) / float64(total)

	// Calculate average time
	hm.metrics.AverageTime[hookType] = hm.metrics.ExecutionTime[hookType] / time.Duration(total)
}

// updateHookMetrics - Update individual hook metrics
func (hm *HookManager) updateHookMetrics(hook Hook, duration time.Duration, err error) {
	// This could be expanded to track per-hook metrics
	// For now, just update type-level metrics
	hm.updateMetrics(hook.Type(), duration, err)
}

// GetMetrics - Get hook execution metrics
func (hm *HookManager) GetMetrics() *HookMetrics {
	hm.metrics.mu.RLock()
	defer hm.metrics.mu.RUnlock()

	// Return copy of metrics
	return &HookMetrics{
		ExecutionCount: copyIntMap(hm.metrics.ExecutionCount),
		ExecutionTime:  copyDurationMap(hm.metrics.ExecutionTime),
		ErrorCount:     copyIntMap(hm.metrics.ErrorCount),
		SuccessRate:    copyFloatMap(hm.metrics.SuccessRate),
		AverageTime:    copyDurationMap(hm.metrics.AverageTime),
	}
}

// Enable - Enable hook manager
func (hm *HookManager) Enable() {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.enabled = true
}

// Disable - Disable hook manager
func (hm *HookManager) Disable() {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.enabled = false
}

// IsEnabled - Check if hook manager is enabled
func (hm *HookManager) IsEnabled() bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.enabled
}

// ListHooks - List all registered hooks
func (hm *HookManager) ListHooks() map[HookType][]string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	result := make(map[HookType][]string)
	for hookType, hooks := range hm.hooks {
		names := make([]string, len(hooks))
		for i, hook := range hooks {
			names[i] = hook.Name()
		}
		result[hookType] = names
	}

	return result
}

// Helper functions for copying maps
func copyIntMap(original map[HookType]int64) map[HookType]int64 {
	copy := make(map[HookType]int64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

func copyDurationMap(original map[HookType]time.Duration) map[HookType]time.Duration {
	copy := make(map[HookType]time.Duration)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

func copyFloatMap(original map[HookType]float64) map[HookType]float64 {
	copy := make(map[HookType]float64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}
