package sigma

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Profiler comprehensive profiling system cho SIGMA Engine
type Profiler struct {
	enabled         bool
	startTime       time.Time
	metrics         *ProfileMetrics
	executionTraces []*ExecutionTrace
	mu              sync.RWMutex
}

// ProfileMetrics detailed performance metrics
type ProfileMetrics struct {
	// Compilation metrics
	CompilationTime     time.Duration `json:"compilation_time"`
	RulesCompiled       int64         `json:"rules_compiled"`
	DAGNodesGenerated   int64         `json:"dag_nodes_generated"`
	OptimizationsApplied int64        `json:"optimizations_applied"`

	// Runtime metrics
	TotalEvents         int64         `json:"total_events"`
	EventsProcessed     int64         `json:"events_processed"`
	MatchedEvents       int64         `json:"matched_events"`
	AverageLatency      time.Duration `json:"average_latency"`
	P50Latency          time.Duration `json:"p50_latency"`
	P95Latency          time.Duration `json:"p95_latency"`
	P99Latency          time.Duration `json:"p99_latency"`
	EventsPerSecond     float64       `json:"events_per_second"`

	// DAG execution metrics
	DAGExecutions       int64         `json:"dag_executions"`
	NodesExecuted       int64         `json:"nodes_executed"`
	SharedComputations  int64         `json:"shared_computations"`
	CacheHits           int64         `json:"cache_hits"`
	CacheMisses         int64         `json:"cache_misses"`
	
	// Prefilter metrics
	PrefilterExecutions int64         `json:"prefilter_executions"`
	PrefilterHits       int64         `json:"prefilter_hits"`
	PrefilterMisses     int64         `json:"prefilter_misses"`
	PrefilterLatency    time.Duration `json:"prefilter_latency"`

	// Memory metrics
	MemoryUsage         int64         `json:"memory_usage_bytes"`
	PeakMemoryUsage     int64         `json:"peak_memory_usage_bytes"`
	AllocatedObjects    int64         `json:"allocated_objects"`
	GCCollections       int64         `json:"gc_collections"`

	// Streaming metrics (if enabled)
	StreamingEnabled    bool          `json:"streaming_enabled"`
	BatchesProcessed    int64         `json:"batches_processed"`
	AverageBatchSize    float64       `json:"average_batch_size"`
	BackpressureEvents  int64         `json:"backpressure_events"`
	WorkerUtilization   float64       `json:"worker_utilization"`

	// Error metrics
	CompilationErrors   int64         `json:"compilation_errors"`
	RuntimeErrors       int64         `json:"runtime_errors"`
	TimeoutErrors       int64         `json:"timeout_errors"`

	// Updated timestamps
	LastUpdate          time.Time     `json:"last_update"`
	
	mu sync.RWMutex
}

// ExecutionTrace detailed execution trace for performance analysis
type ExecutionTrace struct {
	TraceID         string                 `json:"trace_id"`
	Timestamp       time.Time              `json:"timestamp"`
	EventSize       int                    `json:"event_size_bytes"`
	PrefilterTime   time.Duration          `json:"prefilter_time"`
	DAGTime         time.Duration          `json:"dag_time"`
	TotalTime       time.Duration          `json:"total_time"`
	NodesExecuted   int                    `json:"nodes_executed"`
	SharedHits      int                    `json:"shared_hits"`
	CacheHits       int                    `json:"cache_hits"`
	RulesMatched    int                    `json:"rules_matched"`
	Event           map[string]interface{} `json:"event,omitempty"`
	MatchedRules    []string               `json:"matched_rules,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// ProfileConfig configuration cho profiling system
type ProfileConfig struct {
	Enabled           bool          `json:"enabled"`
	DetailedTracing   bool          `json:"detailed_tracing"`
	MaxTraces         int           `json:"max_traces"`
	MetricInterval    time.Duration `json:"metric_interval"`
	MemoryProfiling   bool          `json:"memory_profiling"`
	IncludeEventData  bool          `json:"include_event_data"`
	TraceThreshold    time.Duration `json:"trace_threshold"` // Only trace slow executions
}

// NewProfiler tạo profiler mới
func NewProfiler(config *ProfileConfig) *Profiler {
	if config == nil {
		config = &ProfileConfig{
			Enabled:         true,
			DetailedTracing: false,
			MaxTraces:       1000,
			MetricInterval:  time.Second * 30,
			MemoryProfiling: true,
			TraceThreshold:  time.Millisecond * 10,
		}
	}

	return &Profiler{
		enabled:         config.Enabled,
		startTime:       time.Now(),
		metrics:         &ProfileMetrics{LastUpdate: time.Now()},
		executionTraces: make([]*ExecutionTrace, 0, config.MaxTraces),
	}
}

// StartExecution bắt đầu trace execution
func (p *Profiler) StartExecution(traceID string, event map[string]interface{}) *ExecutionContext {
	if !p.enabled {
		return &ExecutionContext{
			TraceID:   traceID,
			StartTime: time.Now(),
		}
	}

	return &ExecutionContext{
		TraceID:     traceID,
		StartTime:   time.Now(),
		Event:       event,
		Cache:       make(map[string]interface{}),
		SharedState: make(map[string]interface{}),
		Results:     make(map[string]bool),
		MaxDepth:    20,
	}
}

// RecordCompilation ghi lại compilation metrics
func (p *Profiler) RecordCompilation(duration time.Duration, rulesCount int, nodesCount int, optimizations int) {
	if !p.enabled {
		return
	}

	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.CompilationTime += duration
	atomic.AddInt64(&p.metrics.RulesCompiled, int64(rulesCount))
	atomic.AddInt64(&p.metrics.DAGNodesGenerated, int64(nodesCount))
	atomic.AddInt64(&p.metrics.OptimizationsApplied, int64(optimizations))
	p.metrics.LastUpdate = time.Now()
}

// RecordExecution ghi lại execution results
func (p *Profiler) RecordExecution(ctx *ExecutionContext, prefilterTime time.Duration, 
	dagTime time.Duration, matchedRules []string, err error) {
	if !p.enabled {
		return
	}

	totalTime := time.Since(ctx.StartTime)
	atomic.AddInt64(&p.metrics.TotalEvents, 1)
	atomic.AddInt64(&p.metrics.EventsProcessed, 1)

	if len(matchedRules) > 0 {
		atomic.AddInt64(&p.metrics.MatchedEvents, 1)
	}

	if err != nil {
		atomic.AddInt64(&p.metrics.RuntimeErrors, 1)
	}

	// Update latency metrics
	p.updateLatencyMetrics(totalTime)

	// Record detailed trace if enabled
	p.recordTrace(ctx, prefilterTime, dagTime, totalTime, matchedRules, err)

	// Update memory metrics if enabled
	p.updateMemoryMetrics()
}

// RecordPrefilter ghi lại prefilter metrics
func (p *Profiler) RecordPrefilter(duration time.Duration, hit bool) {
	if !p.enabled {
		return
	}

	atomic.AddInt64(&p.metrics.PrefilterExecutions, 1)
	if hit {
		atomic.AddInt64(&p.metrics.PrefilterHits, 1)
	} else {
		atomic.AddInt64(&p.metrics.PrefilterMisses, 1)
	}

	// Update average prefilter latency
	p.metrics.mu.Lock()
	p.metrics.PrefilterLatency = (p.metrics.PrefilterLatency + duration) / 2
	p.metrics.mu.Unlock()
}

// RecordDAGExecution ghi lại DAG execution metrics
func (p *Profiler) RecordDAGExecution(nodesExecuted int, sharedHits int, cacheHits int, cacheMisses int) {
	if !p.enabled {
		return
	}

	atomic.AddInt64(&p.metrics.DAGExecutions, 1)
	atomic.AddInt64(&p.metrics.NodesExecuted, int64(nodesExecuted))
	atomic.AddInt64(&p.metrics.SharedComputations, int64(sharedHits))
	atomic.AddInt64(&p.metrics.CacheHits, int64(cacheHits))
	atomic.AddInt64(&p.metrics.CacheMisses, int64(cacheMisses))
}

// RecordStreaming ghi lại streaming metrics
func (p *Profiler) RecordStreaming(batchSize int, backpressure bool, workerUtil float64) {
	if !p.enabled {
		return
	}

	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.StreamingEnabled = true
	atomic.AddInt64(&p.metrics.BatchesProcessed, 1)
	
	// Update average batch size
	currentAvg := p.metrics.AverageBatchSize
	batchCount := atomic.LoadInt64(&p.metrics.BatchesProcessed)
	p.metrics.AverageBatchSize = (currentAvg*float64(batchCount-1) + float64(batchSize)) / float64(batchCount)

	if backpressure {
		atomic.AddInt64(&p.metrics.BackpressureEvents, 1)
	}

	p.metrics.WorkerUtilization = workerUtil
}

// updateLatencyMetrics cập nhật latency percentiles
func (p *Profiler) updateLatencyMetrics(latency time.Duration) {
	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	// Simple running average for now - in production, use histogram
	p.metrics.AverageLatency = (p.metrics.AverageLatency + latency) / 2

	// Approximate percentiles - should use proper histogram in production
	if latency > p.metrics.P99Latency {
		p.metrics.P99Latency = latency
	}
	if latency > p.metrics.P95Latency && latency <= p.metrics.P99Latency {
		p.metrics.P95Latency = latency
	}
	if latency <= p.metrics.P95Latency {
		p.metrics.P50Latency = (p.metrics.P50Latency + latency) / 2
	}

	// Calculate events per second
	elapsed := time.Since(p.startTime)
	if elapsed > 0 {
		p.metrics.EventsPerSecond = float64(atomic.LoadInt64(&p.metrics.EventsProcessed)) / elapsed.Seconds()
	}
}

// recordTrace ghi lại detailed execution trace
func (p *Profiler) recordTrace(ctx *ExecutionContext, prefilterTime time.Duration, 
	dagTime time.Duration, totalTime time.Duration, matchedRules []string, err error) {
	
	// Only record traces that meet threshold or have errors
	if totalTime < time.Millisecond*10 && err == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	eventSize := len(fmt.Sprintf("%v", ctx.Event))
	
	trace := &ExecutionTrace{
		TraceID:       ctx.TraceID,
		Timestamp:     ctx.StartTime,
		EventSize:     eventSize,
		PrefilterTime: prefilterTime,
		DAGTime:       dagTime,
		TotalTime:     totalTime,
		NodesExecuted: ctx.NodesRan,
		SharedHits:    ctx.SharedHits,
		RulesMatched:  len(matchedRules),
		MatchedRules:  matchedRules,
	}

	if err != nil {
		trace.Error = err.Error()
	}

	// Manage trace buffer size
	if len(p.executionTraces) >= cap(p.executionTraces) {
		// Remove oldest trace
		copy(p.executionTraces, p.executionTraces[1:])
		p.executionTraces = p.executionTraces[:len(p.executionTraces)-1]
	}

	p.executionTraces = append(p.executionTraces, trace)
}

// updateMemoryMetrics cập nhật memory usage metrics
func (p *Profiler) updateMemoryMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	p.metrics.MemoryUsage = int64(m.Alloc)
	if int64(m.Alloc) > p.metrics.PeakMemoryUsage {
		p.metrics.PeakMemoryUsage = int64(m.Alloc)
	}
	p.metrics.AllocatedObjects = int64(m.Mallocs - m.Frees)
	p.metrics.GCCollections = int64(m.NumGC)
}

// GetMetrics trả về current metrics
func (p *Profiler) GetMetrics() *ProfileMetrics {
	if !p.enabled {
		return nil
	}

	p.metrics.mu.RLock()
	defer p.metrics.mu.RUnlock()

	// Create copy to avoid race conditions
	metrics := *p.metrics
	return &metrics
}

// GetTraces trả về execution traces
func (p *Profiler) GetTraces() []*ExecutionTrace {
	if !p.enabled {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Return copy of traces
	traces := make([]*ExecutionTrace, len(p.executionTraces))
	copy(traces, p.executionTraces)
	return traces
}

// GetPerformanceReport tạo comprehensive performance report
func (p *Profiler) GetPerformanceReport() *PerformanceReport {
	if !p.enabled {
		return nil
	}

	metrics := p.GetMetrics()
	traces := p.GetTraces()

	return &PerformanceReport{
		Summary:          p.generateSummary(metrics),
		Metrics:          metrics,
		RecentTraces:     p.getSlowTraces(traces, 10),
		Recommendations: p.generateRecommendations(metrics),
		Timestamp:       time.Now(),
		Uptime:          time.Since(p.startTime),
	}
}

// PerformanceReport comprehensive performance report
type PerformanceReport struct {
	Summary         *PerformanceSummary `json:"summary"`
	Metrics         *ProfileMetrics     `json:"metrics"`
	RecentTraces    []*ExecutionTrace   `json:"recent_traces"`
	Recommendations []string            `json:"recommendations"`
	Timestamp       time.Time           `json:"timestamp"`
	Uptime          time.Duration       `json:"uptime"`
}

// PerformanceSummary high-level performance summary
type PerformanceSummary struct {
	Status              string        `json:"status"`
	EventsPerSecond     float64       `json:"events_per_second"`
	AverageLatency      time.Duration `json:"average_latency"`
	SuccessRate         float64       `json:"success_rate"`
	CacheEfficiency     float64       `json:"cache_efficiency"`
	PrefilterEfficiency float64       `json:"prefilter_efficiency"`
	MemoryEfficiency    string        `json:"memory_efficiency"`
}

// generateSummary tạo performance summary
func (p *Profiler) generateSummary(metrics *ProfileMetrics) *PerformanceSummary {
	summary := &PerformanceSummary{
		EventsPerSecond: metrics.EventsPerSecond,
		AverageLatency:  metrics.AverageLatency,
	}

	// Status assessment
	if metrics.EventsPerSecond >= 5000 {
		summary.Status = "EXCELLENT"
	} else if metrics.EventsPerSecond >= 2000 {
		summary.Status = "GOOD"
	} else if metrics.EventsPerSecond >= 500 {
		summary.Status = "FAIR"
	} else {
		summary.Status = "POOR"
	}

	// Success rate
	if metrics.TotalEvents > 0 {
		successEvents := metrics.TotalEvents - metrics.RuntimeErrors
		summary.SuccessRate = float64(successEvents) / float64(metrics.TotalEvents) * 100
	}

	// Cache efficiency
	totalCacheOps := metrics.CacheHits + metrics.CacheMisses
	if totalCacheOps > 0 {
		summary.CacheEfficiency = float64(metrics.CacheHits) / float64(totalCacheOps) * 100
	}

	// Prefilter efficiency
	totalPrefilterOps := metrics.PrefilterHits + metrics.PrefilterMisses
	if totalPrefilterOps > 0 {
		summary.PrefilterEfficiency = float64(metrics.PrefilterHits) / float64(totalPrefilterOps) * 100
	}

	// Memory efficiency
	memoryMB := metrics.MemoryUsage / (1024 * 1024)
	if memoryMB < 100 {
		summary.MemoryEfficiency = "EXCELLENT"
	} else if memoryMB < 500 {
		summary.MemoryEfficiency = "GOOD"
	} else if memoryMB < 1000 {
		summary.MemoryEfficiency = "FAIR"
	} else {
		summary.MemoryEfficiency = "POOR"
	}

	return summary
}

// getSlowTraces trả về slowest traces
func (p *Profiler) getSlowTraces(traces []*ExecutionTrace, limit int) []*ExecutionTrace {
	if len(traces) == 0 {
		return nil
	}

	// Sort by total time (descending)
	slowTraces := make([]*ExecutionTrace, len(traces))
	copy(slowTraces, traces)

	// Simple bubble sort for small datasets
	for i := 0; i < len(slowTraces)-1; i++ {
		for j := 0; j < len(slowTraces)-i-1; j++ {
			if slowTraces[j].TotalTime < slowTraces[j+1].TotalTime {
				slowTraces[j], slowTraces[j+1] = slowTraces[j+1], slowTraces[j]
			}
		}
	}

	if len(slowTraces) > limit {
		slowTraces = slowTraces[:limit]
	}

	return slowTraces
}

// generateRecommendations tạo performance recommendations
func (p *Profiler) generateRecommendations(metrics *ProfileMetrics) []string {
	var recommendations []string

	// Performance recommendations
	if metrics.EventsPerSecond < 5000 {
		recommendations = append(recommendations, "Consider enabling parallel processing to improve throughput")
	}

	if metrics.AverageLatency > time.Millisecond*100 {
		recommendations = append(recommendations, "High latency detected - review DAG optimization settings")
	}

	// Cache recommendations
	cacheEfficiency := float64(metrics.CacheHits) / float64(metrics.CacheHits+metrics.CacheMisses) * 100
	if cacheEfficiency < 70 {
		recommendations = append(recommendations, "Low cache efficiency - consider increasing cache size")
	}

	// Prefilter recommendations
	prefilterEfficiency := float64(metrics.PrefilterHits) / float64(metrics.PrefilterHits+metrics.PrefilterMisses) * 100
	if prefilterEfficiency < 50 {
		recommendations = append(recommendations, "Low prefilter efficiency - review literal extraction patterns")
	}

	// Memory recommendations
	memoryMB := metrics.MemoryUsage / (1024 * 1024)
	if memoryMB > 1000 {
		recommendations = append(recommendations, "High memory usage - consider reducing cache size or rule complexity")
	}

	// Error rate recommendations
	errorRate := float64(metrics.RuntimeErrors) / float64(metrics.TotalEvents) * 100
	if errorRate > 5 {
		recommendations = append(recommendations, "High error rate - review rule validation and event format consistency")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Performance is optimal - no immediate recommendations")
	}

	return recommendations
}

// ExportMetricsJSON export metrics as JSON
func (p *Profiler) ExportMetricsJSON() ([]byte, error) {
	if !p.enabled {
		return nil, fmt.Errorf("profiler is disabled")
	}

	report := p.GetPerformanceReport()
	return json.MarshalIndent(report, "", "  ")
}

// Reset resets all metrics and traces
func (p *Profiler) Reset() {
	if !p.enabled {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.startTime = time.Now()
	p.metrics = &ProfileMetrics{LastUpdate: time.Now()}
	p.executionTraces = p.executionTraces[:0]
}
