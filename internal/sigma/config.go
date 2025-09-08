package sigma

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config - Enhanced configuration system based on cawalch/sigma-engine
type Config struct {
	// Core Engine Configuration
	Engine    EngineConfig    `json:"engine" yaml:"engine"`
	DAG       DAGConfig       `json:"dag" yaml:"dag"`
	Matcher   MatcherConfig   `json:"matcher" yaml:"matcher"`
	Stream    StreamConfig    `json:"stream" yaml:"stream"`
	Profiling ProfilingConfig `json:"profiling" yaml:"profiling"`
}

// EngineConfig - Core engine configuration with validation
type EngineConfig struct {
	EnableOptimization       bool          `json:"enable_optimization" yaml:"enable_optimization"`
	EnableParallelProcessing bool          `json:"enable_parallel_processing" yaml:"enable_parallel_processing"`
	EnablePrefilter          bool          `json:"enable_prefilter" yaml:"enable_prefilter"`
	EnableSharedComputation  bool          `json:"enable_shared_computation" yaml:"enable_shared_computation"`
	EnableIR                 bool          `json:"enable_ir" yaml:"enable_ir"`
	BatchSize                int           `json:"batch_size" yaml:"batch_size"`
	WorkerCount              int           `json:"worker_count" yaml:"worker_count"`
	PrefilterMinLength       int           `json:"prefilter_min_length" yaml:"prefilter_min_length"`
	CacheSize                int           `json:"cache_size" yaml:"cache_size"`
	Timeout                  time.Duration `json:"timeout" yaml:"timeout"`
	MaxRules                 int           `json:"max_rules" yaml:"max_rules"`
	CompilationMode          string        `json:"compilation_mode" yaml:"compilation_mode"`
}

// DAGConfig - DAG-specific configuration
type DAGConfig struct {
	EnableOptimization  bool          `json:"enable_optimization" yaml:"enable_optimization"`
	OptimizationLevel   int           `json:"optimization_level" yaml:"optimization_level"`
	MaxNodes            int           `json:"max_nodes" yaml:"max_nodes"`
	SharedNodeThreshold int           `json:"shared_node_threshold" yaml:"shared_node_threshold"`
	CacheStrategy       string        `json:"cache_strategy" yaml:"cache_strategy"`
	ExecutionTimeout    time.Duration `json:"execution_timeout" yaml:"execution_timeout"`
	EnableParallelBatch bool          `json:"enable_parallel_batch" yaml:"enable_parallel_batch"`
	ParallelBatchSize   int           `json:"parallel_batch_size" yaml:"parallel_batch_size"`
	MemoryLimitMB       int           `json:"memory_limit_mb" yaml:"memory_limit_mb"`
}

// MatcherConfig - Advanced matcher configuration
type MatcherConfig struct {
	EnableCache      bool          `json:"enable_cache" yaml:"enable_cache"`
	CacheSize        int           `json:"cache_size" yaml:"cache_size"`
	CacheTTL         time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
	EnableHooks      bool          `json:"enable_hooks" yaml:"enable_hooks"`
	EnableContext    bool          `json:"enable_context" yaml:"enable_context"`
	EnableModifiers  bool          `json:"enable_modifiers" yaml:"enable_modifiers"`
	FuzzyThreshold   float64       `json:"fuzzy_threshold" yaml:"fuzzy_threshold"`
	RegexTimeout     time.Duration `json:"regex_timeout" yaml:"regex_timeout"`
	MaxPatternLength int           `json:"max_pattern_length" yaml:"max_pattern_length"`
	CompilationMode  string        `json:"compilation_mode" yaml:"compilation_mode"`
}

// StreamConfig - Streaming configuration with advanced options
type StreamConfig struct {
	// Core streaming
	InputBufferSize  int           `json:"input_buffer_size" yaml:"input_buffer_size"`
	OutputBufferSize int           `json:"output_buffer_size" yaml:"output_buffer_size"`
	BatchSize        int           `json:"batch_size" yaml:"batch_size"`
	BatchTimeout     time.Duration `json:"batch_timeout" yaml:"batch_timeout"`
	WorkerCount      int           `json:"worker_count" yaml:"worker_count"`
	WorkerTimeout    time.Duration `json:"worker_timeout" yaml:"worker_timeout"`

	// Backpressure
	EnableBackpressure    bool   `json:"enable_backpressure" yaml:"enable_backpressure"`
	BackpressureThreshold int    `json:"backpressure_threshold" yaml:"backpressure_threshold"`
	BackpressureStrategy  string `json:"backpressure_strategy" yaml:"backpressure_strategy"`

	// Adaptive batching
	EnableAdaptiveBatch bool    `json:"enable_adaptive_batch" yaml:"enable_adaptive_batch"`
	MinBatchSize        int     `json:"min_batch_size" yaml:"min_batch_size"`
	MaxBatchSize        int     `json:"max_batch_size" yaml:"max_batch_size"`
	AdaptiveThreshold   float64 `json:"adaptive_threshold" yaml:"adaptive_threshold"`

	// Performance targets
	LatencyTarget    time.Duration `json:"latency_target" yaml:"latency_target"`
	ThroughputTarget int           `json:"throughput_target" yaml:"throughput_target"`

	// Delivery guarantees
	DeliveryGuarantee string        `json:"delivery_guarantee" yaml:"delivery_guarantee"`
	RetryAttempts     int           `json:"retry_attempts" yaml:"retry_attempts"`
	RetryBackoff      time.Duration `json:"retry_backoff" yaml:"retry_backoff"`

	// Metrics
	MetricsInterval       time.Duration `json:"metrics_interval" yaml:"metrics_interval"`
	EnableTracing         bool          `json:"enable_tracing" yaml:"enable_tracing"`
	EnableDetailedMetrics bool          `json:"enable_detailed_metrics" yaml:"enable_detailed_metrics"`
}

// ProfilingConfig - Profiling system configuration
type ProfilingConfig struct {
	EnableProfiling      bool          `json:"enable_profiling" yaml:"enable_profiling"`
	EnableCPUProfiling   bool          `json:"enable_cpu_profiling" yaml:"enable_cpu_profiling"`
	EnableMemProfiling   bool          `json:"enable_mem_profiling" yaml:"enable_mem_profiling"`
	EnableTraceProfiling bool          `json:"enable_trace_profiling" yaml:"enable_trace_profiling"`
	SampleRate           int           `json:"sample_rate" yaml:"sample_rate"`
	ProfileDuration      time.Duration `json:"profile_duration" yaml:"profile_duration"`
	OutputPath           string        `json:"output_path" yaml:"output_path"`
}

// DefaultConfig - Production-ready default configuration based on Rust engine
func DefaultConfig() *Config {
	return &Config{
		Engine: EngineConfig{
			EnableOptimization:       true,
			EnableParallelProcessing: true,
			EnablePrefilter:          true,
			EnableSharedComputation:  true,
			EnableIR:                 true,
			BatchSize:                1000,
			WorkerCount:              8,
			PrefilterMinLength:       3,
			CacheSize:                50000,
			Timeout:                  30 * time.Second,
			MaxRules:                 10000,
			CompilationMode:          "optimized",
		},
		DAG: DAGConfig{
			EnableOptimization:  true,
			OptimizationLevel:   3,
			MaxNodes:            100000,
			SharedNodeThreshold: 2,
			CacheStrategy:       "lru",
			ExecutionTimeout:    5 * time.Second,
			EnableParallelBatch: true,
			ParallelBatchSize:   100,
			MemoryLimitMB:       512,
		},
		Matcher: MatcherConfig{
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
		},
		Stream: StreamConfig{
			InputBufferSize:       20000,
			OutputBufferSize:      10000,
			BatchSize:             100,
			BatchTimeout:          10 * time.Millisecond,
			WorkerCount:           12,
			WorkerTimeout:         2 * time.Second,
			EnableBackpressure:    true,
			BackpressureThreshold: 15000,
			BackpressureStrategy:  "adaptive",
			EnableAdaptiveBatch:   true,
			MinBatchSize:          10,
			MaxBatchSize:          500,
			AdaptiveThreshold:     0.7,
			LatencyTarget:         5 * time.Millisecond,
			ThroughputTarget:      20000,
			DeliveryGuarantee:     "at_least_once",
			RetryAttempts:         3,
			RetryBackoff:          100 * time.Millisecond,
			MetricsInterval:       10 * time.Second,
			EnableTracing:         true,
			EnableDetailedMetrics: true,
		},
		Profiling: ProfilingConfig{
			EnableProfiling:      true,
			EnableCPUProfiling:   true,
			EnableMemProfiling:   true,
			EnableTraceProfiling: false,
			SampleRate:           100,
			ProfileDuration:      30 * time.Second,
			OutputPath:           "/tmp/sigma-profiles",
		},
	}
}

// ProductionConfig - High-performance production configuration
func ProductionConfig() *Config {
	config := DefaultConfig()

	// High-performance settings
	config.Engine.BatchSize = 2000
	config.Engine.WorkerCount = 16
	config.Engine.CacheSize = 100000

	config.DAG.OptimizationLevel = 3
	config.DAG.ParallelBatchSize = 200
	config.DAG.MemoryLimitMB = 1024

	config.Stream.InputBufferSize = 50000
	config.Stream.OutputBufferSize = 25000
	config.Stream.WorkerCount = 20
	config.Stream.ThroughputTarget = 50000
	config.Stream.LatencyTarget = 2 * time.Millisecond

	config.Matcher.CacheSize = 50000
	config.Matcher.FuzzyThreshold = 0.9

	return config
}

// DevelopmentConfig - Development-friendly configuration
func DevelopmentConfig() *Config {
	config := DefaultConfig()

	// Development settings
	config.Engine.BatchSize = 100
	config.Engine.WorkerCount = 2
	config.Profiling.EnableProfiling = true
	config.Profiling.EnableTraceProfiling = true
	config.Stream.EnableDetailedMetrics = true

	return config
}

// ConfigFromEnv - Load configuration from environment variables
func ConfigFromEnv() *Config {
	config := DefaultConfig()

	// Engine configuration from env
	if val := os.Getenv("SIGMA_BATCH_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil {
			config.Engine.BatchSize = size
		}
	}

	if val := os.Getenv("SIGMA_WORKER_COUNT"); val != "" {
		if count, err := strconv.Atoi(val); err == nil {
			config.Engine.WorkerCount = count
		}
	}

	if val := os.Getenv("SIGMA_CACHE_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil {
			config.Engine.CacheSize = size
		}
	}

	// Stream configuration from env
	if val := os.Getenv("SIGMA_STREAM_BUFFER_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil {
			config.Stream.InputBufferSize = size
		}
	}

	if val := os.Getenv("SIGMA_THROUGHPUT_TARGET"); val != "" {
		if target, err := strconv.Atoi(val); err == nil {
			config.Stream.ThroughputTarget = target
		}
	}

	return config
}

// Validate - Validate configuration parameters
func (c *Config) Validate() error {
	// Engine validation
	if c.Engine.BatchSize <= 0 {
		return fmt.Errorf("engine.batch_size must be > 0, got %d", c.Engine.BatchSize)
	}

	if c.Engine.WorkerCount <= 0 {
		return fmt.Errorf("engine.worker_count must be > 0, got %d", c.Engine.WorkerCount)
	}

	if c.Engine.CacheSize <= 0 {
		return fmt.Errorf("engine.cache_size must be > 0, got %d", c.Engine.CacheSize)
	}

	// DAG validation
	if c.DAG.OptimizationLevel < 0 || c.DAG.OptimizationLevel > 3 {
		return fmt.Errorf("dag.optimization_level must be 0-3, got %d", c.DAG.OptimizationLevel)
	}

	// Stream validation
	if c.Stream.InputBufferSize <= 0 {
		return fmt.Errorf("stream.input_buffer_size must be > 0, got %d", c.Stream.InputBufferSize)
	}

	if c.Stream.BatchSize <= 0 {
		return fmt.Errorf("stream.batch_size must be > 0, got %d", c.Stream.BatchSize)
	}

	if c.Stream.EnableAdaptiveBatch {
		if c.Stream.MinBatchSize <= 0 || c.Stream.MaxBatchSize <= 0 {
			return fmt.Errorf("adaptive batching requires min_batch_size > 0 and max_batch_size > 0")
		}
		if c.Stream.MinBatchSize >= c.Stream.MaxBatchSize {
			return fmt.Errorf("min_batch_size must be < max_batch_size")
		}
	}

	// Matcher validation
	if c.Matcher.FuzzyThreshold < 0.0 || c.Matcher.FuzzyThreshold > 1.0 {
		return fmt.Errorf("matcher.fuzzy_threshold must be 0.0-1.0, got %f", c.Matcher.FuzzyThreshold)
	}

	return nil
}

// OptimizeForWorkload - Optimize configuration for specific workload
func (c *Config) OptimizeForWorkload(workload string) {
	switch workload {
	case "realtime":
		// Optimize for low latency
		c.Stream.BatchSize = 50
		c.Stream.BatchTimeout = 5 * time.Millisecond
		c.Stream.LatencyTarget = 2 * time.Millisecond
		c.Engine.BatchSize = 500

	case "high_throughput":
		// Optimize for high throughput
		c.Stream.BatchSize = 500
		c.Stream.BatchTimeout = 50 * time.Millisecond
		c.Stream.ThroughputTarget = 100000
		c.Engine.BatchSize = 5000
		c.Engine.WorkerCount = 32

	case "memory_efficient":
		// Optimize for memory usage
		c.Engine.CacheSize = 5000
		c.Matcher.CacheSize = 1000
		c.Stream.InputBufferSize = 5000
		c.DAG.MemoryLimitMB = 128

	case "cpu_efficient":
		// Optimize for CPU usage
		c.Engine.WorkerCount = 4
		c.Stream.WorkerCount = 6
		c.DAG.EnableParallelBatch = false
		c.Engine.EnableOptimization = true
	}
}

// Clone - Create a deep copy of configuration
func (c *Config) Clone() *Config {
	clone := *c
	return &clone
}

// String - String representation for debugging
func (c *Config) String() string {
	return fmt.Sprintf("Config{Engine: %+v, DAG: %+v, Matcher: %+v, Stream: %+v}",
		c.Engine, c.DAG, c.Matcher, c.Stream)
}
