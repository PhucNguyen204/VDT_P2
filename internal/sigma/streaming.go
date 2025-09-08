package sigma

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// StreamingEngine high-throughput streaming engine inspired by cawalch/sigma-engine
type StreamingEngine struct {
	core         *SigmaEngine
	config       *StreamingConfig
	batcher      *AdaptiveBatcher
	backpressure *BackpressureManager
	processor    *BatchProcessor
	metrics      *StreamingMetrics
	workers      []*StreamingWorker
	inputQueue   chan *StreamingEvent
	outputQueue  chan *StreamingResult
	controlQueue chan *ControlMessage
	running      atomic.Bool
	mu           sync.RWMutex
}

// StreamingConfig cấu hình cho streaming engine
type StreamingConfig struct {
	// Input configuration
	InputBufferSize int           `json:"input_buffer_size"`
	BatchSize       int           `json:"batch_size"`
	BatchTimeout    time.Duration `json:"batch_timeout"`

	// Worker configuration
	WorkerCount   int           `json:"worker_count"`
	WorkerTimeout time.Duration `json:"worker_timeout"`

	// Backpressure configuration
	EnableBackpressure    bool                 `json:"enable_backpressure"`
	BackpressureThreshold int                  `json:"backpressure_threshold"`
	BackpressureStrategy  BackpressureStrategy `json:"backpressure_strategy"`

	// Output configuration
	OutputBufferSize  int    `json:"output_buffer_size"`
	DeliveryGuarantee string `json:"delivery_guarantee"` // "at_least_once", "at_most_once", "exactly_once"

	// Performance tuning
	EnableAdaptiveBatch bool          `json:"enable_adaptive_batch"`
	LatencyTarget       time.Duration `json:"latency_target"`
	ThroughputTarget    int           `json:"throughput_target"`

	// Monitoring
	MetricsInterval time.Duration `json:"metrics_interval"`
	EnableTracing   bool          `json:"enable_tracing"`
}

// DefaultStreamingConfig trả về cấu hình mặc định theo cawalch/sigma-engine
func DefaultStreamingConfig() *StreamingConfig {
	return &StreamingConfig{
		InputBufferSize:       10000,
		BatchSize:             100,
		BatchTimeout:          10 * time.Millisecond,
		WorkerCount:           8,
		WorkerTimeout:         1 * time.Second,
		EnableBackpressure:    true,
		BackpressureThreshold: 8000,
		BackpressureStrategy:  BackpressureThrottle,
		OutputBufferSize:      10000,
		DeliveryGuarantee:     "at_least_once",
		EnableAdaptiveBatch:   true,
		LatencyTarget:         50 * time.Millisecond,
		ThroughputTarget:      10000,
		MetricsInterval:       1 * time.Second,
		EnableTracing:         false,
	}
}

// KafkaOptimized config tối ưu cho Kafka workloads theo cawalch pattern
func KafkaOptimized() *StreamingConfig {
	return &StreamingConfig{
		InputBufferSize:       50000,
		BatchSize:             500,
		BatchTimeout:          200 * time.Millisecond,
		WorkerCount:           16,
		WorkerTimeout:         10 * time.Second,
		EnableBackpressure:    true,
		BackpressureThreshold: 40000,
		BackpressureStrategy:  BackpressureBlock,
		OutputBufferSize:      25000,
		DeliveryGuarantee:     "at_least_once",
		EnableAdaptiveBatch:   true,
		LatencyTarget:         50 * time.Millisecond,
		ThroughputTarget:      50000,
		MetricsInterval:       15 * time.Second,
		EnableTracing:         false,
	}
}

// LowLatency config cho ứng dụng yêu cầu độ trễ thấp
func LowLatency() *StreamingConfig {
	return &StreamingConfig{
		InputBufferSize:       5000,
		BatchSize:             10,
		BatchTimeout:          1 * time.Millisecond,
		WorkerCount:           16,
		WorkerTimeout:         1 * time.Second,
		EnableBackpressure:    true,
		BackpressureThreshold: 4000,
		BackpressureStrategy:  BackpressureDrop,
		OutputBufferSize:      2500,
		DeliveryGuarantee:     "at_most_once",
		EnableAdaptiveBatch:   false, // Disable for consistent low latency
		LatencyTarget:         1 * time.Millisecond,
		ThroughputTarget:      5000,
		MetricsInterval:       5 * time.Second,
		EnableTracing:         false,
	}
}

// RealtimeDetection config tối ưu cho realtime threat detection
func RealtimeDetection() *StreamingConfig {
	return &StreamingConfig{
		InputBufferSize:       20000,
		BatchSize:             50,
		BatchTimeout:          5 * time.Millisecond,
		WorkerCount:           12,
		WorkerTimeout:         2 * time.Second,
		EnableBackpressure:    true,
		BackpressureThreshold: 15000,
		BackpressureStrategy:  BackpressureAdaptive,
		OutputBufferSize:      10000,
		DeliveryGuarantee:     "at_least_once",
		EnableAdaptiveBatch:   true,
		LatencyTarget:         5 * time.Millisecond,
		ThroughputTarget:      20000,
		MetricsInterval:       10 * time.Second,
		EnableTracing:         true, // Enable tracing for security analysis
	}
}

// HighThroughput config cho throughput cao theo cawalch pattern
func HighThroughput() *StreamingConfig {
	return &StreamingConfig{
		InputBufferSize:       100000,
		BatchSize:             1000,
		BatchTimeout:          500 * time.Millisecond,
		WorkerCount:           32,
		WorkerTimeout:         30 * time.Second,
		EnableBackpressure:    true,
		BackpressureThreshold: 80000,
		BackpressureStrategy:  BackpressureBlock,
		OutputBufferSize:      50000,
		DeliveryGuarantee:     "at_least_once",
		EnableAdaptiveBatch:   true,
		LatencyTarget:         100 * time.Millisecond,
		ThroughputTarget:      100000,
		MetricsInterval:       60 * time.Second,
		EnableTracing:         false,
	}
}

// StreamingEvent sự kiện đầu vào
type StreamingEvent struct {
	ID        string                 `json:"id"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Priority  ProcessingPriority     `json:"priority"`
	Metadata  map[string]interface{} `json:"metadata"`
	TraceID   string                 `json:"trace_id"`
}

// StreamingResult kết quả xử lý
type StreamingResult struct {
	EventID         string           `json:"event_id"`
	DetectionResult *DetectionResult `json:"detection_result"`
	ProcessingTime  time.Duration    `json:"processing_time"`
	WorkerID        int              `json:"worker_id"`
	BatchID         string           `json:"batch_id"`
	Error           error            `json:"error,omitempty"`
}

// ControlMessage message điều khiển
type ControlMessage struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// AdaptiveBatcher adaptive batching logic
type AdaptiveBatcher struct {
	config         *StreamingConfig
	currentBatch   []*StreamingEvent
	batchTimeout   *time.Timer
	latencyHistory []time.Duration
	throughputHist []int
	mu             sync.Mutex
	metrics        *BatcherMetrics
}

// BatcherMetrics metrics cho batcher
type BatcherMetrics struct {
	BatchesCreated   int64         `json:"batches_created"`
	EventsBatched    int64         `json:"events_batched"`
	AverageBatchSize float64       `json:"average_batch_size"`
	BatchLatency     time.Duration `json:"batch_latency"`
	AdaptationCount  int64         `json:"adaptation_count"`
	mu               sync.RWMutex
}

// BackpressureManager quản lý backpressure
type BackpressureManager struct {
	config       *StreamingConfig
	currentLoad  atomic.Int64
	maxLoad      int64
	strategy     BackpressureStrategy
	metrics      *BackpressureMetrics
	throttleRate atomic.Int64 // events per second when throttling
}

// BackpressureMetrics metrics cho backpressure
type BackpressureMetrics struct {
	EventsDropped        int64         `json:"events_dropped"`
	EventsThrottled      int64         `json:"events_throttled"`
	EventsBuffered       int64         `json:"events_buffered"`
	BackpressureDuration time.Duration `json:"backpressure_duration"`
	TriggerCount         int64         `json:"trigger_count"`
	mu                   sync.RWMutex
}

// BatchProcessor xử lý batch events
type BatchProcessor struct {
	engine  *SigmaEngine
	config  *StreamingConfig
	metrics *ProcessorMetrics
}

// ProcessorMetrics metrics cho processor
type ProcessorMetrics struct {
	BatchesProcessed int64         `json:"batches_processed"`
	EventsProcessed  int64         `json:"events_processed"`
	AverageLatency   time.Duration `json:"average_latency"`
	ErrorCount       int64         `json:"error_count"`
	mu               sync.RWMutex
}

// StreamingWorker worker để xử lý streaming
type StreamingWorker struct {
	id         int
	engine     *StreamingEngine
	processor  *BatchProcessor
	running    atomic.Bool
	metrics    *WorkerMetrics
	batchQueue chan *WorkerBatch
}

// WorkerMetrics metrics cho worker
type WorkerMetrics struct {
	EventsProcessed  int64         `json:"events_processed"`
	BatchesProcessed int64         `json:"batches_processed"`
	AverageLatency   time.Duration `json:"average_latency"`
	ErrorCount       int64         `json:"error_count"`
	LastActive       time.Time     `json:"last_active"`
	mu               sync.RWMutex
}

// NewStreamingEngine tạo streaming engine mới
func NewStreamingEngine(core *SigmaEngine, config *StreamingConfig) *StreamingEngine {
	if config == nil {
		config = DefaultStreamingConfig()
	}

	engine := &StreamingEngine{
		core:         core,
		config:       config,
		metrics:      &StreamingMetrics{},
		inputQueue:   make(chan *StreamingEvent, config.InputBufferSize),
		outputQueue:  make(chan *StreamingResult, config.OutputBufferSize),
		controlQueue: make(chan *ControlMessage, 100),
	}

	// Initialize components
	engine.batcher = NewAdaptiveBatcher(config)
	engine.backpressure = NewBackpressureManager(config)
	engine.processor = NewBatchProcessor(core, config)

	// Initialize workers
	engine.workers = make([]*StreamingWorker, config.WorkerCount)
	for i := 0; i < config.WorkerCount; i++ {
		engine.workers[i] = &StreamingWorker{
			id:        i,
			engine:    engine,
			processor: engine.processor,
			metrics:   &WorkerMetrics{},
		}
	}

	return engine
}

// Start bắt đầu streaming engine
func (se *StreamingEngine) Start(ctx context.Context) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	if se.running.Load() {
		return errors.New("streaming engine already running")
	}

	se.running.Store(true)

	// Start batcher
	go se.runBatcher(ctx)

	// Start workers
	for _, worker := range se.workers {
		go worker.run(ctx)
	}

	// Start backpressure monitor
	go se.runBackpressureMonitor(ctx)

	// Start metrics collector
	go se.runMetricsCollector(ctx)

	return nil
}

// Stop dừng streaming engine
func (se *StreamingEngine) Stop(ctx context.Context) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	if !se.running.Load() {
		return errors.New("streaming engine not running")
	}

	se.running.Store(false)

	// Send shutdown signal
	se.controlQueue <- &ControlMessage{
		Type:      "shutdown",
		Timestamp: time.Now(),
	}

	// Wait for workers to stop (with timeout)
	done := make(chan bool, 1)
	go func() {
		for _, worker := range se.workers {
			for worker.running.Load() {
				time.Sleep(10 * time.Millisecond)
			}
		}
		done <- true
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return errors.New("shutdown timeout")
	}
}

// ProcessEvent xử lý một event
func (se *StreamingEngine) ProcessEvent(event *StreamingEvent) error {
	if !se.running.Load() {
		return errors.New("streaming engine not running")
	}

	// Check backpressure
	if se.config.EnableBackpressure {
		if err := se.backpressure.CheckBackpressure(); err != nil {
			return fmt.Errorf("backpressure triggered: %w", err)
		}
	}

	// Add to input queue
	select {
	case se.inputQueue <- event:
		atomic.AddInt64(&se.metrics.MessagesReceived, 1)
		return nil
	default:
		atomic.AddInt64(&se.metrics.MessagesDropped, 1)
		return errors.New("input queue full")
	}
}

// GetResults lấy kết quả xử lý
func (se *StreamingEngine) GetResults() <-chan *StreamingResult {
	return se.outputQueue
}

// runBatcher chạy adaptive batcher
func (se *StreamingEngine) runBatcher(ctx context.Context) {
	ticker := time.NewTicker(se.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case control := <-se.controlQueue:
			if control.Type == "shutdown" {
				return
			}
		case event := <-se.inputQueue:
			batch := se.batcher.AddEvent(event)
			if batch != nil {
				// Send batch to workers
				se.sendBatchToWorker(batch)
			}
		case <-ticker.C:
			// Force flush any pending batch
			batch := se.batcher.FlushBatch()
			if batch != nil {
				se.sendBatchToWorker(batch)
			}
		}
	}
}

// sendBatchToWorker gửi batch đến worker có sẵn
func (se *StreamingEngine) sendBatchToWorker(batch []*StreamingEvent) {
	// Simple round-robin distribution
	// In production, this could be more sophisticated (load balancing, affinity, etc.)
	batchMessage := &WorkerBatch{
		Events:    batch,
		BatchID:   fmt.Sprintf("batch_%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
	}

	// Send to next available worker
	for _, worker := range se.workers {
		if worker.running.Load() {
			select {
			case worker.batchQueue <- batchMessage:
				return
			default:
				continue // Worker busy, try next
			}
		}
	}

	// If no worker available, could implement fallback strategy
	fmt.Printf("⚠️ No available worker for batch processing\n")
}

// WorkerBatch batch để gửi đến worker
type WorkerBatch struct {
	Events    []*StreamingEvent `json:"events"`
	BatchID   string            `json:"batch_id"`
	Timestamp time.Time         `json:"timestamp"`
}

// Initialize worker components
func (worker *StreamingWorker) run(ctx context.Context) {
	worker.running.Store(true)
	defer worker.running.Store(false)

	// Worker needs a batch queue
	worker.batchQueue = make(chan *WorkerBatch, 100)

	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-worker.batchQueue:
			worker.processBatch(batch)
		}
	}
}

// Add batchQueue field to StreamingWorker
type StreamingWorkerWithQueue struct {
	*StreamingWorker
	batchQueue chan *WorkerBatch
}

// Update StreamingWorker to include batchQueue
func (worker *StreamingWorker) processBatch(batch *WorkerBatch) {
	start := time.Now()

	results := make([]*StreamingResult, len(batch.Events))

	for i, event := range batch.Events {
		result, err := worker.processor.ProcessEvent(event)
		if err != nil {
			worker.metrics.mu.Lock()
			worker.metrics.ErrorCount++
			worker.metrics.mu.Unlock()
		}

		results[i] = &StreamingResult{
			EventID:         event.ID,
			DetectionResult: result,
			ProcessingTime:  time.Since(start),
			WorkerID:        worker.id,
			BatchID:         batch.BatchID,
			Error:           err,
		}
	}

	// Send results to output queue
	for _, result := range results {
		select {
		case worker.engine.outputQueue <- result:
			atomic.AddInt64(&worker.engine.metrics.MessagesProcessed, 1)
		default:
			atomic.AddInt64(&worker.engine.metrics.MessagesDropped, 1)
		}
	}

	// Update metrics
	processingTime := time.Since(start)
	worker.metrics.mu.Lock()
	worker.metrics.EventsProcessed += int64(len(batch.Events))
	worker.metrics.BatchesProcessed++
	worker.metrics.LastActive = time.Now()
	if worker.metrics.BatchesProcessed == 1 {
		worker.metrics.AverageLatency = processingTime
	} else {
		worker.metrics.AverageLatency = time.Duration(
			(int64(worker.metrics.AverageLatency)*(worker.metrics.BatchesProcessed-1) + int64(processingTime)) / worker.metrics.BatchesProcessed,
		)
	}
	worker.metrics.mu.Unlock()
}

// Rest of the implementations...

// NewAdaptiveBatcher tạo adaptive batcher
func NewAdaptiveBatcher(config *StreamingConfig) *AdaptiveBatcher {
	return &AdaptiveBatcher{
		config:         config,
		currentBatch:   make([]*StreamingEvent, 0, config.BatchSize),
		latencyHistory: make([]time.Duration, 0, 100),
		throughputHist: make([]int, 0, 100),
		metrics:        &BatcherMetrics{},
	}
}

// AddEvent thêm event vào batch
func (ab *AdaptiveBatcher) AddEvent(event *StreamingEvent) []*StreamingEvent {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	ab.currentBatch = append(ab.currentBatch, event)

	// Check if batch is ready
	if len(ab.currentBatch) >= ab.config.BatchSize {
		return ab.flushCurrentBatch()
	}

	// Start timeout timer if this is first event
	if len(ab.currentBatch) == 1 {
		ab.batchTimeout = time.AfterFunc(ab.config.BatchTimeout, func() {
			ab.mu.Lock()
			defer ab.mu.Unlock()
			if len(ab.currentBatch) > 0 {
				ab.flushCurrentBatch()
			}
		})
	}

	return nil
}

// FlushBatch flush current batch
func (ab *AdaptiveBatcher) FlushBatch() []*StreamingEvent {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	return ab.flushCurrentBatch()
}

func (ab *AdaptiveBatcher) flushCurrentBatch() []*StreamingEvent {
	if len(ab.currentBatch) == 0 {
		return nil
	}

	batch := make([]*StreamingEvent, len(ab.currentBatch))
	copy(batch, ab.currentBatch)

	// Reset current batch
	ab.currentBatch = ab.currentBatch[:0]

	// Cancel timeout
	if ab.batchTimeout != nil {
		ab.batchTimeout.Stop()
		ab.batchTimeout = nil
	}

	// Update metrics
	ab.metrics.mu.Lock()
	ab.metrics.BatchesCreated++
	ab.metrics.EventsBatched += int64(len(batch))
	ab.metrics.AverageBatchSize = float64(ab.metrics.EventsBatched) / float64(ab.metrics.BatchesCreated)
	ab.metrics.mu.Unlock()

	return batch
}

// NewBackpressureManager tạo backpressure manager
func NewBackpressureManager(config *StreamingConfig) *BackpressureManager {
	return &BackpressureManager{
		config:   config,
		maxLoad:  int64(config.BackpressureThreshold),
		strategy: config.BackpressureStrategy,
		metrics:  &BackpressureMetrics{},
	}
}

// CheckBackpressure kiểm tra backpressure
func (bm *BackpressureManager) CheckBackpressure() error {
	currentLoad := bm.currentLoad.Load()

	if currentLoad >= bm.maxLoad {
		bm.metrics.mu.Lock()
		bm.metrics.TriggerCount++
		bm.metrics.mu.Unlock()

		switch bm.strategy {
		case BackpressureDrop:
			bm.metrics.mu.Lock()
			bm.metrics.EventsDropped++
			bm.metrics.mu.Unlock()
			return errors.New("event dropped due to backpressure")
		case BackpressureThrottle:
			bm.metrics.mu.Lock()
			bm.metrics.EventsThrottled++
			bm.metrics.mu.Unlock()
			// Simple throttling - sleep briefly
			time.Sleep(time.Millisecond)
			return nil
		case BackpressureBuffer:
			bm.metrics.mu.Lock()
			bm.metrics.EventsBuffered++
			bm.metrics.mu.Unlock()
			// Allow buffering but warn
			return nil
		case BackpressureBlock:
			return errors.New("processing blocked due to backpressure")
		}
	}

	return nil
}

// NewBatchProcessor tạo batch processor
func NewBatchProcessor(engine *SigmaEngine, config *StreamingConfig) *BatchProcessor {
	return &BatchProcessor{
		engine:  engine,
		config:  config,
		metrics: &ProcessorMetrics{},
	}
}

// ProcessEvent xử lý một event
func (bp *BatchProcessor) ProcessEvent(event *StreamingEvent) (*DetectionResult, error) {
	start := time.Now()

	result, err := bp.engine.Evaluate(event.Data)
	if err != nil {
		bp.metrics.mu.Lock()
		bp.metrics.ErrorCount++
		bp.metrics.mu.Unlock()
		return nil, err
	}

	// Convert to DetectionResult
	detectionResult := &DetectionResult{
		RuleMatches:    result.MatchedRules,
		TotalMatches:   len(result.MatchedRules),
		ProcessingTime: time.Since(start),
		EventContext: &EventContext{
			Event:         event.Data,
			Timestamp:     event.Timestamp,
			Source:        event.Source,
			CorrelationID: event.ID,
		},
		Metadata: event.Metadata,
	}

	// Determine highest severity
	highestSev := LevelLow
	for _, match := range result.MatchedRules {
		if match.Level == "critical" {
			highestSev = LevelCritical
		} else if match.Level == "high" && highestSev != LevelCritical {
			highestSev = LevelHigh
		} else if match.Level == "medium" && highestSev == LevelLow {
			highestSev = LevelMedium
		}
	}
	detectionResult.HighestSeverity = highestSev

	// Update metrics
	processingTime := time.Since(start)
	bp.metrics.mu.Lock()
	bp.metrics.EventsProcessed++
	if bp.metrics.EventsProcessed == 1 {
		bp.metrics.AverageLatency = processingTime
	} else {
		bp.metrics.AverageLatency = time.Duration(
			(int64(bp.metrics.AverageLatency)*(bp.metrics.EventsProcessed-1) + int64(processingTime)) / bp.metrics.EventsProcessed,
		)
	}
	bp.metrics.mu.Unlock()

	return detectionResult, nil
}

// Add remaining monitoring functions
func (se *StreamingEngine) runBackpressureMonitor(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Update current load
			currentLoad := int64(len(se.inputQueue))
			se.backpressure.currentLoad.Store(currentLoad)
		}
	}
}

func (se *StreamingEngine) runMetricsCollector(ctx context.Context) {
	ticker := time.NewTicker(se.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect and aggregate metrics
			se.collectMetrics()
		}
	}
}

func (se *StreamingEngine) collectMetrics() {
	// Aggregate metrics from all components
	se.metrics.mu.Lock()
	defer se.metrics.mu.Unlock()

	// Calculate processing rate
	if se.metrics.MessagesProcessed > 0 {
		se.metrics.ProcessingRate = float64(se.metrics.MessagesProcessed) / time.Since(time.Now().Add(-se.config.MetricsInterval)).Seconds()
	}

	// Calculate buffer utilization
	se.metrics.BufferUtilization = float64(len(se.inputQueue)) / float64(se.config.InputBufferSize) * 100
}

// StreamingWorker already updated with batchQueue field

// GetMetrics returns streaming metrics
func (se *StreamingEngine) GetMetrics() *StreamingMetrics {
	se.metrics.mu.RLock()
	defer se.metrics.mu.RUnlock()

	// Return copy of metrics
	return &StreamingMetrics{
		MessagesReceived:  se.metrics.MessagesReceived,
		MessagesProcessed: se.metrics.MessagesProcessed,
		MessagesDropped:   se.metrics.MessagesDropped,
		ProcessingRate:    se.metrics.ProcessingRate,
		BufferUtilization: se.metrics.BufferUtilization,
		// ... other fields
	}
}
