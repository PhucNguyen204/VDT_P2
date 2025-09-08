package sigma

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerPool high-performance worker pool cho parallel DAG execution
type WorkerPool struct {
	workers      []*Worker
	workQueue    chan *WorkItem
	resultQueue  chan *WorkResult
	workerCount  int
	running      int32
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	metrics      *WorkerPoolMetrics
}

// Worker individual worker trong pool
type Worker struct {
	id         int
	pool       *WorkerPool
	engine     *DAGEngine
	workQueue  chan *WorkItem
	quit       chan bool
	metrics    *WorkerMetrics
}

// WorkItem work item cho worker processing
type WorkItem struct {
	ID            string
	Event         map[string]interface{}
	Context       *ExecutionContext
	ResultChannel chan *WorkResult
	Priority      int
	Timestamp     time.Time
}

// WorkResult result từ worker processing
type WorkResult struct {
	ID            string
	Matches       []*DetectionResult
	ExecutionTime time.Duration
	NodesExecuted int
	SharedHits    int
	CacheHits     int
	Error         error
	WorkerID      int
}

// WorkerPoolMetrics metrics cho worker pool
type WorkerPoolMetrics struct {
	TotalTasks       int64         `json:"total_tasks"`
	CompletedTasks   int64         `json:"completed_tasks"`
	FailedTasks      int64         `json:"failed_tasks"`
	AverageLatency   time.Duration `json:"average_latency"`
	ThroughputPerSec float64       `json:"throughput_per_sec"`
	ActiveWorkers    int32         `json:"active_workers"`
	QueueSize        int32         `json:"queue_size"`
	mu               sync.RWMutex
}



// BatchMetrics metrics cho batch processing
type BatchMetrics struct {
	BatchesProcessed  int64         `json:"batches_processed"`
	EventsProcessed   int64         `json:"events_processed"`
	AverageBatchSize  float64       `json:"average_batch_size"`
	BatchLatency      time.Duration `json:"batch_latency"`
	ThroughputPerSec  float64       `json:"throughput_per_sec"`
	mu                sync.RWMutex
}

// NewWorkerPool tạo worker pool mới
func NewWorkerPool(workerCount int, queueSize int, engine *DAGEngine) *WorkerPool {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workerCount: workerCount,
		workQueue:   make(chan *WorkItem, queueSize),
		resultQueue: make(chan *WorkResult, queueSize),
		ctx:         ctx,
		cancel:      cancel,
		metrics:     &WorkerPoolMetrics{},
	}

	// Create workers
	pool.workers = make([]*Worker, workerCount)
	for i := 0; i < workerCount; i++ {
		pool.workers[i] = &Worker{
			id:        i,
			pool:      pool,
			engine:    engine,
			workQueue: pool.workQueue,
			quit:      make(chan bool),
			metrics:   &WorkerMetrics{},
		}
	}

	return pool
}

// Start bắt đầu worker pool
func (wp *WorkerPool) Start() {
	if !atomic.CompareAndSwapInt32(&wp.running, 0, 1) {
		return // Already running
	}

	// Start all workers
	for _, worker := range wp.workers {
		wp.wg.Add(1)
		go worker.start(&wp.wg)
		atomic.AddInt32(&wp.metrics.ActiveWorkers, 1)
	}

	// Start metrics updater
	go wp.updateMetrics()
}

// Stop dừng worker pool
func (wp *WorkerPool) Stop() {
	if !atomic.CompareAndSwapInt32(&wp.running, 1, 0) {
		return // Already stopped
	}

	wp.cancel()

	// Stop all workers
	for _, worker := range wp.workers {
		close(worker.quit)
	}

	wp.wg.Wait()
	close(wp.workQueue)
	close(wp.resultQueue)
}

// Submit submit work item to pool
func (wp *WorkerPool) Submit(item *WorkItem) error {
	if atomic.LoadInt32(&wp.running) == 0 {
		return fmt.Errorf("worker pool is not running")
	}

	select {
	case wp.workQueue <- item:
		atomic.AddInt64(&wp.metrics.TotalTasks, 1)
		atomic.AddInt32(&wp.metrics.QueueSize, 1)
		return nil
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool is shutting down")
	default:
		return fmt.Errorf("work queue is full")
	}
}

// ProcessAsync process event asynchronously
func (wp *WorkerPool) ProcessAsync(event map[string]interface{}) <-chan *WorkResult {
	resultChan := make(chan *WorkResult, 1)
	
	ctx := &ExecutionContext{
		Event:       event,
		Cache:       make(map[string]interface{}),
		SharedState: make(map[string]interface{}),
		Results:     make(map[string]bool),
		StartTime:   time.Now(),
		MaxDepth:    20,
	}

	item := &WorkItem{
		ID:            fmt.Sprintf("task-%d", time.Now().UnixNano()),
		Event:         event,
		Context:       ctx,
		ResultChannel: resultChan,
		Timestamp:     time.Now(),
	}

	go func() {
		if err := wp.Submit(item); err != nil {
			resultChan <- &WorkResult{
				ID:    item.ID,
				Error: err,
			}
		}
	}()

	return resultChan
}

// start worker execution
func (w *Worker) start(wg *sync.WaitGroup) {
	defer wg.Done()
	defer atomic.AddInt32(&w.pool.metrics.ActiveWorkers, -1)

	for {
		select {
		case work := <-w.workQueue:
			w.processWork(work)
		case <-w.quit:
			return
		case <-w.pool.ctx.Done():
			return
		}
	}
}

// processWork xử lý work item
func (w *Worker) processWork(item *WorkItem) {
	startTime := time.Now()
	
	w.metrics.mu.Lock()
	w.metrics.LastActive = startTime
	w.metrics.mu.Unlock()

	// Decrement queue size
	atomic.AddInt32(&w.pool.metrics.QueueSize, -1)

	// Execute DAG
	matches, nodesRan, sharedHits, err := w.engine.Execute(item.Event)
	
	executionTime := time.Since(startTime)
	
	// Update worker metrics
	atomic.AddInt64(&w.metrics.EventsProcessed, 1)
	if err != nil {
		atomic.AddInt64(&w.metrics.ErrorCount, 1)
		atomic.AddInt64(&w.pool.metrics.FailedTasks, 1)
	} else {
		atomic.AddInt64(&w.pool.metrics.CompletedTasks, 1)
	}

	w.metrics.mu.Lock()
	w.metrics.LastActive = time.Now()
	// Update average latency
	currentEvents := atomic.LoadInt64(&w.metrics.EventsProcessed)
	if currentEvents > 0 {
		w.metrics.AverageLatency = (w.metrics.AverageLatency + executionTime) / 2
	}
	w.metrics.mu.Unlock()

	// Convert RuleMatch to DetectionResult
	var results []*DetectionResult
	for _, match := range matches {
		results = append(results, &DetectionResult{
			RuleMatches:     []*RuleMatch{match},
			TotalMatches:    1,
			ProcessingTime:  executionTime,
			Metadata:        make(map[string]interface{}),
		})
	}

	// Send result
	result := &WorkResult{
		ID:            item.ID,
		Matches:       results,
		ExecutionTime: executionTime,
		NodesExecuted: nodesRan,
		SharedHits:    sharedHits,
		Error:         err,
		WorkerID:      w.id,
	}

	select {
	case item.ResultChannel <- result:
	case <-w.pool.ctx.Done():
		return
	}
}

// updateMetrics cập nhật pool metrics
func (wp *WorkerPool) updateMetrics() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastCompleted int64
	var lastTime = time.Now()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			currentCompleted := atomic.LoadInt64(&wp.metrics.CompletedTasks)
			
			// Calculate throughput
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed > 0 {
				tasksDelta := currentCompleted - lastCompleted
				wp.metrics.mu.Lock()
				wp.metrics.ThroughputPerSec = float64(tasksDelta) / elapsed
				wp.metrics.mu.Unlock()
			}

			lastCompleted = currentCompleted
			lastTime = now

		case <-wp.ctx.Done():
			return
		}
	}
}


// Note: BatchProcessor methods removed due to type conflicts with streaming.go
// Using simplified batch processing in DAG engine instead

// Note: Removed conflicting BatchProcessor methods - using streaming.go implementation instead

// GetWorkerPoolMetrics trả về worker pool metrics
func (wp *WorkerPool) GetMetrics() *WorkerPoolMetrics {
	wp.metrics.mu.RLock()
	defer wp.metrics.mu.RUnlock()
	
	metrics := *wp.metrics
	return &metrics
}

// Note: GetBatchMetrics removed due to type conflicts
