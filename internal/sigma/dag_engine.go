package sigma

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// debugf prints debug message if debug logging is enabled
func (e *DAGEngine) debugf(format string, args ...interface{}) {
	if e.config != nil && e.config.EnableDebugLogging {
		fmt.Printf(format, args...)
	}
}

// DAGEngine high-performance execution engine với shared computation
type DAGEngine struct {
	nodes          map[string]*DAGNode
	sharedNodes    map[string]*SharedNode
	executionCache map[string]*CacheEntry
	rules          []*CompiledRule
	config         *EngineConfig
	metrics        *DAGMetrics
	optimizer      *DAGOptimizer
	matcher        *AdvancedMatcher
	profiler       *Profiler
	workerPool     *WorkerPool
	batchProcessor *BatchProcessor
	mu             sync.RWMutex
}

// SharedNode node được share giữa các rules
type SharedNode struct {
	Node     *DAGNode
	RuleIDs  []string
	UseCount int
	LastUsed time.Time
}

// CacheEntry cache entry cho execution results
type CacheEntry struct {
	Result    bool
	Value     interface{}
	Timestamp time.Time
	HitCount  int
}

// DAGMetrics metrics cho DAG execution
type DAGMetrics struct {
	NodesExecuted   int64
	SharedHits      int64
	CacheHits       int64
	CacheMisses     int64
	TotalExecutions int64
	AverageNodes    float64
	mu              sync.RWMutex
}

// Use ExecutionContext from types.go - removed duplicate

// NewDAGEngine tạo DAG engine mới
func NewDAGEngine(config *EngineConfig) *DAGEngine {
	engine := &DAGEngine{
		nodes:          make(map[string]*DAGNode),
		sharedNodes:    make(map[string]*SharedNode),
		executionCache: make(map[string]*CacheEntry),
		config:         config,
		metrics:        &DAGMetrics{},
		optimizer:      NewDAGOptimizer(DefaultOptimizerConfig()),
		matcher:        NewAdvancedMatcher(DefaultMatcherConfig()),
		profiler:       NewProfiler(nil),
	}

	// Initialize performance components if parallel processing is enabled
	if config.EnableParallelProcessing {
		engine.workerPool = NewWorkerPool(config.WorkerCount, config.BatchSize*2, engine)
		// Note: BatchProcessor from streaming.go has different signature, skip for now
	}

	return engine
}

// DAGBuilder builds optimized DAG from compiled rules
type DAGBuilder struct {
	config      *EngineConfig
	nodeMap     map[string]*DAGNode
	sharedNodes map[string]*SharedNode
}

// NewDAGBuilder tạo DAG builder mới
func NewDAGBuilder(config *EngineConfig) *DAGBuilder {
	return &DAGBuilder{
		config:      config,
		nodeMap:     make(map[string]*DAGNode),
		sharedNodes: make(map[string]*SharedNode),
	}
}

// BuildFromRules build DAG từ compiled rules
func (b *DAGBuilder) BuildFromRules(rules []*CompiledRule) (*DAGEngine, error) {
	engine := NewDAGEngine(b.config)
	engine.rules = rules

	// Phase 1: Collect all nodes
	for _, rule := range rules {
		b.collectNodes(rule.RootNode, rule.ID)
	}

	// Phase 2: Identify shared computation opportunities
	if b.config.EnableSharedComputation {
		b.identifySharedNodes()
	}

	// Phase 3: Build optimized DAG
	engine.nodes = b.nodeMap
	engine.sharedNodes = b.sharedNodes

	// Phase 4: Apply optimization if enabled
	if b.config.EnableOptimization {
		optimizationResult, err := engine.optimizer.OptimizeDAG(engine, rules)
		if err != nil {
			// Log warning but continue - optimization failure shouldn't break functionality
			fmt.Printf("⚠️ DAG optimization failed: %v\n", err)
		} else {
			fmt.Printf("✅ DAG optimization completed: %d→%d nodes, %v\n",
				optimizationResult.OriginalNodes,
				optimizationResult.OptimizedNodes,
				optimizationResult.OptimizationTime)
		}
	}

	return engine, nil
}

// collectNodes collect tất cả nodes từ rule tree
func (b *DAGBuilder) collectNodes(node *DAGNode, ruleID string) {
	if node == nil {
		return
	}

	// Check if node already exists (potential shared node)
	nodeKey := b.getNodeKey(node)
	if existing, exists := b.nodeMap[nodeKey]; exists {
		// Mark as shared
		if shared, sharedExists := b.sharedNodes[nodeKey]; sharedExists {
			shared.RuleIDs = append(shared.RuleIDs, ruleID)
			shared.UseCount++
		} else {
			b.sharedNodes[nodeKey] = &SharedNode{
				Node:     existing,
				RuleIDs:  []string{ruleID},
				UseCount: 2, // This is the second usage
				LastUsed: time.Now(),
			}
		}
	} else {
		// First occurrence
		b.nodeMap[nodeKey] = node
	}

	// Recursively collect children
	for _, child := range node.Children {
		b.collectNodes(child, ruleID)
	}
}

// getNodeKey tạo unique key cho node (cho shared computation)
func (b *DAGBuilder) getNodeKey(node *DAGNode) string {
	if node.Type == NodePrimitive && node.Primitive != nil {
		p := node.Primitive
		return fmt.Sprintf("primitive_%s_%s_%v", p.Field, string(p.Type), p.Value)
	}

	// For composite nodes, create key based on structure
	return fmt.Sprintf("%s_%s", string(node.Type), node.ID)
}

// identifySharedNodes identify nodes that can be shared
func (b *DAGBuilder) identifySharedNodes() {
	// Remove nodes that are only used once
	for key, shared := range b.sharedNodes {
		if shared.UseCount < 2 {
			delete(b.sharedNodes, key)
		}
	}
}

// Execute thực thi DAG với event
func (e *DAGEngine) Execute(event map[string]interface{}) ([]*RuleMatch, int, int, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.config.EnableDebugLogging {
		fmt.Printf("🔍 DAG Execute: Starting execution with %d rules\n", len(e.rules))
	}

	ctx := &ExecutionContext{
		Event:     event,
		Results:   make(map[string]bool),
		StartTime: time.Now(),
	}

	matches := make([]*RuleMatch, 0)

	// Evaluate each rule
	for _, rule := range e.rules {
		// fmt.Printf("🔍 Evaluating rule %d: %s (ID: %s)\n", i, rule.Title, rule.ID) // Debug disabled
		matched, err := e.evaluateRule(rule, ctx)
		if err != nil {
			return nil, ctx.NodesRan, ctx.SharedHits, fmt.Errorf("error evaluating rule %s: %w", rule.ID, err)
		}

		if matched {
			match := &RuleMatch{
				RuleID:        rule.ID,
				Title:         rule.Title,
				Level:         rule.Level,
				Tags:          rule.Tags,
				Description:   rule.Description,
				MatchedFields: e.extractMatchedFields(rule, event),
				Confidence:    1.0, // TODO: implement confidence scoring
			}
			matches = append(matches, match)
		}
	}

	// Update metrics
	e.metrics.mu.Lock()
	e.metrics.TotalExecutions++
	e.metrics.NodesExecuted += int64(ctx.NodesRan)
	e.metrics.SharedHits += int64(ctx.SharedHits)
	if e.metrics.TotalExecutions == 1 {
		e.metrics.AverageNodes = float64(ctx.NodesRan)
	} else {
		e.metrics.AverageNodes = (e.metrics.AverageNodes*float64(e.metrics.TotalExecutions-1) + float64(ctx.NodesRan)) / float64(e.metrics.TotalExecutions)
	}
	e.metrics.mu.Unlock()

	return matches, ctx.NodesRan, ctx.SharedHits, nil
}

// evaluateRule evaluate một rule với event
func (e *DAGEngine) evaluateRule(rule *CompiledRule, ctx *ExecutionContext) (bool, error) {
	// fmt.Printf("🔍 EvaluateRule: %s, RootNode=%v\n", rule.Title, rule.RootNode != nil) // Debug disabled

	if rule.RootNode == nil {
		// fmt.Printf("❌ Rule %s has no root node!\n", rule.Title) // Debug disabled
		return false, nil
	}

	// fmt.Printf("🔍 Root node type: %s\n", rule.RootNode.Type) // Debug disabled
	return e.evaluateNode(rule.RootNode, ctx)
}

// evaluateNode evaluate một DAG node
func (e *DAGEngine) evaluateNode(node *DAGNode, ctx *ExecutionContext) (bool, error) {
	if node == nil {
		return false, nil
	}

	ctx.NodesRan++

	// Check cache first
	if e.config.CacheSize > 0 {
		cacheKey := e.getCacheKey(node, ctx.Event)
		if entry, exists := e.executionCache[cacheKey]; exists {
			if time.Since(entry.Timestamp) < 5*time.Minute { // Cache TTL
				entry.HitCount++
				e.metrics.mu.Lock()
				e.metrics.CacheHits++
				e.metrics.mu.Unlock()
				return entry.Result, nil
			}
		}
	}

	var result bool
	var err error

	switch node.Type {
	case NodePrimitive:
		result, err = e.evaluatePrimitive(node.Primitive, ctx)
	case NodeAnd:
		result, err = e.evaluateAnd(node, ctx)
	case NodeOr:
		result, err = e.evaluateOr(node, ctx)
	case NodeNot:
		result, err = e.evaluateNot(node, ctx)
	default:
		return false, fmt.Errorf("unknown node type: %s", node.Type)
	}

	if err != nil {
		return false, err
	}

	// Cache result
	if e.config.CacheSize > 0 {
		cacheKey := e.getCacheKey(node, ctx.Event)
		e.cacheResult(cacheKey, result)
	}

	return result, nil
}

// evaluatePrimitive evaluate primitive operation
func (e *DAGEngine) evaluatePrimitive(primitive *Primitive, ctx *ExecutionContext) (bool, error) {
	if primitive == nil {
		return false, nil
	}

	if e.config.EnableDebugLogging {
		fmt.Printf("🔍 Evaluating Primitive: Field='%s', Type='%s', Value='%v'\n", primitive.Field, primitive.Type, primitive.Value)
	}

	// Check shared computation
	nodeKey := fmt.Sprintf("primitive_%s_%s_%v", primitive.Field, string(primitive.Type), primitive.Value)
	if result, exists := ctx.Results[nodeKey]; exists {
		ctx.SharedHits++
		return result, nil
	}

	// Get field value from event
	fieldValue, exists := e.getFieldValue(ctx.Event, primitive.Field)
	if e.config.EnableDebugLogging {
		fmt.Printf("🔍 Field lookup: Field='%s', Value='%v', Exists=%v\n", primitive.Field, fieldValue, exists)
	}

	var result bool

	switch primitive.Type {
	case PrimitiveExists:
		result = exists
	// PrimitiveNotExists removed - not in types.go
	case PrimitiveEquals:
		result = exists && e.compareEqual(fieldValue, primitive.Value)
	case PrimitiveContains:
		result = exists && e.compareContains(fieldValue, primitive.Value)
	case PrimitiveStartsWith:
		result = exists && e.compareStartsWith(fieldValue, primitive.Value)
	case PrimitiveEndsWith:
		result = exists && e.compareEndsWith(fieldValue, primitive.Value)
	case PrimitiveRegex:
		result = exists && e.compareRegex(fieldValue, primitive.CompiledRegex)
	case PrimitiveGreater:
		result = exists && e.compareGreaterThan(fieldValue, primitive.Value)
	case PrimitiveLess:
		result = exists && e.compareLessThan(fieldValue, primitive.Value)
	case PrimitiveIn:
		if e.config.EnableDebugLogging {
			fmt.Printf("🔍 PrimitiveIn: Values=%v, Value=%v\n", primitive.Values, primitive.Value)
		}
		if primitive.Values != nil && len(primitive.Values) > 0 {
			result = exists && e.compareIn(fieldValue, primitive.Values)
		} else {
			// Fallback for single value
			result = exists && e.compareEqual(fieldValue, primitive.Value)
		}
	default:
		return false, fmt.Errorf("unknown primitive type: %s", primitive.Type)
	}

	// Store result for shared computation
	ctx.Results[nodeKey] = result

	return result, nil
}

// evaluateAnd evaluate AND node
func (e *DAGEngine) evaluateAnd(node *DAGNode, ctx *ExecutionContext) (bool, error) {
	for _, child := range node.Children {
		result, err := e.evaluateNode(child, ctx)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil // Short-circuit evaluation
		}
	}
	return true, nil
}

// evaluateOr evaluate OR node
func (e *DAGEngine) evaluateOr(node *DAGNode, ctx *ExecutionContext) (bool, error) {
	for _, child := range node.Children {
		result, err := e.evaluateNode(child, ctx)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil // Short-circuit evaluation
		}
	}
	return false, nil
}

// evaluateNot evaluate NOT node
func (e *DAGEngine) evaluateNot(node *DAGNode, ctx *ExecutionContext) (bool, error) {
	if len(node.Children) != 1 {
		return false, fmt.Errorf("NOT node must have exactly one child")
	}

	result, err := e.evaluateNode(node.Children[0], ctx)
	if err != nil {
		return false, err
	}

	return !result, nil
}

// getFieldValue extract field value từ event (support nested fields)
func (e *DAGEngine) getFieldValue(event map[string]interface{}, field string) (interface{}, bool) {
	// Support nested field access với dot notation
	parts := strings.Split(field, ".")

	current := event
	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part
			value, exists := current[part]
			return value, exists
		} else {
			// Intermediate part
			if next, exists := current[part]; exists {
				if nextMap, ok := next.(map[string]interface{}); ok {
					current = nextMap
				} else {
					return nil, false
				}
			} else {
				return nil, false
			}
		}
	}

	return nil, false
}

// Comparison functions
func (e *DAGEngine) compareEqual(actual, expected interface{}) bool {
	// Handle string comparison
	if actualStr, ok1 := actual.(string); ok1 {
		if expectedStr, ok2 := expected.(string); ok2 {
			return strings.EqualFold(actualStr, expectedStr) // Case insensitive
		}
	}

	// Handle numeric comparison
	if actualNum := e.toNumber(actual); actualNum != nil {
		if expectedNum := e.toNumber(expected); expectedNum != nil {
			return *actualNum == *expectedNum
		}
	}

	// Fallback to deep equal
	return reflect.DeepEqual(actual, expected)
}

func (e *DAGEngine) compareContains(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false
	}
	return strings.Contains(strings.ToLower(actualStr), strings.ToLower(expectedStr))
}

func (e *DAGEngine) compareStartsWith(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false
	}
	return strings.HasPrefix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
}

func (e *DAGEngine) compareEndsWith(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false
	}

	// Debug endsWith comparison
	fmt.Printf("🔍 EndsWith Debug: actual='%s', expected='%s'\n", actualStr, expectedStr)

	// Normalize paths for Windows/Unix compatibility
	actualLower := strings.ToLower(actualStr)
	expectedLower := strings.ToLower(expectedStr)

	// Handle both forward and back slashes
	actualLower = strings.ReplaceAll(actualLower, "/", "\\")
	expectedLower = strings.ReplaceAll(expectedLower, "/", "\\")

	result := strings.HasSuffix(actualLower, expectedLower)
	fmt.Printf("🔍 EndsWith Result: %v (actual_lower='%s', expected_lower='%s')\n", result, actualLower, expectedLower)

	return result
}

func (e *DAGEngine) compareRegex(actual interface{}, regex *regexp.Regexp) bool {
	if regex == nil {
		return false
	}
	actualStr, ok := actual.(string)
	if !ok {
		return false
	}
	return regex.MatchString(actualStr)
}

func (e *DAGEngine) compareGreaterThan(actual, expected interface{}) bool {
	actualNum := e.toNumber(actual)
	expectedNum := e.toNumber(expected)
	if actualNum == nil || expectedNum == nil {
		return false
	}

	actualFloat := *actualNum
	expectedFloat := *expectedNum
	return actualFloat > expectedFloat
}

func (e *DAGEngine) compareLessThan(actual, expected interface{}) bool {
	actualNum := e.toNumber(actual)
	expectedNum := e.toNumber(expected)
	if actualNum == nil || expectedNum == nil {
		return false
	}

	actualFloat := *actualNum
	expectedFloat := *expectedNum
	return actualFloat < expectedFloat
}

func (e *DAGEngine) compareIn(actual interface{}, values []interface{}) bool {
	fmt.Printf("🔍 CompareIn Debug: actual='%v', values=%v (count: %d)\n", actual, values, len(values))

	for i, value := range values {
		fmt.Printf("  Checking [%d]: '%v' against actual '%v'\n", i, value, actual)

		// For string values, use case-insensitive comparison
		if actualStr, ok1 := actual.(string); ok1 {
			if valueStr, ok2 := value.(string); ok2 {
				if strings.EqualFold(actualStr, valueStr) {
					fmt.Printf("  ✅ MATCH found: '%s' == '%s'\n", actualStr, valueStr)
					return true
				}
				// Also check if actual string contains the value (for contains logic)
				if strings.Contains(strings.ToLower(actualStr), strings.ToLower(valueStr)) {
					fmt.Printf("  ✅ CONTAINS MATCH found: '%s' contains '%s'\n", actualStr, valueStr)
					return true
				}
				continue
			}
		}

		// For non-string values, use exact comparison
		if e.compareEqual(actual, value) {
			fmt.Printf("  ✅ EXACT MATCH found\n")
			return true
		}
	}

	fmt.Printf("  ❌ NO MATCH found\n")
	return false
}

// toNumber convert interface{} to float64
func (e *DAGEngine) toNumber(value interface{}) *float64 {
	switch v := value.(type) {
	case int:
		f := float64(v)
		return &f
	case int64:
		f := float64(v)
		return &f
	case float64:
		return &v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return &f
		}
	}
	return nil
}

// extractMatchedFields extract các fields đã match từ event
func (e *DAGEngine) extractMatchedFields(rule *CompiledRule, event map[string]interface{}) map[string]interface{} {
	matched := make(map[string]interface{})

	for _, primitive := range rule.Primitives {
		if value, exists := e.getFieldValue(event, primitive.Field); exists {
			matched[primitive.Field] = value
		}
	}

	return matched
}

// Cache management
func (e *DAGEngine) getCacheKey(node *DAGNode, event map[string]interface{}) string {
	if node.Type == NodePrimitive && node.Primitive != nil {
		if value, exists := e.getFieldValue(event, node.Primitive.Field); exists {
			return fmt.Sprintf("%s_%s_%v_%v", node.Primitive.Field, string(node.Primitive.Type), node.Primitive.Value, value)
		}
	}
	return fmt.Sprintf("%s_%s", string(node.Type), node.ID)
}

func (e *DAGEngine) cacheResult(key string, result bool) {
	// Simple LRU eviction if cache is full
	if len(e.executionCache) >= e.config.CacheSize {
		e.evictOldEntries()
	}

	e.executionCache[key] = &CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
		HitCount:  0,
	}

	e.metrics.mu.Lock()
	e.metrics.CacheMisses++
	e.metrics.mu.Unlock()
}

func (e *DAGEngine) evictOldEntries() {
	// Simple eviction - remove 10% of oldest entries
	toRemove := e.config.CacheSize / 10
	if toRemove == 0 {
		toRemove = 1
	}

	oldestTime := time.Now()
	oldestKeys := make([]string, 0, toRemove)

	for key, entry := range e.executionCache {
		if entry.Timestamp.Before(oldestTime) || len(oldestKeys) < toRemove {
			if len(oldestKeys) < toRemove {
				oldestKeys = append(oldestKeys, key)
				if entry.Timestamp.Before(oldestTime) {
					oldestTime = entry.Timestamp
				}
			} else {
				// Replace if this entry is older
				if entry.Timestamp.Before(oldestTime) {
					oldestKeys[0] = key
					oldestTime = entry.Timestamp
				}
			}
		}
	}

	for _, key := range oldestKeys {
		delete(e.executionCache, key)
	}
}

// ExecuteBatch high-performance batch execution
func (e *DAGEngine) ExecuteBatch(events []map[string]interface{}) ([]*DetectionResult, error) {
	if len(events) == 0 {
		return nil, nil
	}

	defer func() {
		if e.profiler != nil {
			e.profiler.RecordStreaming(len(events), false, 1.0)
		}
	}()

	// Use batch processor if available and enabled
	if e.batchProcessor != nil && e.config.EnableParallelProcessing {
		return e.executeBatchParallel(events)
	}

	// Sequential batch processing
	var allResults []*DetectionResult
	for _, event := range events {

		matches, _, _, err := e.Execute(event)
		if err != nil {
			continue // Skip errors in batch mode
		}

		// Convert RuleMatch to DetectionResult
		for _, match := range matches {
			allResults = append(allResults, &DetectionResult{
				RuleMatches:    []*RuleMatch{match},
				TotalMatches:   1,
				ProcessingTime: time.Microsecond,
				Metadata:       make(map[string]interface{}),
			})
		}
	}

	return allResults, nil
}

// executeBatchParallel high-performance parallel batch execution
func (e *DAGEngine) executeBatchParallel(events []map[string]interface{}) ([]*DetectionResult, error) {
	numWorkers := e.config.WorkerCount
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > len(events) {
		numWorkers = len(events)
	}

	type chunkResult struct {
		results []*DetectionResult
		err     error
	}

	resultsChan := make(chan chunkResult, numWorkers)
	chunkSize := len(events) / numWorkers
	if chunkSize == 0 {
		chunkSize = 1
	}

	var wg sync.WaitGroup

	// Process chunks in parallel
	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == numWorkers-1 {
			end = len(events) // Last worker takes remaining events
		}
		if start >= len(events) {
			break
		}

		wg.Add(1)
		go func(eventChunk []map[string]interface{}) {
			defer wg.Done()

			var chunkResults []*DetectionResult
			for _, event := range eventChunk {

				matches, _, _, err := e.Execute(event)
				if err == nil {
					// Convert RuleMatch to DetectionResult
					for _, match := range matches {
						chunkResults = append(chunkResults, &DetectionResult{
							RuleMatches:    []*RuleMatch{match},
							TotalMatches:   1,
							ProcessingTime: time.Microsecond,
							Metadata:       make(map[string]interface{}),
						})
					}
				}
			}

			resultsChan <- chunkResult{results: chunkResults}
		}(events[start:end])
	}

	// Wait for all workers and collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var allResults []*DetectionResult
	for result := range resultsChan {
		if result.err == nil {
			allResults = append(allResults, result.results...)
		}
	}

	return allResults, nil
}

// ExecuteAsync asynchronous execution với worker pool
func (e *DAGEngine) ExecuteAsync(event map[string]interface{}) <-chan *WorkResult {
	if e.workerPool == nil {
		// Fallback to synchronous execution
		resultChan := make(chan *WorkResult, 1)
		go func() {
			startTime := time.Now()

			matches, nodesRan, sharedHits, err := e.Execute(event)

			// Convert RuleMatch to DetectionResult
			var results []*DetectionResult
			for _, match := range matches {
				results = append(results, &DetectionResult{
					RuleMatches:    []*RuleMatch{match},
					TotalMatches:   1,
					ProcessingTime: time.Microsecond,
					Metadata:       make(map[string]interface{}),
				})
			}

			resultChan <- &WorkResult{
				ID:            fmt.Sprintf("sync-%d", time.Now().UnixNano()),
				Matches:       results,
				ExecutionTime: time.Since(startTime),
				NodesExecuted: nodesRan,
				SharedHits:    sharedHits,
				Error:         err,
			}
		}()
		return resultChan
	}

	return e.workerPool.ProcessAsync(event)
}

// StartPerformanceComponents khởi động performance components
func (e *DAGEngine) StartPerformanceComponents() {
	if e.workerPool != nil {
		e.workerPool.Start()
	}
	// BatchProcessor start removed due to type conflicts
}

// StopPerformanceComponents dừng performance components
func (e *DAGEngine) StopPerformanceComponents() {
	if e.workerPool != nil {
		e.workerPool.Stop()
	}
	// BatchProcessor stop removed due to type conflicts
}

// GetPerformanceMetrics trả về comprehensive performance metrics
func (e *DAGEngine) GetPerformanceMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// DAG metrics
	e.metrics.mu.RLock()
	metrics["dag"] = map[string]interface{}{
		"nodes_executed":   e.metrics.NodesExecuted,
		"shared_hits":      e.metrics.SharedHits,
		"cache_hits":       e.metrics.CacheHits,
		"cache_misses":     e.metrics.CacheMisses,
		"total_executions": e.metrics.TotalExecutions,
		"average_nodes":    e.metrics.AverageNodes,
	}
	e.metrics.mu.RUnlock()

	// Worker pool metrics
	if e.workerPool != nil {
		metrics["worker_pool"] = e.workerPool.GetMetrics()
	}

	// Batch processor metrics removed due to type conflicts

	// Profiler metrics
	if e.profiler != nil {
		metrics["profiler"] = e.profiler.GetMetrics()
	}

	return metrics
}

// NodeCount trả về số lượng nodes trong DAG
func (e *DAGEngine) NodeCount() int {
	return len(e.nodes)
}

// Shutdown cleanup resources
func (e *DAGEngine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear caches
	e.executionCache = make(map[string]*CacheEntry)
	e.sharedNodes = make(map[string]*SharedNode)

	return nil
}
