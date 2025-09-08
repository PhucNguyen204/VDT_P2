package sigma

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	//import file c
)

// AdvancedMatcher high-performance matcher với cache, hooks và modifiers
// Inspired by cawalch/sigma-engine matcher module
type AdvancedMatcher struct {
	cache     *MatcherCache
	hooks     []MatchHook
	modifiers map[string]Modifier
	context   *MatcherContext
	config    *MatcherConfig
	metrics   *MatcherMetrics
	mu        sync.RWMutex
}

// MatcherConfig cấu hình cho Advanced Matcher
type MatcherConfig struct {
	EnableCache         bool          `json:"enable_cache"`
	CacheSize           int           `json:"cache_size"`
	CacheTTL            time.Duration `json:"cache_ttl"`
	EnableHooks         bool          `json:"enable_hooks"`
	EnableModifiers     bool          `json:"enable_modifiers"`
	MaxRecursionDepth   int           `json:"max_recursion_depth"`
	MatchTimeout        time.Duration `json:"match_timeout"`
	CaseSensitive       bool          `json:"case_sensitive"`
	EnableFuzzyMatching bool          `json:"enable_fuzzy_matching"`
	FuzzyThreshold      float64       `json:"fuzzy_threshold"`
}

// DefaultMatcherConfig trả về cấu hình mặc định
func DefaultMatcherConfig() *MatcherConfig {
	return &MatcherConfig{
		EnableCache:         true,
		CacheSize:           10000,
		CacheTTL:            5 * time.Minute,
		EnableHooks:         true,
		EnableModifiers:     true,
		MaxRecursionDepth:   10,
		MatchTimeout:        100 * time.Millisecond,
		CaseSensitive:       false,
		EnableFuzzyMatching: false,
		FuzzyThreshold:      0.8,
	}
}

// MatcherCache cache cho match results
type MatcherCache struct {
	entries map[string]*MatchCacheEntry
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

// MatchCacheEntry entry trong cache
type MatchCacheEntry struct {
	Result     bool
	Confidence MatchConfidence
	Timestamp  time.Time
	HitCount   int
	LastAccess time.Time
}

// MatchHook hook function cho matching events
type MatchHook func(ctx context.Context, primitive *Primitive, event map[string]interface{}, result bool) error

// Modifier function để modify giá trị trước matching
type Modifier func(value interface{}) interface{}

// MatcherContext context cho matching operations
type MatcherContext struct {
	Event        map[string]interface{}
	Rules        []*CompiledRule
	CurrentRule  *CompiledRule
	CurrentDepth int
	StartTime    time.Time
	TraceID      string
	Metadata     map[string]interface{}
	CancelFunc   context.CancelFunc
}

// MatcherMetrics metrics cho matcher
type MatcherMetrics struct {
	MatchesAttempted  int64         `json:"matches_attempted"`
	MatchesSuccessful int64         `json:"matches_successful"`
	CacheHits         int64         `json:"cache_hits"`
	CacheMisses       int64         `json:"cache_misses"`
	HooksExecuted     int64         `json:"hooks_executed"`
	ModifiersApplied  int64         `json:"modifiers_applied"`
	AverageMatchTime  time.Duration `json:"average_match_time"`
	TimeoutOccurred   int64         `json:"timeout_occurred"`
	ErrorsOccurred    int64         `json:"errors_occurred"`
	mu                sync.RWMutex
}

// NewAdvancedMatcher tạo advanced matcher mới
func NewAdvancedMatcher(config *MatcherConfig) *AdvancedMatcher {
	if config == nil {
		config = DefaultMatcherConfig()
	}

	matcher := &AdvancedMatcher{
		config:    config,
		modifiers: make(map[string]Modifier),
		metrics:   &MatcherMetrics{},
	}

	if config.EnableCache {
		matcher.cache = NewMatcherCache(config.CacheSize, config.CacheTTL)
	}

	// Register default modifiers
	matcher.registerDefaultModifiers()

	return matcher
}

// NewMatcherCache tạo cache mới
func NewMatcherCache(maxSize int, ttl time.Duration) *MatcherCache {
	return &MatcherCache{
		entries: make(map[string]*MatchCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Match thực hiện advanced matching với cache, hooks và modifiers
func (m *AdvancedMatcher) Match(primitive *Primitive, event map[string]interface{}) (bool, MatchConfidence, error) {
	start := time.Now()
	m.metrics.mu.Lock()
	m.metrics.MatchesAttempted++
	m.metrics.mu.Unlock()

	defer func() {
		duration := time.Since(start)
		m.metrics.mu.Lock()
		if m.metrics.MatchesAttempted == 1 {
			m.metrics.AverageMatchTime = duration
		} else {
			m.metrics.AverageMatchTime = time.Duration(
				(int64(m.metrics.AverageMatchTime)*(m.metrics.MatchesAttempted-1) + int64(duration)) / m.metrics.MatchesAttempted,
			)
		}
		m.metrics.mu.Unlock()
	}()

	// Create context với timeout
	ctx, cancel := context.WithTimeout(context.Background(), m.config.MatchTimeout)
	defer cancel()

	// Check cache first
	if m.config.EnableCache && m.cache != nil {
		cacheKey := m.generateCacheKey(primitive, event)
		if result, confidence, found := m.cache.Get(cacheKey); found {
			m.metrics.mu.Lock()
			m.metrics.CacheHits++
			m.metrics.mu.Unlock()
			return result, confidence, nil
		}
		m.metrics.mu.Lock()
		m.metrics.CacheMisses++
		m.metrics.mu.Unlock()
	}

	// Execute pre-match hooks
	if m.config.EnableHooks {
		for _, hook := range m.hooks {
			if err := hook(ctx, primitive, event, false); err != nil {
				m.metrics.mu.Lock()
				m.metrics.ErrorsOccurred++
				m.metrics.mu.Unlock()
				return false, ConfidenceLow, fmt.Errorf("pre-match hook failed: %w", err)
			}
			m.metrics.mu.Lock()
			m.metrics.HooksExecuted++
			m.metrics.mu.Unlock()
		}
	}

	// Perform actual matching với modifiers
	result, confidence, err := m.performMatch(ctx, primitive, event)
	if err != nil {
		m.metrics.mu.Lock()
		m.metrics.ErrorsOccurred++
		m.metrics.mu.Unlock()
		return false, ConfidenceLow, err
	}

	// Execute post-match hooks
	if m.config.EnableHooks {
		for _, hook := range m.hooks {
			if err := hook(ctx, primitive, event, result); err != nil {
				// Log warning but don't fail the match
				fmt.Printf("⚠️ Post-match hook failed: %v\n", err)
			}
			m.metrics.mu.Lock()
			m.metrics.HooksExecuted++
			m.metrics.mu.Unlock()
		}
	}

	// Cache result
	if m.config.EnableCache && m.cache != nil {
		cacheKey := m.generateCacheKey(primitive, event)
		m.cache.Set(cacheKey, result, confidence)
	}

	if result {
		m.metrics.mu.Lock()
		m.metrics.MatchesSuccessful++
		m.metrics.mu.Unlock()
	}

	return result, confidence, nil
}

// performMatch thực hiện matching logic với modifiers
func (m *AdvancedMatcher) performMatch(ctx context.Context, primitive *Primitive, event map[string]interface{}) (bool, MatchConfidence, error) {
	// Get field value
	fieldValue, exists := m.getFieldValue(event, primitive.Field)
	if !exists {
		return false, ConfidenceLow, nil
	}

	// Apply modifiers if enabled
	if m.config.EnableModifiers {
		fieldValue = m.applyModifiers(fieldValue, primitive)
	}

	// Check for timeout
	select {
	case <-ctx.Done():
		m.metrics.mu.Lock()
		m.metrics.TimeoutOccurred++
		m.metrics.mu.Unlock()
		return false, ConfidenceLow, fmt.Errorf("match timeout exceeded")
	default:
	}

	// Perform type-specific matching
	switch primitive.Type {
	case PrimitiveEquals:
		return m.matchEquals(fieldValue, primitive.Value), ConfidenceHigh, nil
	case PrimitiveContains:
		return m.matchContains(fieldValue, primitive.Value), ConfidenceHigh, nil
	case PrimitiveStartsWith:
		return m.matchStartsWith(fieldValue, primitive.Value), ConfidenceHigh, nil
	case PrimitiveEndsWith:
		return m.matchEndsWith(fieldValue, primitive.Value), ConfidenceHigh, nil
	case PrimitiveRegex:
		return m.matchRegex(fieldValue, primitive.Value)
	case PrimitiveIn:
		return m.matchIn(fieldValue, primitive.Values), ConfidenceHigh, nil
	case PrimitiveGreater:
		return m.matchGreater(fieldValue, primitive.Value), ConfidenceMedium, nil
	case PrimitiveLess:
		return m.matchLess(fieldValue, primitive.Value), ConfidenceMedium, nil
	case PrimitiveExists:
		return exists, ConfidenceMax, nil
	default:
		return false, ConfidenceLow, fmt.Errorf("unknown primitive type: %s", primitive.Type)
	}
}

// Matching implementations với fuzzy support
func (m *AdvancedMatcher) matchEquals(actual, expected interface{}) bool {
	if m.config.EnableFuzzyMatching {
		return m.fuzzyEquals(actual, expected)
	}

	if !m.config.CaseSensitive {
		if actualStr, ok1 := actual.(string); ok1 {
			if expectedStr, ok2 := expected.(string); ok2 {
				return strings.EqualFold(actualStr, expectedStr)
			}
		}
	}

	return actual == expected
}

func (m *AdvancedMatcher) matchContains(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false
	}

	if !m.config.CaseSensitive {
		actualStr = strings.ToLower(actualStr)
		expectedStr = strings.ToLower(expectedStr)
	}

	return strings.Contains(actualStr, expectedStr)
}

func (m *AdvancedMatcher) matchStartsWith(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false
	}

	if !m.config.CaseSensitive {
		actualStr = strings.ToLower(actualStr)
		expectedStr = strings.ToLower(expectedStr)
	}

	return strings.HasPrefix(actualStr, expectedStr)
}

func (m *AdvancedMatcher) matchEndsWith(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false
	}

	if !m.config.CaseSensitive {
		actualStr = strings.ToLower(actualStr)
		expectedStr = strings.ToLower(expectedStr)
	}

	return strings.HasSuffix(actualStr, expectedStr)
}

func (m *AdvancedMatcher) matchRegex(actual, expected interface{}) (bool, MatchConfidence, error) {
	actualStr, ok1 := actual.(string)
	patternStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return false, ConfidenceLow, nil
	}

	regex, err := regexp.Compile(patternStr)
	if err != nil {
		return false, ConfidenceLow, fmt.Errorf("invalid regex pattern: %w", err)
	}

	return regex.MatchString(actualStr), ConfidenceMedium, nil
}

func (m *AdvancedMatcher) matchIn(actual interface{}, values []interface{}) bool {
	for _, value := range values {
		if m.matchEquals(actual, value) {
			return true
		}
	}
	return false
}

func (m *AdvancedMatcher) matchGreater(actual, expected interface{}) bool {
	actualNum, err1 := m.toNumber(actual)
	expectedNum, err2 := m.toNumber(expected)
	if err1 != nil || err2 != nil {
		return false
	}
	return actualNum > expectedNum
}

func (m *AdvancedMatcher) matchLess(actual, expected interface{}) bool {
	actualNum, err1 := m.toNumber(actual)
	expectedNum, err2 := m.toNumber(expected)
	if err1 != nil || err2 != nil {
		return false
	}
	return actualNum < expectedNum
}

// Fuzzy matching implementation
func (m *AdvancedMatcher) fuzzyEquals(actual, expected interface{}) bool {
	actualStr, ok1 := actual.(string)
	expectedStr, ok2 := expected.(string)
	if !ok1 || !ok2 {
		return actual == expected
	}

	similarity := m.calculateStringSimilarity(actualStr, expectedStr)
	return similarity >= m.config.FuzzyThreshold
}

// calculateStringSimilarity calculates Levenshtein distance based similarity
func (m *AdvancedMatcher) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	distance := m.levenshteinDistance(s1, s2)
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	return 1.0 - float64(distance)/float64(maxLen)
}

// levenshteinDistance calculates Levenshtein distance
func (m *AdvancedMatcher) levenshteinDistance(s1, s2 string) int {
	runes1 := []rune(s1)
	runes2 := []rune(s2)

	rows := len(runes1) + 1
	cols := len(runes2) + 1

	matrix := make([][]int, rows)
	for i := range matrix {
		matrix[i] = make([]int, cols)
		matrix[i][0] = i
	}

	for j := 0; j < cols; j++ {
		matrix[0][j] = j
	}

	for i := 1; i < rows; i++ {
		for j := 1; j < cols; j++ {
			cost := 0
			if runes1[i-1] != runes2[j-1] {
				cost = 1
			}

			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[rows-1][cols-1]
}

func min(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

// Helper functions
func (m *AdvancedMatcher) getFieldValue(event map[string]interface{}, field string) (interface{}, bool) {
	// Support nested field access với dot notation
	if strings.Contains(field, ".") {
		return m.getNestedFieldValue(event, field)
	}

	value, exists := event[field]
	return value, exists
}

func (m *AdvancedMatcher) getNestedFieldValue(event map[string]interface{}, field string) (interface{}, bool) {
	parts := strings.Split(field, ".")
	current := event

	for i, part := range parts {
		if i == len(parts)-1 {
			value, exists := current[part]
			return value, exists
		}

		next, exists := current[part]
		if !exists {
			return nil, false
		}

		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, false
		}

		current = nextMap
	}

	return nil, false
}

func (m *AdvancedMatcher) toNumber(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to number", value)
	}
}

func (m *AdvancedMatcher) generateCacheKey(primitive *Primitive, event map[string]interface{}) string {
	fieldValue, _ := m.getFieldValue(event, primitive.Field)
	return fmt.Sprintf("%s:%s:%v:%v", primitive.Type, primitive.Field, primitive.Value, fieldValue)
}

func (m *AdvancedMatcher) applyModifiers(value interface{}, primitive *Primitive) interface{} {
	// Apply modifiers based on primitive type or field
	for name, modifier := range m.modifiers {
		if m.shouldApplyModifier(name, primitive) {
			value = modifier(value)
			m.metrics.mu.Lock()
			m.metrics.ModifiersApplied++
			m.metrics.mu.Unlock()
		}
	}
	return value
}

func (m *AdvancedMatcher) shouldApplyModifier(modifierName string, primitive *Primitive) bool {
	// Logic to determine if modifier should be applied
	// This could be based on field name, primitive type, etc.
	return strings.Contains(primitive.Field, "password") && modifierName == "hash"
}

// Cache operations
func (c *MatcherCache) Get(key string) (bool, MatchConfidence, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return false, ConfidenceLow, false
	}

	// Check TTL
	if time.Since(entry.Timestamp) > c.ttl {
		delete(c.entries, key)
		return false, ConfidenceLow, false
	}

	entry.HitCount++
	entry.LastAccess = time.Now()

	return entry.Result, entry.Confidence, true
}

func (c *MatcherCache) Set(key string, result bool, confidence MatchConfidence) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Implement LRU eviction if cache is full
	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	c.entries[key] = &MatchCacheEntry{
		Result:     result,
		Confidence: confidence,
		Timestamp:  time.Now(),
		HitCount:   0,
		LastAccess: time.Now(),
	}
}

func (c *MatcherCache) evictLRU() {
	if len(c.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range c.entries {
		if entry.LastAccess.Before(oldestTime) {
			oldestTime = entry.LastAccess
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// Hook management
func (m *AdvancedMatcher) AddHook(hook MatchHook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, hook)
}

func (m *AdvancedMatcher) RemoveAllHooks() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = m.hooks[:0]
}

// Modifier management
func (m *AdvancedMatcher) AddModifier(name string, modifier Modifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modifiers[name] = modifier
}

func (m *AdvancedMatcher) registerDefaultModifiers() {
	// Hash modifier for password fields
	m.AddModifier("hash", func(value interface{}) interface{} {
		if str, ok := value.(string); ok {
			// Simple hash for demonstration
			return fmt.Sprintf("hash_%s", str)
		}
		return value
	})

	// Lowercase modifier
	m.AddModifier("lowercase", func(value interface{}) interface{} {
		if str, ok := value.(string); ok {
			return strings.ToLower(str)
		}
		return value
	})

	// Trim modifier
	m.AddModifier("trim", func(value interface{}) interface{} {
		if str, ok := value.(string); ok {
			return strings.TrimSpace(str)
		}
		return value
	})
}

// GetMetrics returns current matcher metrics
func (m *AdvancedMatcher) GetMetrics() *MatcherMetrics {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	// Return copy
	return &MatcherMetrics{
		MatchesAttempted:  m.metrics.MatchesAttempted,
		MatchesSuccessful: m.metrics.MatchesSuccessful,
		CacheHits:         m.metrics.CacheHits,
		CacheMisses:       m.metrics.CacheMisses,
		HooksExecuted:     m.metrics.HooksExecuted,
		ModifiersApplied:  m.metrics.ModifiersApplied,
		AverageMatchTime:  m.metrics.AverageMatchTime,
		TimeoutOccurred:   m.metrics.TimeoutOccurred,
		ErrorsOccurred:    m.metrics.ErrorsOccurred,
	}
}
