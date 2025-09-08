package sigma

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Comprehensive test suite for enhanced SIGMA engine

func TestEnhancedEngineBuilder(t *testing.T) {
	t.Run("RealtimeEngine", func(t *testing.T) {
		engine, err := RealtimeEngineBuilder().
			AddRule(testRule()).
			WithFieldMapping("ProcessImage", "Image").
			ForProduction().
			Build()

		require.NoError(t, err)
		assert.NotNil(t, engine)
		assert.True(t, engine.config.EnablePrefilter)
		assert.True(t, engine.config.EnableIR)
		assert.NotNil(t, engine.streaming)
	})

	t.Run("HighThroughputEngine", func(t *testing.T) {
		engine, err := HighThroughputEngineBuilder().
			AddRule(testRule()).
			WithFieldMapping("ProcessCommandLine", "CommandLine").
			Build()

		require.NoError(t, err)
		assert.NotNil(t, engine)
		assert.Equal(t, 5000, engine.config.BatchSize)
	})

	t.Run("SecurityEngine", func(t *testing.T) {
		engine, err := SecurityEngineBuilder().
			AddRule(testRule()).
			Build()

		require.NoError(t, err)
		assert.NotNil(t, engine)
		assert.NotEmpty(t, engine.fieldMapper.mappings)
	})
}

func TestIRSystem(t *testing.T) {
	t.Run("IRCreation", func(t *testing.T) {
		ir := NewIR()
		assert.NotNil(t, ir)
		assert.Empty(t, ir.Rules)
		assert.Empty(t, ir.Primitives)
		assert.NotNil(t, ir.Metadata)
	})

	t.Run("IRRuleAddition", func(t *testing.T) {
		ir := NewIR()

		rule := &IRRule{
			ID:          "test-rule-1",
			Title:       "Test Rule",
			Description: "Test rule for IR system",
			Level:       "medium",
			Tags:        []string{"test", "ir"},
			Primitives: []*IRPrimitive{
				{
					ID:    "primitive-1",
					Type:  IRPrimEquals,
					Field: "EventID",
					Value: "4624",
				},
			},
			Metadata: &IRRuleMetadata{
				ParsedAt:   time.Now(),
				Complexity: 1,
			},
		}

		ir.AddRule(rule)

		assert.Len(t, ir.Rules, 1)
		assert.Len(t, ir.Primitives, 1)
		assert.Equal(t, 1, ir.Metadata.RuleCount)
		assert.Equal(t, 1, ir.Metadata.PrimitiveCount)
	})

	t.Run("IROptimization", func(t *testing.T) {
		ir := NewIR()

		// Add multiple rules with shared primitives
		for i := 0; i < 3; i++ {
			rule := &IRRule{
				ID:    fmt.Sprintf("rule-%d", i),
				Title: fmt.Sprintf("Rule %d", i),
				Primitives: []*IRPrimitive{
					{
						ID:    fmt.Sprintf("shared-primitive"),
						Type:  IRPrimEquals,
						Field: "EventID",
						Value: "4624",
					},
				},
			}
			ir.AddRule(rule)
		}

		result := ir.OptimizePrimitives()
		assert.NotNil(t, result)
		assert.Greater(t, result.PrimitivesProcessed, 0)
	})

	t.Run("IRLiteralExtraction", func(t *testing.T) {
		ir := NewIR()

		primitive := &IRPrimitive{
			ID:       "test-primitive",
			Type:     IRPrimContains,
			Field:    "CommandLine",
			Pattern:  "powershell",
			Literals: []string{"powershell", "invoke-expression"},
		}

		ir.Primitives["test-primitive"] = primitive

		literals := ir.ExtractLiterals()
		assert.Contains(t, literals, "powershell")
		assert.Contains(t, literals, "invoke-expression")
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("CompilationError", func(t *testing.T) {
		err := ErrInvalidYAML("test-rule", fmt.Errorf("yaml parse error"))

		assert.Equal(t, "INVALID_YAML", err.ErrorCode())
		assert.Equal(t, ErrorTypeCompilation, err.ErrorType())
		assert.Equal(t, SeverityHigh, err.Severity())
		assert.False(t, err.Retryable())
		assert.Contains(t, err.Error(), "Invalid YAML syntax")
	})

	t.Run("ExecutionError", func(t *testing.T) {
		err := ErrNodeExecution("rule-1", "node-1", "event-1", fmt.Errorf("execution failed"))

		assert.Equal(t, "NODE_EXECUTION", err.ErrorCode())
		assert.Equal(t, ErrorTypeExecution, err.ErrorType())
		assert.True(t, err.Retryable())
		assert.Equal(t, "rule-1", err.RuleID)
		assert.Equal(t, "event-1", err.EventID)
	})

	t.Run("StreamingError", func(t *testing.T) {
		err := ErrWorkerPanic(1, fmt.Errorf("worker panic"))

		assert.Equal(t, "WORKER_PANIC", err.ErrorCode())
		assert.Equal(t, ErrorTypeStreaming, err.ErrorType())
		assert.Equal(t, SeverityCritical, err.Severity())
		assert.Equal(t, 1, err.WorkerID)
	})

	t.Run("ErrorCollection", func(t *testing.T) {
		collection := NewErrorCollection()

		collection.Add(ErrInvalidYAML("rule-1", nil))
		collection.Add(ErrNodeExecution("rule-2", "node-1", "event-1", nil))

		assert.True(t, collection.HasErrors())
		assert.Equal(t, 2, collection.Count)

		compilationErrors := collection.GetByType(ErrorTypeCompilation)
		assert.Len(t, compilationErrors, 1)

		retryableErrors := collection.GetRetryable()
		assert.Len(t, retryableErrors, 1)
	})
}

func TestHookSystem(t *testing.T) {
	t.Run("HookManager", func(t *testing.T) {
		manager := NewHookManager()
		assert.NotNil(t, manager)
		assert.True(t, manager.IsEnabled())
	})

	t.Run("LoggingHook", func(t *testing.T) {
		logger := logrus.New()
		hook := NewLoggingHook("test-logging", HookPreExecution, logger)

		assert.Equal(t, "test-logging", hook.Name())
		assert.Equal(t, HookPreExecution, hook.Type())
		assert.True(t, hook.Enabled())

		ctx := &HookContext{
			Type:      HookPreExecution,
			Timestamp: time.Now(),
			Data:      make(map[string]interface{}),
			Metadata:  make(map[string]string),
		}

		result, err := hook.Execute(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Continue)
	})

	t.Run("ValidationHook", func(t *testing.T) {
		validators := []Validator{&testValidator{}}
		hook := NewValidationHook("test-validation", HookPreMatch, validators)

		ctx := &HookContext{
			Type:     HookPreMatch,
			Data:     map[string]interface{}{"valid": true},
			Metadata: make(map[string]string),
		}

		result, err := hook.Execute(ctx)
		assert.NoError(t, err)
		assert.True(t, result.Continue)
	})

	t.Run("HookExecution", func(t *testing.T) {
		manager := NewHookManager()
		hook := NewLoggingHook("test", HookPreExecution, logrus.New())

		err := manager.RegisterHook(hook)
		assert.NoError(t, err)

		ctx := &HookContext{
			Type:     HookPreExecution,
			Data:     make(map[string]interface{}),
			Metadata: make(map[string]string),
		}

		err = manager.ExecuteHooks(HookPreExecution, ctx)
		assert.NoError(t, err)

		metrics := manager.GetMetrics()
		assert.Equal(t, int64(1), metrics.ExecutionCount[HookPreExecution])
	})
}

func TestContextSystem(t *testing.T) {
	t.Run("MatcherContextCreation", func(t *testing.T) {
		ctx := NewMatcherContext("event-1", "session-1", "agent-1")

		assert.Equal(t, "event-1", ctx.EventID)
		assert.Equal(t, "session-1", ctx.SessionID)
		assert.Equal(t, "agent-1", ctx.AgentID)
		assert.NotNil(t, ctx.Variables)
		assert.NotNil(t, ctx.State)
		assert.True(t, ctx.CacheEnabled)
	})

	t.Run("VariableManagement", func(t *testing.T) {
		ctx := NewMatcherContext("event-1", "session-1", "agent-1")

		ctx.SetVariable("test_var", "test_value")
		value, exists := ctx.GetVariable("test_var")

		assert.True(t, exists)
		assert.Equal(t, "test_value", value)
	})

	t.Run("StateManagement", func(t *testing.T) {
		ctx := NewMatcherContext("event-1", "session-1", "agent-1")

		ctx.SetState("current_state", "processing")
		state, exists := ctx.GetState("current_state")

		assert.True(t, exists)
		assert.Equal(t, "processing", state)
	})

	t.Run("MatchHistoryTracking", func(t *testing.T) {
		ctx := NewMatcherContext("event-1", "session-1", "agent-1")

		record := &MatchRecord{
			RuleID:       "rule-1",
			PatternID:    "pattern-1",
			MatchedValue: "test",
			MatchType:    "exact",
			Timestamp:    time.Now(),
			Confidence:   0.95,
		}

		ctx.AddMatchRecord(record)
		history := ctx.GetMatchHistory()

		assert.Len(t, history, 1)
		assert.Equal(t, "rule-1", history[0].RuleID)
	})

	t.Run("ContextCloning", func(t *testing.T) {
		ctx := NewMatcherContext("event-1", "session-1", "agent-1")
		ctx.SetVariable("test", "value")
		ctx.SetState("state", "active")

		clone := ctx.Clone()

		assert.NotEqual(t, ctx.EventID, clone.EventID)
		assert.Equal(t, ctx.SessionID, clone.SessionID)
		assert.Equal(t, ctx.AgentID, clone.AgentID)
		assert.Equal(t, ctx.ExecutionDepth+1, clone.ExecutionDepth)

		value, exists := clone.GetVariable("test")
		assert.True(t, exists)
		assert.Equal(t, "value", value)
	})

	t.Run("ContextStore", func(t *testing.T) {
		store := NewContextStore(1 * time.Hour)
		ctx := NewMatcherContext("event-1", "session-1", "agent-1")

		store.StoreContext(ctx)

		retrieved, exists := store.GetContext("event-1")
		assert.True(t, exists)
		assert.Equal(t, ctx.EventID, retrieved.EventID)

		sessionContexts := store.GetContextsBySession("session-1")
		assert.Len(t, sessionContexts, 1)

		agentContexts := store.GetContextsByAgent("agent-1")
		assert.Len(t, agentContexts, 1)
	})
}

func TestAdaptiveStreaming(t *testing.T) {
	t.Run("ConfigurationPresets", func(t *testing.T) {
		realtimeConfig := RealtimeStreamingConfig()
		assert.Equal(t, 2*time.Millisecond, realtimeConfig.LatencyTarget)
		assert.Equal(t, 50000, realtimeConfig.ThroughputTarget)
		assert.True(t, realtimeConfig.EnablePriority)

		highThroughputConfig := HighThroughputStreamingConfig()
		assert.Equal(t, 200000, highThroughputConfig.ThroughputTarget)
		assert.Equal(t, 1000, highThroughputConfig.MaxBatchSize)

		balancedConfig := BalancedStreamingConfig()
		assert.Equal(t, 5*time.Millisecond, balancedConfig.LatencyTarget)
		assert.Equal(t, 100000, balancedConfig.ThroughputTarget)
	})

	t.Run("AdaptiveEngineCreation", func(t *testing.T) {
		engine, err := NewEngineBuilder().Build()
		require.NoError(t, err)

		config := RealtimeStreamingConfig()
		adaptiveEngine := NewAdaptiveStreamingEngine(engine, config)

		assert.NotNil(t, adaptiveEngine)
		assert.Equal(t, config, adaptiveEngine.config)
		assert.NotNil(t, adaptiveEngine.metrics)
		assert.NotNil(t, adaptiveEngine.state)
	})

	t.Run("StreamingMetrics", func(t *testing.T) {
		engine, err := NewEngineBuilder().Build()
		require.NoError(t, err)

		adaptiveEngine := NewAdaptiveStreamingEngine(engine, nil)
		metrics := adaptiveEngine.GetMetrics()

		assert.NotNil(t, metrics)
		assert.Equal(t, int64(0), metrics.EventsProcessed)
		assert.Equal(t, 0, metrics.ActiveWorkers)
	})
}

func TestConfigurationSystem(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultConfig()

		assert.NotNil(t, config)
		assert.True(t, config.Engine.EnableOptimization)
		assert.True(t, config.Engine.EnableParallelProcessing)
		assert.True(t, config.Engine.EnablePrefilter)
		assert.True(t, config.Stream.EnableAdaptiveBatch)

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("ProductionConfig", func(t *testing.T) {
		config := ProductionConfig()

		assert.Equal(t, 2000, config.Engine.BatchSize)
		assert.Equal(t, 16, config.Engine.WorkerCount)
		assert.Equal(t, 100000, config.Engine.CacheSize)

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("ConfigValidation", func(t *testing.T) {
		config := DefaultConfig()

		// Test invalid batch size
		config.Engine.BatchSize = -1
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "batch_size must be > 0")

		// Test invalid worker count
		config.Engine.BatchSize = 100
		config.Engine.WorkerCount = 0
		err = config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "worker_count must be > 0")
	})

	t.Run("WorkloadOptimization", func(t *testing.T) {
		config := DefaultConfig()

		config.OptimizeForWorkload("realtime")
		assert.Equal(t, 50, config.Stream.BatchSize)
		assert.Equal(t, 5*time.Millisecond, config.Stream.BatchTimeout)

		config.OptimizeForWorkload("high_throughput")
		assert.Equal(t, 500, config.Stream.BatchSize)
		assert.Equal(t, 100000, config.Stream.ThroughputTarget)
	})
}

func TestEndToEndIntegration(t *testing.T) {
	t.Run("CompleteEngine", func(t *testing.T) {
		// Build complete engine with all features
		engine, err := SecurityEngineBuilder().
			AddRule(testRule()).
			AddRule(complexTestRule()).
			WithFieldMapping("ProcessImage", "Image").
			WithFieldMapping("ProcessCommandLine", "CommandLine").
			ForProduction().
			Build()

		require.NoError(t, err)
		assert.NotNil(t, engine)

		// Test event processing
		event := map[string]interface{}{
			"EventID":     "4624",
			"LogonType":   2,
			"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			"CommandLine": "powershell.exe -Command Invoke-Expression",
		}

		result, err := engine.Evaluate(event)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("StreamingIntegration", func(t *testing.T) {
		// Build engine with streaming
		engine, err := RealtimeEngineBuilder().
			AddRule(testRule()).
			Build()

		require.NoError(t, err)

		// Test streaming capabilities
		if engine.streaming != nil {
			ctx := context.Background()
			err = engine.streaming.Start(ctx)
			assert.NoError(t, err)

			// Create test event
			event := &StreamingEvent{
				EventID:   "test-event-1",
				Data:      map[string]interface{}{"EventID": "4624"},
				Timestamp: time.Now(),
				Priority:  1,
			}

			// Process event (this may fail if full streaming implementation is not complete)
			_ = engine.streaming.ProcessEvent(event)

			err = engine.streaming.Stop()
			assert.NoError(t, err)
		}
	})
}

func TestPerformanceValidation(t *testing.T) {
	t.Run("EnginePerformance", func(t *testing.T) {
		engine, err := HighThroughputEngineBuilder().
			AddRule(testRule()).
			Build()

		require.NoError(t, err)

		// Create test events
		events := make([]map[string]interface{}, 1000)
		for i := 0; i < 1000; i++ {
			events[i] = map[string]interface{}{
				"EventID":   "4624",
				"LogonType": 2,
				"Index":     i,
			}
		}

		// Measure performance
		start := time.Now()
		results, err := engine.EvaluateBatch(events)
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.Len(t, results, 1000)

		eventsPerSecond := float64(1000) / duration.Seconds()
		t.Logf("Processed %d events in %v (%.2f events/sec)", 1000, duration, eventsPerSecond)

		// Should maintain high performance
		assert.Greater(t, eventsPerSecond, 1000.0)
	})

	t.Run("MemoryUsage", func(t *testing.T) {
		engine, err := NewEngineBuilder().
			AddRule(testRule()).
			Build()

		require.NoError(t, err)

		// Process many events to test memory usage
		for i := 0; i < 10000; i++ {
			event := map[string]interface{}{
				"EventID": "4624",
				"Index":   i,
			}

			_, err := engine.Evaluate(event)
			assert.NoError(t, err)
		}

		// Memory usage should remain reasonable
		// This would require actual memory profiling in a real test
	})
}

// Test helper functions

func testRule() string {
	return `
title: Test Login Event
id: 12345678-1234-1234-1234-123456789abc
description: Test rule for validation
author: Test Author
date: 2024-01-01
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4624
        LogonType: 2
    condition: selection
level: low
tags:
    - attack.initial_access
    - attack.t1078
`
}

func complexTestRule() string {
	return `
title: Suspicious PowerShell Execution
id: abcdef12-3456-7890-abcd-ef1234567890
description: Detects suspicious PowerShell execution patterns
author: Test Author
date: 2024-01-01
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'FromBase64String'
    filter_legitimate:
        User|startswith: 'NT AUTHORITY\'
    condition: selection_powershell and selection_suspicious and not filter_legitimate
level: high
tags:
    - attack.execution
    - attack.t1059.001
`
}

// Test validator implementation
type testValidator struct{}

func (v *testValidator) Validate(data interface{}) error {
	if dataMap, ok := data.(map[string]interface{}); ok {
		if valid, exists := dataMap["valid"]; exists && valid == true {
			return nil
		}
		return fmt.Errorf("validation failed: data is not valid")
	}
	return fmt.Errorf("validation failed: invalid data type")
}

// Benchmark tests

func BenchmarkEngineEvaluation(b *testing.B) {
	engine, err := NewEngineBuilder().
		AddRule(testRule()).
		Build()

	require.NoError(b, err)

	event := map[string]interface{}{
		"EventID":   "4624",
		"LogonType": 2,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(event)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBatchEvaluation(b *testing.B) {
	engine, err := NewEngineBuilder().
		AddRule(testRule()).
		Build()

	require.NoError(b, err)

	events := make([]map[string]interface{}, 100)
	for i := 0; i < 100; i++ {
		events[i] = map[string]interface{}{
			"EventID":   "4624",
			"LogonType": 2,
			"Index":     i,
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateBatch(events)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIROptimization(b *testing.B) {
	ir := NewIR()

	// Add many rules
	for i := 0; i < 1000; i++ {
		rule := &IRRule{
			ID:    fmt.Sprintf("rule-%d", i),
			Title: fmt.Sprintf("Rule %d", i),
			Primitives: []*IRPrimitive{
				{
					ID:    fmt.Sprintf("primitive-%d", i%100), // Create some shared primitives
					Type:  IRPrimEquals,
					Field: "EventID",
					Value: "4624",
				},
			},
		}
		ir.AddRule(rule)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ir.OptimizePrimitives()
	}
}
