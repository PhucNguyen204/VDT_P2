package test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// TestErrorResilience tests engine resilience under error conditions
func TestErrorResilience(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🛡️ Testing Engine Error Resilience")
	t.Logf("================================")

	// Test malformed rules handling
	t.Run("Malformed_Rules", func(t *testing.T) {
		malformedRules := []string{
			// Missing detection section
			`title: Incomplete Rule
logsource:
    category: process_creation
level: high`,

			// Invalid YAML structure
			`title: Bad YAML
detection:
  selection:
    - Image: test
    - invalid: structure
condition: selection`,

			// Missing condition
			`title: No Condition
logsource:
    category: process_creation
detection:
    selection:
        Image: test.exe`,

			// Invalid regex
			`title: Bad Regex
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '[invalid regex'
    condition: selection`,

			// Circular reference
			`title: Circular Reference
logsource:
    category: process_creation
detection:
    selection1: selection2
    selection2: selection1
    condition: selection1`,
		}

		engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
		
		validRuleCount := 0
		for i, rule := range malformedRules {
			err := engine.FromRules([]string{rule})
			if err != nil {
				t.Logf("✅ Malformed rule %d: Correctly rejected - %v", i+1, err)
			} else {
				t.Errorf("❌ Malformed rule %d: Should have been rejected", i+1)
				validRuleCount++
			}
		}

		if validRuleCount == 0 {
			t.Logf("🛡️ Excellent: All malformed rules properly rejected")
		} else {
			t.Logf("⚠️ %d malformed rules incorrectly accepted", validRuleCount)
		}
	})

	// Test edge case events
	t.Run("Edge_Case_Events", func(t *testing.T) {
		rules := []string{
			`title: Standard Detection
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\test.exe'
        CommandLine|contains: 'parameter'
    condition: selection
level: medium`,
		}

		engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
		err := engine.FromRules(rules)
		if err != nil {
			t.Fatalf("Failed to compile test rules: %v", err)
		}

		edgeCaseEvents := []struct {
			name        string
			event       map[string]interface{}
			shouldError bool
		}{
			{
				name:        "Nil_Event",
				event:       nil,
				shouldError: true,
			},
			{
				name:        "Empty_Event",
				event:       map[string]interface{}{},
				shouldError: false,
			},
			{
				name: "Null_Values",
				event: map[string]interface{}{
					"EventID": nil,
					"Image":   nil,
					"CommandLine": nil,
				},
				shouldError: false,
			},
			{
				name: "Wrong_Types",
				event: map[string]interface{}{
					"EventID": "not_a_number",
					"Image":   123,
					"CommandLine": []string{"array", "instead", "of", "string"},
				},
				shouldError: false,
			},
			{
				name: "Very_Long_Strings",
				event: map[string]interface{}{
					"EventID": 1,
					"Image":   strings.Repeat("A", 10000) + "test.exe",
					"CommandLine": strings.Repeat("B", 50000) + "parameter",
				},
				shouldError: false,
			},
			{
				name: "Unicode_Characters",
				event: map[string]interface{}{
					"EventID": 1,
					"Image":   "C:\\测试\\тест\\🔥test.exe",
					"CommandLine": "test.exe --param=こんにちは parameter 🎯",
				},
				shouldError: false,
			},
			{
				name: "Nested_Objects",
				event: map[string]interface{}{
					"EventID": 1,
					"Image":   "C:\\Tools\\test.exe",
					"Details": map[string]interface{}{
						"CommandLine": "test.exe parameter",
						"User": map[string]interface{}{
							"Name": "testuser",
							"SID":  "S-1-5-21-1234567890",
						},
					},
				},
				shouldError: false,
			},
		}

		for _, tc := range edgeCaseEvents {
			t.Run(tc.name, func(t *testing.T) {
				result, err := engine.Evaluate(tc.event)
				
				if tc.shouldError {
					if err != nil {
						t.Logf("✅ %s: Correctly handled error - %v", tc.name, err)
					} else {
						t.Errorf("❌ %s: Should have returned error", tc.name)
					}
				} else {
					if err != nil {
						t.Errorf("❌ %s: Unexpected error - %v", tc.name, err)
					} else {
						t.Logf("✅ %s: Handled gracefully (%d matches)", tc.name, len(result.MatchedRules))
					}
				}
			})
		}
	})

	// Test resource exhaustion scenarios
	t.Run("Resource_Exhaustion", func(t *testing.T) {
		// Memory exhaustion test
		t.Run("Memory_Exhaustion", func(t *testing.T) {
			// Create rules với very large patterns
			largePattern := strings.Repeat("A", 1000)
			rule := fmt.Sprintf(`title: Large Pattern Rule
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: '%s'
    condition: selection
level: medium`, largePattern)

			engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
			
			start := time.Now()
			err := engine.FromRules([]string{rule})
			compileTime := time.Since(start)

			if err != nil {
				t.Logf("⚠️ Large pattern rule rejected: %v", err)
			} else {
				t.Logf("✅ Large pattern rule compiled in %v", compileTime)
				
				// Test evaluation với large pattern
				event := map[string]interface{}{
					"EventID": 1,
					"Image":   "test.exe",
					"CommandLine": "test.exe " + largePattern,
				}

				start = time.Now()
				result, err := engine.Evaluate(event)
				evalTime := time.Since(start)

				if err != nil {
					t.Errorf("❌ Large pattern evaluation failed: %v", err)
				} else {
					t.Logf("✅ Large pattern evaluated in %v (%d matches)", evalTime, len(result.MatchedRules))
				}
			}
		})

		// Timeout test
		t.Run("Timeout_Handling", func(t *testing.T) {
			// Create config với very short timeout
			config := sigma.DefaultEngineConfig()
			config.Timeout = 1 * time.Millisecond

			engine := sigma.NewSigmaEngine(config, logger)
			
			// Complex regex rule that might timeout
			rule := `title: Complex Regex
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '(a+)+b'
    condition: selection
level: medium`

			err := engine.FromRules([]string{rule})
			if err != nil {
				t.Logf("✅ Complex regex rule rejected during compilation: %v", err)
				return
			}

			// Event that could cause regex timeout
			event := map[string]interface{}{
				"EventID": 1,
				"Image":   "test.exe",
				"CommandLine": strings.Repeat("a", 1000) + "c", // No 'b' to cause backtracking
			}

			start := time.Now()
			result, err := engine.Evaluate(event)
			evalTime := time.Since(start)

			if err != nil && strings.Contains(err.Error(), "timeout") {
				t.Logf("✅ Timeout correctly handled: %v (took %v)", err, evalTime)
			} else if err != nil {
				t.Logf("⚠️ Other error occurred: %v", err)
			} else {
				t.Logf("ℹ️ Evaluation completed normally: %d matches in %v", len(result.MatchedRules), evalTime)
			}
		})
	})
}

// TestConcurrencyStress tests concurrent access patterns
func TestConcurrencyStress(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🔄 Testing Concurrency Stress")
	t.Logf("============================")

	rules := []string{
		`title: Concurrent Test Rule 1
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\concurrent1.exe'
    condition: selection
level: medium`,

		`title: Concurrent Test Rule 2
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\concurrent2.exe'
    condition: selection
level: medium`,
	}

	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	err := engine.FromRules(rules)
	if err != nil {
		t.Fatalf("Failed to compile concurrent test rules: %v", err)
	}

	// Test concurrent evaluation
	t.Run("Concurrent_Evaluation", func(t *testing.T) {
		numGoroutines := 100
		numEventsPerGoroutine := 100
		
		var wg sync.WaitGroup
		var mu sync.Mutex
		results := make(map[int]int) // goroutine_id -> matches_found
		errors := 0

		start := time.Now()

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				matches := 0
				for j := 0; j < numEventsPerGoroutine; j++ {
					event := map[string]interface{}{
						"EventID": 1,
						"Image":   fmt.Sprintf("C:\\Tools\\concurrent%d.exe", (goroutineID+j)%2+1),
						"ProcessId": goroutineID*1000 + j,
					}

					result, err := engine.Evaluate(event)
					if err != nil {
						mu.Lock()
						errors++
						mu.Unlock()
					} else if len(result.MatchedRules) > 0 {
						matches++
					}
				}

				mu.Lock()
				results[goroutineID] = matches
				mu.Unlock()
			}(i)
		}

		wg.Wait()
		totalTime := time.Since(start)

		totalEvents := numGoroutines * numEventsPerGoroutine
		totalMatches := 0
		for _, matches := range results {
			totalMatches += matches
		}

		t.Logf("📊 Concurrent Evaluation Results:")
		t.Logf("   Goroutines: %d", numGoroutines)
		t.Logf("   Events per goroutine: %d", numEventsPerGoroutine)
		t.Logf("   Total events: %d", totalEvents)
		t.Logf("   Total matches: %d", totalMatches)
		t.Logf("   Errors: %d", errors)
		t.Logf("   Total time: %v", totalTime)
		t.Logf("   Events/second: %.2f", float64(totalEvents)/totalTime.Seconds())

		if errors == 0 {
			t.Logf("✅ No concurrency errors detected")
		} else {
			t.Errorf("❌ %d concurrency errors occurred", errors)
		}

		expectedMatches := totalEvents / 2 // Half should match
		matchTolerance := float64(expectedMatches) * 0.1 // 10% tolerance
		
		if float64(totalMatches) >= float64(expectedMatches)-matchTolerance &&
		   float64(totalMatches) <= float64(expectedMatches)+matchTolerance {
			t.Logf("✅ Match count within expected range")
		} else {
			t.Logf("⚠️ Match count outside expected range: got %d, expected ~%d", totalMatches, expectedMatches)
		}
	})

	// Test concurrent rule updates
	t.Run("Concurrent_Updates", func(t *testing.T) {
		numUpdaters := 10
		numEvaluators := 20
		duration := 5 * time.Second

		var wg sync.WaitGroup
		ctx, cancel := context.WithTimeout(context.Background(), duration)
		defer cancel()

		updateErrors := 0
		evalErrors := 0
		var mu sync.Mutex

		// Start rule updaters
		for i := 0; i < numUpdaters; i++ {
			wg.Add(1)
			go func(updaterID int) {
				defer wg.Done()
				
				for {
					select {
					case <-ctx.Done():
						return
					default:
						newRule := fmt.Sprintf(`title: Dynamic Rule %d
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\dynamic_%d.exe'
    condition: selection
level: medium`, updaterID, updaterID)

						err := engine.FromRules([]string{newRule})
						if err != nil {
							mu.Lock()
							updateErrors++
							mu.Unlock()
						}
						
						time.Sleep(10 * time.Millisecond)
					}
				}
			}(i)
		}

		// Start evaluators
		for i := 0; i < numEvaluators; i++ {
			wg.Add(1)
			go func(evalID int) {
				defer wg.Done()
				
				for {
					select {
					case <-ctx.Done():
						return
					default:
						event := map[string]interface{}{
							"EventID": 1,
							"Image":   fmt.Sprintf("C:\\Tools\\dynamic_%d.exe", evalID%numUpdaters),
							"ProcessId": evalID * 1000,
						}

						_, err := engine.Evaluate(event)
						if err != nil {
							mu.Lock()
							evalErrors++
							mu.Unlock()
						}
						
						time.Sleep(1 * time.Millisecond)
					}
				}
			}(i)
		}

		wg.Wait()

		t.Logf("📊 Concurrent Updates Results:")
		t.Logf("   Update errors: %d", updateErrors)
		t.Logf("   Evaluation errors: %d", evalErrors)

		if updateErrors == 0 && evalErrors == 0 {
			t.Logf("✅ No errors during concurrent updates and evaluations")
		} else {
			t.Logf("⚠️ Some errors occurred during concurrent operations")
		}
	})
}

// TestAdvancedFieldMapping tests complex field mapping scenarios
func TestAdvancedFieldMapping(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🗺️ Testing Advanced Field Mapping")
	t.Logf("=================================")

	// Test nested field mapping
	t.Run("Nested_Field_Mapping", func(t *testing.T) {
		engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
		
		// Add nested field mappings
		engine.AddFieldMapping("ProcessInfo.Image", "Image")
		engine.AddFieldMapping("ProcessInfo.CommandLine", "CommandLine")
		engine.AddFieldMapping("User.Name", "UserName")

		rule := `title: Nested Field Test
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\test.exe'
        CommandLine|contains: 'parameter'
        UserName: 'testuser'
    condition: selection
level: medium`

		err := engine.FromRules([]string{rule})
		if err != nil {
			t.Fatalf("Failed to compile nested field rule: %v", err)
		}

		// Test với nested event structure
		nestedEvent := map[string]interface{}{
			"EventID": 1,
			"ProcessInfo": map[string]interface{}{
				"Image":       "C:\\Tools\\test.exe",
				"CommandLine": "test.exe --parameter value",
			},
			"User": map[string]interface{}{
				"Name": "testuser",
				"SID":  "S-1-5-21-1234567890",
			},
		}

		result, err := engine.Evaluate(nestedEvent)
		if err != nil {
			t.Errorf("Nested field evaluation failed: %v", err)
		} else if len(result.MatchedRules) == 0 {
			t.Errorf("❌ Nested fields not properly mapped")
		} else {
			t.Logf("✅ Nested field mapping working: %d matches", len(result.MatchedRules))
		}
	})

	// Test field mapping conflicts
	t.Run("Field_Mapping_Conflicts", func(t *testing.T) {
		engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
		
		// Add conflicting mappings
		engine.AddFieldMapping("OriginalField", "MappedField")
		engine.AddFieldMapping("AnotherField", "MappedField") // Same target

		rule := `title: Mapping Conflict Test
logsource:
    category: process_creation
detection:
    selection:
        MappedField: 'test_value'
    condition: selection
level: medium`

		err := engine.FromRules([]string{rule})
		if err != nil {
			t.Fatalf("Failed to compile conflict test rule: %v", err)
		}

		// Test với both source fields present
		conflictEvent := map[string]interface{}{
			"EventID":       1,
			"OriginalField": "test_value",
			"AnotherField":  "different_value",
		}

		result, err := engine.Evaluate(conflictEvent)
		if err != nil {
			t.Errorf("Conflict evaluation failed: %v", err)
		} else {
			t.Logf("ℹ️ Conflict handling: %d matches", len(result.MatchedRules))
		}
	})

	// Test dynamic field mapping
	t.Run("Dynamic_Field_Mapping", func(t *testing.T) {
		engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)

		rule := `title: Dynamic Mapping Test
logsource:
    category: process_creation
detection:
    selection:
        DynamicField: 'test_value'
    condition: selection
level: medium`

		err := engine.FromRules([]string{rule})
		if err != nil {
			t.Fatalf("Failed to compile dynamic test rule: %v", err)
		}

		// First test without mapping
		event1 := map[string]interface{}{
			"EventID":       1,
			"OriginalField": "test_value",
		}

		result1, _ := engine.Evaluate(event1)
		matches1 := len(result1.MatchedRules)

		// Add mapping and test again
		engine.AddFieldMapping("OriginalField", "DynamicField")

		result2, _ := engine.Evaluate(event1)
		matches2 := len(result2.MatchedRules)

		t.Logf("📊 Dynamic Mapping Results:")
		t.Logf("   Before mapping: %d matches", matches1)
		t.Logf("   After mapping: %d matches", matches2)

		if matches2 > matches1 {
			t.Logf("✅ Dynamic field mapping working")
		} else {
			t.Logf("⚠️ Dynamic field mapping may not be effective")
		}
	})
}

// TestStreamingEdgeCases tests streaming engine edge cases
func TestStreamingEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("📡 Testing Streaming Edge Cases")
	t.Logf("===============================")

	coreEngine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupTestFieldMappings(coreEngine)

	rules := []string{
		`title: Streaming Test Rule
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\stream_test.exe'
    condition: selection
level: medium`,
	}

	err := coreEngine.FromRules(rules)
	if err != nil {
		t.Fatalf("Failed to compile streaming test rules: %v", err)
	}

	// Test rapid start/stop cycles
	t.Run("Rapid_Start_Stop", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			config := sigma.DefaultStreamingConfig()
			config.WorkerCount = 2
			
			streamEngine := sigma.NewStreamingEngine(coreEngine, config)
			
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			
			err := streamEngine.Start(ctx)
			if err != nil {
				t.Errorf("Start cycle %d failed: %v", i+1, err)
				cancel()
				continue
			}

			// Send a few events
			for j := 0; j < 5; j++ {
				event := &sigma.StreamingEvent{
					ID:   fmt.Sprintf("event_%d_%d", i, j),
					Data: map[string]interface{}{
						"EventID": 1,
						"Image":   "C:\\Tools\\stream_test.exe",
					},
					Timestamp: time.Now(),
					Source:    "test",
				}
				streamEngine.ProcessEvent(event)
			}

			stopCtx, stopCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			err = streamEngine.Stop(stopCtx)
			stopCancel()
			cancel()

			if err != nil {
				t.Logf("⚠️ Stop cycle %d had issues: %v", i+1, err)
			}
		}
		t.Logf("✅ Rapid start/stop cycles completed")
	})

	// Test backpressure scenarios
	t.Run("Backpressure_Scenarios", func(t *testing.T) {
		config := sigma.DefaultStreamingConfig()
		config.InputBufferSize = 10  // Very small buffer
		config.BackpressureThreshold = 5
		config.BackpressureStrategy = sigma.BackpressureDrop

		streamEngine := sigma.NewStreamingEngine(coreEngine, config)
		
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		err := streamEngine.Start(ctx)
		if err != nil {
			t.Fatalf("Failed to start streaming engine: %v", err)
		}

		// Flood với events to trigger backpressure
		eventsToSend := 100
		eventsAccepted := 0
		eventsDropped := 0

		for i := 0; i < eventsToSend; i++ {
			event := &sigma.StreamingEvent{
				ID:   fmt.Sprintf("flood_event_%d", i),
				Data: map[string]interface{}{
					"EventID": 1,
					"Image":   "C:\\Tools\\stream_test.exe",
				},
				Timestamp: time.Now(),
				Source:    "flood_test",
			}

			err := streamEngine.ProcessEvent(event)
			if err != nil {
				eventsDropped++
			} else {
				eventsAccepted++
			}
		}

		time.Sleep(100 * time.Millisecond) // Let processing catch up

		stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Second)
		streamEngine.Stop(stopCtx)
		stopCancel()

		t.Logf("📊 Backpressure Test Results:")
		t.Logf("   Events sent: %d", eventsToSend)
		t.Logf("   Events accepted: %d", eventsAccepted)
		t.Logf("   Events dropped: %d", eventsDropped)

		if eventsDropped > 0 {
			t.Logf("✅ Backpressure mechanism activated")
		} else {
			t.Logf("ℹ️ No backpressure triggered (buffer may be adequate)")
		}
	})
}

// Helper function
func setupTestFieldMappings(engine *sigma.SigmaEngine) {
	mappings := map[string]string{
		"ProcessImage":       "Image",
		"ProcessCommandLine": "CommandLine",
		"ParentProcessImage": "ParentImage",
	}

	for from, to := range mappings {
		engine.AddFieldMapping(from, to)
	}
}
