package test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// TestMITREATTACKCoverage tests coverage của MITRE ATT&CK framework
func TestMITREATTACKCoverage(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🔍 Testing MITRE ATT&CK Coverage")
	t.Logf("==============================")

	// Comprehensive MITRE ATT&CK test cases
	attackTestCases := []struct {
		name        string
		technique   string
		description string
		rules       []string
		events      []map[string]interface{}
		expectMatch bool
		severity    string
	}{
		{
			name:      "T1003.001_LSASS_Memory_Dump",
			technique: "T1003.001",
			description: "Credential dumping via LSASS memory",
			rules: []string{
				`title: LSASS Memory Access
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\procdump.exe'
            - '\taskmgr.exe'
            - '\ProcessHacker.exe'
        CommandLine|contains:
            - 'lsass'
            - '-ma lsass'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Tools\\procdump.exe",
					"CommandLine": "procdump.exe -ma lsass.exe lsass.dmp",
					"User": "SYSTEM",
				},
			},
			expectMatch: true,
			severity: "critical",
		},
		{
			name:      "T1055_Process_Injection",
			technique: "T1055",
			description: "Process injection techniques",
			rules: []string{
				`title: Suspicious Process Injection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        CommandLine|contains:
            - 'CreateRemoteThread'
            - 'SetWindowsHookEx'
            - 'VirtualAllocEx'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1055`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\svchost.exe",
					"CommandLine": "svchost.exe -k netsvcs VirtualAllocEx",
				},
			},
			expectMatch: true,
			severity: "high",
		},
		{
			name:      "T1047_WMI_Execution",
			technique: "T1047",
			description: "Windows Management Instrumentation execution",
			rules: []string{
				`title: WMI Process Creation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wmiprvse.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1047`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\cmd.exe",
					"ParentImage": "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
					"CommandLine": "cmd.exe /c whoami",
				},
			},
			expectMatch: true,
			severity: "medium",
		},
		{
			name:      "T1082_System_Information_Discovery",
			technique: "T1082",
			description: "System information discovery commands",
			rules: []string{
				`title: System Discovery Commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmd.exe'
        CommandLine|contains:
            - 'systeminfo'
            - 'whoami /all'
            - 'net config'
            - 'ipconfig /all'
    condition: selection
level: low
tags:
    - attack.discovery
    - attack.t1082`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\cmd.exe",
					"CommandLine": "cmd.exe /c systeminfo && whoami /all",
				},
			},
			expectMatch: true,
			severity: "low",
		},
		{
			name:      "T1071.001_Web_Protocols",
			technique: "T1071.001",
			description: "Command and control via web protocols",
			rules: []string{
				`title: Suspicious Web Traffic
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 
            - 80
            - 443
        ProcessName|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\rundll32.exe'
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 3,
					"ProcessName": "powershell.exe",
					"DestinationIp": "192.168.1.100",
					"DestinationPort": 443,
					"Protocol": "tcp",
				},
			},
			expectMatch: true,
			severity: "medium",
		},
	}

	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupAdvancedFieldMappings(engine)

	// Compile all rules
	allRules := []string{}
	for _, tc := range attackTestCases {
		allRules = append(allRules, tc.rules...)
	}

	err := engine.FromRules(allRules)
	if err != nil {
		t.Fatalf("Failed to compile MITRE rules: %v", err)
	}

	// Test each technique
	detectionResults := make(map[string]bool)
	
	for _, tc := range attackTestCases {
		t.Run(tc.name, func(t *testing.T) {
			detected := false
			
			for _, event := range tc.events {
				result, err := engine.Evaluate(event)
				if err != nil {
					t.Errorf("Evaluation failed: %v", err)
					continue
				}

				if len(result.MatchedRules) > 0 {
					detected = true
					t.Logf("✅ %s (%s): DETECTED - %d rules matched", 
						tc.name, tc.technique, len(result.MatchedRules))
					
					for _, match := range result.MatchedRules {
						t.Logf("   🚨 %s (Level: %s)", match.Title, match.Level)
					}
				}
			}

			detectionResults[tc.technique] = detected

			if detected == tc.expectMatch {
				if detected {
					t.Logf("✅ %s: Correctly detected", tc.technique)
				} else {
					t.Logf("✅ %s: Correctly ignored", tc.technique)
				}
			} else {
				if tc.expectMatch {
					t.Errorf("❌ %s: MISSED ATTACK - %s", tc.technique, tc.description)
				} else {
					t.Errorf("❌ %s: FALSE POSITIVE - %s", tc.technique, tc.description)
				}
			}
		})
	}

	// Summary
	totalTechniques := len(attackTestCases)
	detectedCount := 0
	for _, detected := range detectionResults {
		if detected {
			detectedCount++
		}
	}

	coverage := float64(detectedCount) / float64(totalTechniques) * 100
	t.Logf("🎯 MITRE ATT&CK Coverage: %.1f%% (%d/%d techniques)", 
		coverage, detectedCount, totalTechniques)

	if coverage >= 80 {
		t.Logf("🏆 EXCELLENT: High MITRE ATT&CK coverage")
	} else if coverage >= 60 {
		t.Logf("👍 GOOD: Decent MITRE ATT&CK coverage")
	} else {
		t.Logf("⚠️ NEEDS IMPROVEMENT: Low MITRE ATT&CK coverage")
	}
}

// TestAdvancedEvasionTechniques tests evasion resistance
func TestAdvancedEvasionTechniques(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🕵️ Testing Advanced Evasion Techniques")
	t.Logf("====================================")

	evasionTestCases := []struct {
		name        string
		description string
		rules       []string
		cleanEvent  map[string]interface{}
		evasions    []map[string]interface{}
		expectDetect []bool
	}{
		{
			name: "Case_Variation_Evasion",
			description: "Testing case variation evasion attempts",
			rules: []string{
				`title: PowerShell Detection
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Invoke-Expression'
    condition: selection
level: high`,
			},
			cleanEvent: map[string]interface{}{
				"EventID": 1,
				"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"CommandLine": "powershell.exe -Command Invoke-Expression",
			},
			evasions: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE",
					"CommandLine": "POWERSHELL.EXE -Command INVOKE-EXPRESSION",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe",
					"CommandLine": "PowerShell.exe -Command invoke-expression",
				},
			},
			expectDetect: []bool{true, true}, // Should detect case variations
		},
		{
			name: "Path_Traversal_Evasion",
			description: "Testing path traversal evasion",
			rules: []string{
				`title: Mimikatz Detection
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
    condition: selection
level: critical`,
			},
			cleanEvent: map[string]interface{}{
				"EventID": 1,
				"Image": "C:\\Tools\\mimikatz.exe",
				"CommandLine": "mimikatz.exe",
			},
			evasions: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Tools\\..\\Tools\\mimikatz.exe",
					"CommandLine": "mimikatz.exe",
				},
				{
					"EventID": 1,
					"Image": "C:\\Tools\\subfolder\\..\\mimikatz.exe",
					"CommandLine": "mimikatz.exe",
				},
			},
			expectDetect: []bool{true, true}, // Should detect path variations
		},
		{
			name: "Command_Obfuscation",
			description: "Testing command line obfuscation",
			rules: []string{
				`title: Base64 PowerShell
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high`,
			},
			cleanEvent: map[string]interface{}{
				"EventID": 1,
				"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
			},
			evasions: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
					"CommandLine": "powershell.exe -en SQBFAFgA", // Abbreviated parameter
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
					"CommandLine": "powershell.exe -e SQBFAFgA", // Further abbreviated
				},
			},
			expectDetect: []bool{false, false}, // May not detect abbreviated forms
		},
	}

	for _, tc := range evasionTestCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
			setupAdvancedFieldMappings(engine)

			err := engine.FromRules(tc.rules)
			if err != nil {
				t.Fatalf("Failed to compile rules: %v", err)
			}

			// Test clean event (should always detect)
			result, err := engine.Evaluate(tc.cleanEvent)
			if err != nil {
				t.Errorf("Clean event evaluation failed: %v", err)
			} else if len(result.MatchedRules) == 0 {
				t.Errorf("Clean event not detected - test setup issue")
			}

			// Test evasion attempts
			for i, evasion := range tc.evasions {
				result, err := engine.Evaluate(evasion)
				if err != nil {
					t.Errorf("Evasion %d evaluation failed: %v", i+1, err)
					continue
				}

				detected := len(result.MatchedRules) > 0
				expected := tc.expectDetect[i]

				if detected == expected {
					if detected {
						t.Logf("✅ Evasion %d: Correctly detected", i+1)
					} else {
						t.Logf("⚠️ Evasion %d: Expected bypass (known limitation)", i+1)
					}
				} else {
					if expected {
						t.Errorf("❌ Evasion %d: BYPASSED detection", i+1)
					} else {
						t.Logf("🎉 Evasion %d: Unexpectedly detected (improvement!)", i+1)
					}
				}
			}
		})
	}
}

// TestPerformanceStress tests under stress conditions
func TestPerformanceStress(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("⚡ Testing Performance Under Stress")
	t.Logf("=================================")

	// Large ruleset test
	rules := generateLargeRuleset(100) // 100 rules
	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupAdvancedFieldMappings(engine)

	start := time.Now()
	err := engine.FromRules(rules)
	compileTime := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to compile large ruleset: %v", err)
	}

	t.Logf("📊 Large Ruleset Performance:")
	t.Logf("   Rules compiled: %d", len(rules))
	t.Logf("   Compilation time: %v", compileTime)
	t.Logf("   Rules/second: %.2f", float64(len(rules))/compileTime.Seconds())

	// High volume event test
	eventCounts := []int{1000, 5000, 10000, 20000}
	
	for _, count := range eventCounts {
		t.Run(fmt.Sprintf("Events_%d", count), func(t *testing.T) {
			events := generateHighVolumeEvents(count)
			
			// Sequential processing
			start := time.Now()
			matchCount := 0
			for _, event := range events {
				result, err := engine.Evaluate(event)
				if err == nil && len(result.MatchedRules) > 0 {
					matchCount++
				}
			}
			seqTime := time.Since(start)

			// Batch processing
			start = time.Now()
			batchResults, err := engine.EvaluateBatch(events)
			batchTime := time.Since(start)

			batchMatches := 0
			if err == nil {
				for _, result := range batchResults {
					if len(result.MatchedRules) > 0 {
						batchMatches++
					}
				}
			}

			seqEPS := float64(count) / seqTime.Seconds()
			batchEPS := float64(count) / batchTime.Seconds()

			t.Logf("📊 %d Events Performance:", count)
			t.Logf("   Sequential: %.2f events/sec, %d matches", seqEPS, matchCount)
			t.Logf("   Batch: %.2f events/sec, %d matches", batchEPS, batchMatches)

			// Performance thresholds
			if seqEPS >= 1000 {
				t.Logf("   ✅ Sequential: EXCELLENT performance")
			} else if seqEPS >= 500 {
				t.Logf("   👍 Sequential: GOOD performance")
			} else {
				t.Logf("   ⚠️ Sequential: Performance below target")
			}

			if batchEPS > seqEPS*1.2 {
				improvement := (batchEPS - seqEPS) / seqEPS * 100
				t.Logf("   🚀 Batch improvement: %.1f%%", improvement)
			}
		})
	}

	// Memory stress test
	t.Run("Memory_Stress", func(t *testing.T) {
		// Generate many unique events to stress cache
		uniqueEvents := make([]map[string]interface{}, 1000)
		for i := 0; i < 1000; i++ {
			uniqueEvents[i] = map[string]interface{}{
				"EventID": 1,
				"Image": fmt.Sprintf("C:\\Tools\\tool_%d.exe", i),
				"CommandLine": fmt.Sprintf("tool_%d.exe --option %d", i, rand.Intn(1000)),
				"ProcessId": 1000 + i,
			}
		}

		start := time.Now()
		for _, event := range uniqueEvents {
			_, err := engine.Evaluate(event)
			if err != nil {
				t.Errorf("Memory stress evaluation failed: %v", err)
			}
		}
		memoryStressTime := time.Since(start)

		eps := float64(len(uniqueEvents)) / memoryStressTime.Seconds()
		t.Logf("📊 Memory Stress Test:")
		t.Logf("   Unique events: %d", len(uniqueEvents))
		t.Logf("   Processing time: %v", memoryStressTime)
		t.Logf("   Events/second: %.2f", eps)

		if eps >= 500 {
			t.Logf("   ✅ Memory handling: EXCELLENT")
		} else {
			t.Logf("   ⚠️ Memory handling: Needs optimization")
		}
	})
}

// TestRealWorldScenarios tests realistic attack scenarios
func TestRealWorldScenarios(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🌍 Testing Real-World Attack Scenarios")
	t.Logf("====================================")

	scenarios := []struct {
		name        string
		description string
		eventChain  []map[string]interface{}
		rules       []string
		expectChain bool
	}{
		{
			name: "APT_Lateral_Movement",
			description: "Advanced Persistent Threat lateral movement",
			eventChain: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\cmd.exe",
					"CommandLine": "cmd.exe /c net user administrator newpass123",
					"User": "SYSTEM",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\net.exe",
					"CommandLine": "net use \\\\target-pc\\c$ /user:administrator newpass123",
					"User": "administrator",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\sc.exe",
					"CommandLine": "sc \\\\target-pc create malware binpath= C:\\temp\\backdoor.exe",
					"User": "administrator",
				},
			},
			rules: []string{
				`title: Suspicious Net Commands
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: 
            - '\net.exe'
            - '\sc.exe'
        CommandLine|contains:
            - 'net user'
            - 'net use'
            - 'sc create'
    condition: selection
level: medium`,
			},
			expectChain: true,
		},
		{
			name: "Ransomware_Deployment",
			description: "Ransomware deployment sequence",
			eventChain: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\vssadmin.exe",
					"CommandLine": "vssadmin delete shadows /all /quiet",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\wbadmin.exe",
					"CommandLine": "wbadmin delete catalog -quiet",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\bcdedit.exe",
					"CommandLine": "bcdedit /set {default} recoveryenabled no",
				},
			},
			rules: []string{
				`title: Ransomware Preparation
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\vssadmin.exe'
            - '\wbadmin.exe'
            - '\bcdedit.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'delete catalog'
            - 'recoveryenabled no'
    condition: selection
level: critical`,
			},
			expectChain: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
			setupAdvancedFieldMappings(engine)

			err := engine.FromRules(scenario.rules)
			if err != nil {
				t.Fatalf("Failed to compile scenario rules: %v", err)
			}

			detectedEvents := 0
			totalMatches := 0

			for i, event := range scenario.eventChain {
				result, err := engine.Evaluate(event)
				if err != nil {
					t.Errorf("Event %d evaluation failed: %v", i+1, err)
					continue
				}

				if len(result.MatchedRules) > 0 {
					detectedEvents++
					totalMatches += len(result.MatchedRules)
					t.Logf("   🚨 Event %d: %d rules matched", i+1, len(result.MatchedRules))
				}
			}

			chainDetected := detectedEvents > 0
			chainCoverage := float64(detectedEvents) / float64(len(scenario.eventChain)) * 100

			t.Logf("📊 %s Results:", scenario.name)
			t.Logf("   Events in chain: %d", len(scenario.eventChain))
			t.Logf("   Events detected: %d", detectedEvents)
			t.Logf("   Chain coverage: %.1f%%", chainCoverage)
			t.Logf("   Total matches: %d", totalMatches)

			if chainDetected == scenario.expectChain {
				if chainDetected {
					t.Logf("   ✅ Attack chain: DETECTED")
				} else {
					t.Logf("   ✅ Benign chain: IGNORED")
				}
			} else {
				if scenario.expectChain {
					t.Errorf("   ❌ Attack chain: MISSED")
				} else {
					t.Errorf("   ❌ Benign chain: FALSE POSITIVE")
				}
			}

			if chainCoverage >= 70 {
				t.Logf("   🏆 Excellent chain coverage")
			} else if chainCoverage >= 50 {
				t.Logf("   👍 Good partial coverage")
			} else if chainDetected {
				t.Logf("   ⚠️ Limited coverage but detected")
			}
		})
	}
}

// Helper functions

func setupAdvancedFieldMappings(engine *sigma.SigmaEngine) {
	mappings := map[string]string{
		"ProcessImage":               "Image",
		"ProcessCommandLine":         "CommandLine",
		"ParentProcessImage":         "ParentImage",
		"ParentProcessCommandLine":   "ParentCommandLine",
		"TargetFilename":             "file_path",
		"DestinationIp":              "dst_ip",
		"SourceIp":                   "src_ip",
		"DestinationPort":            "dst_port",
		"SourcePort":                 "src_port",
		"QueryName":                  "dns_query",
		"QueryResult":                "dns_answer",
		"ProcessName":                "Image",
		"User":                       "User",
	}

	for from, to := range mappings {
		engine.AddFieldMapping(from, to)
	}
}

func generateLargeRuleset(count int) []string {
	rules := make([]string, count)
	
	for i := 0; i < count; i++ {
		rule := fmt.Sprintf(`title: Generated Rule %d
id: test-rule-%d
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\tool_%d.exe'
        CommandLine|contains: 'parameter_%d'
    condition: selection
level: medium
tags:
    - test.generated`, i, i, i%10, i%20)
		rules[i] = rule
	}
	
	return rules
}

func generateHighVolumeEvents(count int) []map[string]interface{} {
	events := make([]map[string]interface{}, count)
	
	templates := []map[string]interface{}{
		{
			"EventID": 1,
			"Image": "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": "cmd.exe /c dir",
		},
		{
			"EventID": 1,
			"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			"CommandLine": "powershell.exe -Command Get-Process",
		},
		{
			"EventID": 1,
			"Image": "C:\\Windows\\System32\\notepad.exe",
			"CommandLine": "notepad.exe document.txt",
		},
		{
			"EventID": 3,
			"ProcessName": "chrome.exe",
			"DestinationIp": "8.8.8.8",
			"DestinationPort": 443,
		},
	}
	
	for i := 0; i < count; i++ {
		template := templates[i%len(templates)]
		event := make(map[string]interface{})
		
		for k, v := range template {
			event[k] = v
		}
		
		// Add variations
		if processId, ok := event["ProcessId"]; ok {
			event["ProcessId"] = processId.(int) + i
		} else {
			event["ProcessId"] = 1000 + i
		}
		
		events[i] = event
	}
	
	return events
}
