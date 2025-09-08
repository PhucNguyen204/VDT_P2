package test

import (
	"fmt"
	"math/rand"
	"runtime"
	"testing"

	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// BenchmarkSigmaEngine benchmarks core engine performance
func BenchmarkSigmaEngine(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Setup engine với realistic rules
	rules := []string{
		`title: Benchmark Rule 1
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
        CommandLine|contains: 'sekurlsa'
    condition: selection
level: critical`,

		`title: Benchmark Rule 2
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-ExecutionPolicy Bypass'
    condition: selection
level: high`,

		`title: Benchmark Rule 3
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort:
            - 4444
            - 5555
            - 6666
        ProcessName|endswith: '.exe'
    condition: selection
level: medium`,
	}

	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupBenchmarkFieldMappings(engine)
	
	err := engine.FromRules(rules)
	if err != nil {
		b.Fatalf("Failed to compile benchmark rules: %v", err)
	}

	// Test event
	event := map[string]interface{}{
		"EventID":     1,
		"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		"CommandLine": "powershell.exe -Command Get-Process",
		"ProcessId":   1234,
	}

	// Warmup
	for i := 0; i < 100; i++ {
		engine.Evaluate(event)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Single_Event_Evaluation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := engine.Evaluate(event)
			if err != nil {
				b.Fatalf("Evaluation failed: %v", err)
			}
		}
	})

	b.Run("Batch_Event_Evaluation", func(b *testing.B) {
		batchSize := 100
		events := make([]map[string]interface{}, batchSize)
		for i := 0; i < batchSize; i++ {
			events[i] = event
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := engine.EvaluateBatch(events)
			if err != nil {
				b.Fatalf("Batch evaluation failed: %v", err)
			}
		}
	})
}

// BenchmarkRuleCompilation benchmarks rule compilation performance
func BenchmarkRuleCompilation(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	ruleTemplate := `title: Compilation Benchmark Rule %d
id: benchmark-rule-%d
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\tool_%d.exe'
        CommandLine|contains: 
            - 'param_%d'
            - 'option_%d'
    condition: selection
level: medium
tags:
    - test.benchmark`

	b.Run("Single_Rule_Compilation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
			rule := fmt.Sprintf(ruleTemplate, i, i, i%10, i%20, i%30)
			
			err := engine.FromRules([]string{rule})
			if err != nil {
				b.Fatalf("Rule compilation failed: %v", err)
			}
		}
	})

	ruleSizes := []int{10, 50, 100, 500, 1000}
	
	for _, size := range ruleSizes {
		b.Run(fmt.Sprintf("Ruleset_Size_%d", size), func(b *testing.B) {
			rules := make([]string, size)
			for i := 0; i < size; i++ {
				rules[i] = fmt.Sprintf(ruleTemplate, i, i, i%10, i%20, i%30)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
				err := engine.FromRules(rules)
				if err != nil {
					b.Fatalf("Ruleset compilation failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	b.Run("Memory_Growth_Test", func(b *testing.B) {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
		setupBenchmarkFieldMappings(engine)

		// Load many rules
		rules := generateBenchmarkRules(1000)
		err := engine.FromRules(rules)
		if err != nil {
			b.Fatalf("Failed to compile rules: %v", err)
		}

		// Process many events
		for i := 0; i < b.N; i++ {
			event := generateRandomEvent(i)
			_, err := engine.Evaluate(event)
			if err != nil {
				b.Fatalf("Evaluation failed: %v", err)
			}
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)

		b.ReportMetric(float64(m2.Alloc-m1.Alloc)/float64(b.N), "bytes/op")
		b.ReportMetric(float64(m2.Mallocs-m1.Mallocs)/float64(b.N), "allocs/op")
	})
}

// BenchmarkConcurrency benchmarks concurrent performance
func BenchmarkConcurrency(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupBenchmarkFieldMappings(engine)

	rules := generateBenchmarkRules(50)
	err := engine.FromRules(rules)
	if err != nil {
		b.Fatalf("Failed to compile rules: %v", err)
	}

	workerCounts := []int{1, 2, 4, 8, 16, 32}

	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("Workers_%d", workers), func(b *testing.B) {
			b.SetParallelism(workers)
			b.RunParallel(func(pb *testing.PB) {
				eventCounter := 0
				for pb.Next() {
					event := generateRandomEvent(eventCounter)
					eventCounter++
					
					_, err := engine.Evaluate(event)
					if err != nil {
						b.Fatalf("Concurrent evaluation failed: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkPrefilter benchmarks prefilter performance
func BenchmarkPrefilter(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test với prefilter enabled
	configWithPrefilter := sigma.DefaultEngineConfig()
	configWithPrefilter.EnablePrefilter = true

	engineWithPrefilter := sigma.NewSigmaEngine(configWithPrefilter, logger)
	setupBenchmarkFieldMappings(engineWithPrefilter)

	// Test without prefilter
	configWithoutPrefilter := sigma.DefaultEngineConfig()
	configWithoutPrefilter.EnablePrefilter = false

	engineWithoutPrefilter := sigma.NewSigmaEngine(configWithoutPrefilter, logger)
	setupBenchmarkFieldMappings(engineWithoutPrefilter)

	rules := generateBenchmarkRules(100)
	
	err := engineWithPrefilter.FromRules(rules)
	if err != nil {
		b.Fatalf("Failed to compile rules with prefilter: %v", err)
	}

	err = engineWithoutPrefilter.FromRules(rules)
	if err != nil {
		b.Fatalf("Failed to compile rules without prefilter: %v", err)
	}

	// Create mix of events (some matching, some not)
	events := make([]map[string]interface{}, 1000)
	for i := 0; i < 1000; i++ {
		if i%10 == 0 {
			// Matching event
			events[i] = map[string]interface{}{
				"EventID":     1,
				"Image":       fmt.Sprintf("C:\\Tools\\tool_%d.exe", i%10),
				"CommandLine": fmt.Sprintf("tool_%d.exe param_%d", i%10, i%20),
			}
		} else {
			// Non-matching event
			events[i] = map[string]interface{}{
				"EventID":     1,
				"Image":       "C:\\Windows\\System32\\notepad.exe",
				"CommandLine": "notepad.exe document.txt",
			}
		}
	}

	b.Run("With_Prefilter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := events[i%len(events)]
			_, err := engineWithPrefilter.Evaluate(event)
			if err != nil {
				b.Fatalf("Evaluation with prefilter failed: %v", err)
			}
		}
	})

	b.Run("Without_Prefilter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := events[i%len(events)]
			_, err := engineWithoutPrefilter.Evaluate(event)
			if err != nil {
				b.Fatalf("Evaluation without prefilter failed: %v", err)
			}
		}
	})
}

// BenchmarkFieldMapping benchmarks field mapping performance
func BenchmarkFieldMapping(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Engine without field mapping
	engineNoMapping := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	
	// Engine với extensive field mapping
	engineWithMapping := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupExtensiveFieldMappings(engineWithMapping)

	rule := `title: Field Mapping Benchmark
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\test.exe'
        CommandLine|contains: 'parameter'
    condition: selection
level: medium`

	err := engineNoMapping.FromRules([]string{rule})
	if err != nil {
		b.Fatalf("Failed to compile rule without mapping: %v", err)
	}

	err = engineWithMapping.FromRules([]string{rule})
	if err != nil {
		b.Fatalf("Failed to compile rule with mapping: %v", err)
	}

	// Test event with direct fields
	directEvent := map[string]interface{}{
		"EventID":     1,
		"Image":       "C:\\Tools\\test.exe",
		"CommandLine": "test.exe --parameter value",
	}

	// Test event với mapped fields
	mappedEvent := map[string]interface{}{
		"EventID":               1,
		"ProcessImage":          "C:\\Tools\\test.exe",
		"ProcessCommandLine":    "test.exe --parameter value",
	}

	b.Run("No_Mapping_Direct_Fields", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := engineNoMapping.Evaluate(directEvent)
			if err != nil {
				b.Fatalf("Direct field evaluation failed: %v", err)
			}
		}
	})

	b.Run("With_Mapping_Mapped_Fields", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := engineWithMapping.Evaluate(mappedEvent)
			if err != nil {
				b.Fatalf("Mapped field evaluation failed: %v", err)
			}
		}
	})

	b.Run("With_Mapping_Direct_Fields", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := engineWithMapping.Evaluate(directEvent)
			if err != nil {
				b.Fatalf("Direct field with mapping evaluation failed: %v", err)
			}
		}
	})
}

// BenchmarkComplexRules benchmarks complex rule patterns
func BenchmarkComplexRules(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	complexRules := []struct {
		name string
		rule string
	}{
		{
			name: "Simple_Equals",
			rule: `title: Simple Rule
logsource:
    category: process_creation
detection:
    selection:
        Image: 'test.exe'
    condition: selection
level: low`,
		},
		{
			name: "Multiple_Contains",
			rule: `title: Multiple Contains
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'param1'
            - 'param2'
            - 'param3'
            - 'param4'
            - 'param5'
    condition: selection
level: medium`,
		},
		{
			name: "Complex_Logic",
			rule: `title: Complex Logic
logsource:
    category: process_creation
detection:
    selection1:
        Image|endswith: '\tool.exe'
    selection2:
        CommandLine|contains:
            - 'dangerous'
            - 'malicious'
    filter:
        CommandLine|contains: 'whitelist'
    condition: (selection1 and selection2) and not filter
level: high`,
		},
		{
			name: "Regex_Pattern",
			rule: `title: Regex Pattern
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '(cmd|powershell)\.exe.*(-e|-enc|-EncodedCommand)'
    condition: selection
level: high`,
		},
	}

	event := map[string]interface{}{
		"EventID":     1,
		"Image":       "C:\\Tools\\tool.exe",
		"CommandLine": "tool.exe --dangerous parameter",
	}

	for _, tc := range complexRules {
		b.Run(tc.name, func(b *testing.B) {
			engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
			setupBenchmarkFieldMappings(engine)

			err := engine.FromRules([]string{tc.rule})
			if err != nil {
				b.Fatalf("Failed to compile %s rule: %v", tc.name, err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := engine.Evaluate(event)
				if err != nil {
					b.Fatalf("%s evaluation failed: %v", tc.name, err)
				}
			}
		})
	}
}

// Helper functions for benchmarks

func setupBenchmarkFieldMappings(engine *sigma.SigmaEngine) {
	mappings := map[string]string{
		"ProcessImage":        "Image",
		"ProcessCommandLine":  "CommandLine",
		"ParentProcessImage":  "ParentImage",
		"TargetFilename":      "file_path",
		"DestinationIp":       "dst_ip",
		"SourceIp":            "src_ip",
		"DestinationPort":     "dst_port",
		"SourcePort":          "src_port",
	}

	for from, to := range mappings {
		engine.AddFieldMapping(from, to)
	}
}

func setupExtensiveFieldMappings(engine *sigma.SigmaEngine) {
	mappings := map[string]string{
		// Process fields
		"ProcessImage":                "Image",
		"ProcessCommandLine":          "CommandLine",
		"ParentProcessImage":          "ParentImage",
		"ParentProcessCommandLine":    "ParentCommandLine",
		"ProcessId":                   "ProcessId",
		"ParentProcessId":             "ParentProcessId",
		"ProcessName":                 "ProcessName",
		"ParentProcessName":           "ParentProcessName",
		
		// File fields
		"TargetFilename":              "file_path",
		"FileName":                    "file_name",
		"FilePath":                    "file_path",
		"SourceFilename":              "src_file",
		"DestinationFilename":         "dst_file",
		
		// Network fields
		"DestinationIp":               "dst_ip",
		"SourceIp":                    "src_ip",
		"DestinationPort":             "dst_port",
		"SourcePort":                  "src_port",
		"Protocol":                    "protocol",
		"DestinationHostname":         "dst_host",
		"SourceHostname":              "src_host",
		
		// Registry fields
		"TargetObject":                "reg_key",
		"Details":                     "reg_value",
		"RegistryKey":                 "reg_key",
		"RegistryValue":               "reg_value",
		
		// DNS fields
		"QueryName":                   "dns_query",
		"QueryResult":                 "dns_answer",
		"QueryType":                   "dns_type",
		"QueryStatus":                 "dns_status",
		
		// User fields
		"User":                        "user_name",
		"UserName":                    "user_name",
		"LogonType":                   "logon_type",
		"LogonId":                     "logon_id",
		"SubjectUserName":             "subject_user",
		"TargetUserName":              "target_user",
		
		// Service fields
		"ServiceName":                 "service_name",
		"ServiceFileName":             "service_file",
		"ServiceType":                 "service_type",
		"StartType":                   "start_type",
	}

	for from, to := range mappings {
		engine.AddFieldMapping(from, to)
	}
}

func generateBenchmarkRules(count int) []string {
	rules := make([]string, count)
	
	ruleTemplates := []string{
		`title: Generated Rule %d - Process
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\tool_%d.exe'
        CommandLine|contains: 'param_%d'
    condition: selection
level: medium`,

		`title: Generated Rule %d - Network
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort: %d
        ProcessName|endswith: '.exe'
    condition: selection
level: low`,

		`title: Generated Rule %d - File
logsource:
    category: file_event
detection:
    selection:
        file_path|contains: '\temp\\'
        file_name|endswith: '.tmp_%d'
    condition: selection
level: low`,
	}
	
	for i := 0; i < count; i++ {
		template := ruleTemplates[i%len(ruleTemplates)]
		switch i % len(ruleTemplates) {
		case 0:
			rules[i] = fmt.Sprintf(template, i, i%10, i%20)
		case 1:
			rules[i] = fmt.Sprintf(template, i, 1000+i%9000)
		case 2:
			rules[i] = fmt.Sprintf(template, i, i%100)
		}
	}
	
	return rules
}

func generateRandomEvent(seed int) map[string]interface{} {
	rand.Seed(int64(seed))
	
	eventTypes := []map[string]interface{}{
		{
			"EventID": 1,
			"Image":   fmt.Sprintf("C:\\Tools\\tool_%d.exe", rand.Intn(20)),
			"CommandLine": fmt.Sprintf("tool_%d.exe param_%d", rand.Intn(20), rand.Intn(40)),
			"ProcessId": 1000 + rand.Intn(9000),
		},
		{
			"EventID": 3,
			"ProcessName": "chrome.exe",
			"DestinationIp": fmt.Sprintf("192.168.1.%d", rand.Intn(255)),
			"DestinationPort": 80 + rand.Intn(8000),
			"Protocol": "tcp",
		},
		{
			"EventID": 11,
			"file_path": fmt.Sprintf("C:\\temp\\file_%d.tmp", rand.Intn(1000)),
			"file_name": fmt.Sprintf("file_%d.tmp_%d", rand.Intn(100), rand.Intn(200)),
			"ProcessId": 1000 + rand.Intn(9000),
		},
	}
	
	return eventTypes[seed%len(eventTypes)]
}
