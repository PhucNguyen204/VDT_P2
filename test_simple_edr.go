package main

import (
	"fmt"
	"log"
	"time"

	"edr-server/internal/sigma"
	"github.com/sirupsen/logrus"
)

func main() {
	// Khởi tạo logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	
	fmt.Println("🚀 EDR Engine Demo - Phát hiện hành vi nguy hiểm")
	fmt.Println("=" + string(make([]byte, 50)))
	
	// Define simple test rules
	testRules := []string{
		// SSH Brute Force Rule
		`title: SSH Brute Force Attack Detection
id: test-ssh-brute-force
status: test
description: Detects SSH brute force attacks using hydra
author: EDR Team
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'hydra'
            - 'ssh://'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1110`,
    
		// Mimikatz Detection Rule
		`title: Mimikatz Process Detection
id: test-mimikatz
status: test
description: Detects Mimikatz execution
author: EDR Team
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith:
            - '\mimikatz.exe'
            - '\mimilove.exe'
    selection2:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'lsadump::'
            - 'privilege::debug'
    condition: selection1 or selection2
level: critical
tags:
    - attack.credential_access
    - attack.t1003`,
    
		// PowerShell Encoded Command
		`title: PowerShell Encoded Command
id: test-powershell-encoded
status: test
description: Detects PowerShell with encoded commands
author: EDR Team
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc'
            - '-e '
        Image|endswith: '\powershell.exe'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001`,
    
		// PsExec Lateral Movement
		`title: PsExec Lateral Movement
id: test-psexec
status: test
description: Detects PsExec usage for lateral movement
author: EDR Team
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\psexec.exe'
            - '\psexec64.exe'
        CommandLine|contains: '\\'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002`,
	}
	
	// Tạo engine config
	config := sigma.DefaultEngineConfig()
	engine := sigma.NewSigmaEngine(config, logger)
	
	// Compile rules
	fmt.Println("📋 Đang compile rules...")
	err := engine.FromRules(testRules)
	if err != nil {
		log.Fatalf("❌ Không thể compile rules: %v", err)
	}
	fmt.Printf("✅ Đã load %d rules\n\n", len(testRules))
	
	// Test events
	testEvents := []struct {
		name  string
		event map[string]interface{}
	}{
		{
			name: "🔴 SSH Brute Force Attack (Hydra)",
			event: map[string]interface{}{
				"EventID": 1,
				"CommandLine": "hydra -l root -P /usr/share/wordlists/passwords.txt -t 4 ssh://192.168.1.100:22",
				"Image": "/usr/bin/hydra",
				"ProcessName": "hydra",
				"User": "attacker",
				"ComputerName": "attack-machine",
				"@timestamp": time.Now().Format(time.RFC3339),
			},
		},
		{
			name: "🔴 Mimikatz Credential Dumping",
			event: map[string]interface{}{
				"EventID": 1,
				"CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
				"Image": "C:\\Tools\\mimikatz.exe",
				"ProcessName": "mimikatz.exe",
				"User": "admin",
				"ComputerName": "DESKTOP-WIN10",
				"@timestamp": time.Now().Format(time.RFC3339),
			},
		},
		{
			name: "🔴 PowerShell Encoded Command",
			event: map[string]interface{}{
				"EventID": 1,
				"CommandLine": "powershell.exe -EncodedCommand IABpAHcAcgAgAC0AdQBzAGUAYgAgAGgAdAB0AHAAOgAvAC8AbQBhAGw",
				"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"ProcessName": "powershell.exe",
				"User": "user1",
				"ComputerName": "WORKSTATION-01",
				"@timestamp": time.Now().Format(time.RFC3339),
			},
		},
		{
			name: "🔴 Lateral Movement via PsExec",
			event: map[string]interface{}{
				"EventID": 1,
				"CommandLine": "psexec.exe \\\\192.168.1.105 -u Administrator -p Password123 cmd.exe",
				"Image": "C:\\Tools\\PsExec.exe",
				"ProcessName": "psexec.exe",
				"User": "admin",
				"ComputerName": "DC-SERVER",
				"@timestamp": time.Now().Format(time.RFC3339),
			},
		},
		{
			name: "🟢 Normal Process - Chrome",
			event: map[string]interface{}{
				"EventID": 1,
				"CommandLine": "chrome.exe --no-sandbox",
				"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
				"ProcessName": "chrome.exe",
				"User": "user1",
				"ComputerName": "DESKTOP-01",
				"@timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}
	
	// Process events through engine
	fmt.Println("🔍 Phân tích events...")
	fmt.Println()
	
	detectedCount := 0
	for _, test := range testEvents {
		fmt.Printf("Event: %s\n", test.name)
		fmt.Printf("  Command: %s\n", test.event["CommandLine"])
		
		// Process event
		result, err := engine.Evaluate(test.event)
		if err != nil {
			fmt.Printf("  ❌ Lỗi khi phân tích: %v\n", err)
			continue
		}
		
		if result != nil && len(result.MatchedRules) > 0 {
			detectedCount++
			fmt.Printf("  ⚠️  PHÁT HIỆN: %d threats\n", len(result.MatchedRules))
			for _, match := range result.MatchedRules {
				fmt.Printf("     - Rule: %s (Level: %s)\n", match.Title, match.Level)
				fmt.Printf("       Description: %s\n", match.Description)
				if len(match.Tags) > 0 {
					fmt.Printf("       MITRE: %v\n", match.Tags)
				}
			}
		} else {
			fmt.Printf("  ✅ Không phát hiện threat\n")
		}
		fmt.Println()
	}
	
	// Summary
	fmt.Println("=" + string(make([]byte, 50)))
	fmt.Printf("📊 Tổng kết: Phát hiện %d/%d threats\n", detectedCount, len(testEvents))
	fmt.Println("\n✨ EDR Engine hoạt động tốt! Engine có thể phát hiện các hành vi nguy hiểm.")
}