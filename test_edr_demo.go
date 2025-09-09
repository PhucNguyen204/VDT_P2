package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	
	// Khởi tạo Sigma Engine
	fmt.Println("📋 Đang load Sigma rules...")
	
	// Load tất cả rules từ thư mục
	rules, err := loadRulesFromDirectory("rules/")
	if err != nil {
		log.Fatalf("❌ Không thể load rules: %v", err)
	}
	
	// Tạo engine config
	config := sigma.DefaultEngineConfig()
	engine := sigma.NewSigmaEngine(config, logger)
	
	// Compile rules
	err = engine.FromRules(rules)
	if err != nil {
		log.Fatalf("❌ Không thể compile rules: %v", err)
	}
	fmt.Printf("✅ Đã load %d rules\n\n", len(rules))
	
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
			fmt.Printf("  ⚠️  PHÁT HIỆN: %d threats\n", len(result.MatchedRules))
			for _, match := range result.MatchedRules {
				fmt.Printf("     - Rule: %s (Level: %s)\n", match.Title, match.Level)
				fmt.Printf("       Description: %s\n", match.Description)
			}
		} else {
			fmt.Printf("  ✅ Không phát hiện threat\n")
		}
		fmt.Println()
	}
	
	// Simulate sending events to server (if running)
	fmt.Println("📡 Thử gửi event đến EDR Server...")
	sendEventToServer(testEvents[0].event)
}

func sendEventToServer(event map[string]interface{}) {
	url := "http://localhost:8080/api/v1/events"
	
	jsonData, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("  ❌ Không thể marshal event: %v\n", err)
		return
	}
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("  ⚠️  Server chưa chạy hoặc không thể kết nối: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("  ✅ Đã gửi event thành công!\n")
	} else {
		fmt.Printf("  ❌ Lỗi từ server: %s\n", resp.Status)
	}
}

func loadRulesFromDirectory(dir string) ([]string, error) {
	var rules []string
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(path, ".yml") {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rules = append(rules, string(content))
		}
		
		return nil
	})
	
	return rules, err
}