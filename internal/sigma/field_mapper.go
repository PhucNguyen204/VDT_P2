package sigma

import (
	"strings"
	"sync"
)

// FieldMapper maps fields between different taxonomies
type FieldMapper struct {
	mappings        map[string]string // from -> to mappings
	reverseMappings map[string]string // to -> from mappings
	caseSensitive   bool
	mu              sync.RWMutex
}

// NewFieldMapper tạo field mapper mới
func NewFieldMapper() *FieldMapper {
	return &FieldMapper{
		mappings:        make(map[string]string),
		reverseMappings: make(map[string]string),
		caseSensitive:   false,
	}
}

// NewFieldMapperWithCase tạo field mapper với case sensitivity option
func NewFieldMapperWithCase(caseSensitive bool) *FieldMapper {
	return &FieldMapper{
		mappings:        make(map[string]string),
		reverseMappings: make(map[string]string),
		caseSensitive:   caseSensitive,
	}
}

// AddMapping add field mapping from -> to
func (fm *FieldMapper) AddMapping(from, to string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Normalize case if not case sensitive
	if !fm.caseSensitive {
		from = strings.ToLower(from)
		to = strings.ToLower(to)
	}

	fm.mappings[from] = to
	fm.reverseMappings[to] = from
}

// MapField maps a field name to its target field
func (fm *FieldMapper) MapField(field string) string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	normalizedField := field
	if !fm.caseSensitive {
		normalizedField = strings.ToLower(field)
	}

	if mapped, exists := fm.mappings[normalizedField]; exists {
		return mapped
	}

	// Return original field if no mapping found
	return field
}

// ReverseMapField maps a target field back to its source field
func (fm *FieldMapper) ReverseMapField(field string) string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	normalizedField := field
	if !fm.caseSensitive {
		normalizedField = strings.ToLower(field)
	}

	if mapped, exists := fm.reverseMappings[normalizedField]; exists {
		return mapped
	}

	// Return original field if no mapping found
	return field
}

// HasMapping check if field has mapping
func (fm *FieldMapper) HasMapping(field string) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	normalizedField := field
	if !fm.caseSensitive {
		normalizedField = strings.ToLower(field)
	}

	_, exists := fm.mappings[normalizedField]
	return exists
}

// RemoveMapping remove field mapping
func (fm *FieldMapper) RemoveMapping(from string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	normalizedFrom := from
	if !fm.caseSensitive {
		normalizedFrom = strings.ToLower(from)
	}

	if to, exists := fm.mappings[normalizedFrom]; exists {
		delete(fm.mappings, normalizedFrom)
		delete(fm.reverseMappings, to)
	}
}

// GetAllMappings return all current mappings
func (fm *FieldMapper) GetAllMappings() map[string]string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	// Return copy to prevent external modification
	mappings := make(map[string]string)
	for k, v := range fm.mappings {
		mappings[k] = v
	}

	return mappings
}

// LoadMappingsFromMap load mappings from map
func (fm *FieldMapper) LoadMappingsFromMap(mappings map[string]string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Clear existing mappings
	fm.mappings = make(map[string]string)
	fm.reverseMappings = make(map[string]string)

	// Load new mappings
	for from, to := range mappings {
		normalizedFrom := from
		normalizedTo := to
		if !fm.caseSensitive {
			normalizedFrom = strings.ToLower(from)
			normalizedTo = strings.ToLower(to)
		}

		fm.mappings[normalizedFrom] = normalizedTo
		fm.reverseMappings[normalizedTo] = normalizedFrom
	}
}

// LoadCommonMappings load common field mappings for popular log sources
func (fm *FieldMapper) LoadCommonMappings() {
	commonMappings := map[string]string{
		// Windows Event Log mappings
		"ProcessImage":             "Image",
		"ProcessCommandLine":       "CommandLine",
		"ParentProcessImage":       "ParentImage",
		"ParentProcessCommandLine": "ParentCommandLine",
		"ProcessId":                "ProcessId",
		"ParentProcessId":          "ParentProcessId",
		"User":                     "User",
		"LogonId":                  "LogonId",
		"IntegrityLevel":           "IntegrityLevel",
		"Company":                  "Company",
		"Description":              "Description",
		"Product":                  "Product",
		"FileVersion":              "FileVersion",

		// Sysmon mappings
		"UtcTime":           "EventTime",
		"ProcessGuid":       "ProcessGuid",
		"ParentProcessGuid": "ParentProcessGuid",
		"Hashes":            "Hashes",
		"CurrentDirectory":  "CurrentDirectory",
		"OriginalFileName":  "OriginalFileName",

		// Network mappings
		"SourceIp":            "src_ip",
		"DestinationIp":       "dst_ip",
		"SourcePort":          "src_port",
		"DestinationPort":     "dst_port",
		"Protocol":            "protocol",
		"SourceHostname":      "src_host",
		"DestinationHostname": "dst_host",

		// Authentication mappings
		"TargetUserName":            "user",
		"TargetDomainName":          "domain",
		"LogonType":                 "logon_type",
		"AuthenticationPackageName": "auth_package",
		"WorkstationName":           "workstation",
		"IpAddress":                 "src_ip",
		"IpPort":                    "src_port",

		// File mappings
		"TargetFilename":          "file_path",
		"CreationUtcTime":         "file_created",
		"PreviousCreationUtcTime": "file_previous_created",

		// Registry mappings
		"TargetObject": "registry_key",
		"Details":      "registry_value",

		// Process creation mappings
		"CommandLine":       "command_line",
		"ParentCommandLine": "parent_command_line",
		"LogonGuid":         "logon_guid",
		"TerminalSessionId": "session_id",

		// Common timestamp mappings
		"@timestamp":  "timestamp",
		"EventTime":   "timestamp",
		"TimeCreated": "timestamp",
		"SystemTime":  "timestamp",
	}

	fm.LoadMappingsFromMap(commonMappings)
}

// LoadECSMappings load Elastic Common Schema mappings
func (fm *FieldMapper) LoadECSMappings() {
	ecsMappings := map[string]string{
		// ECS Process fields
		"process.executable":          "Image",
		"process.command_line":        "CommandLine",
		"process.pid":                 "ProcessId",
		"process.name":                "ProcessName",
		"process.parent.executable":   "ParentImage",
		"process.parent.command_line": "ParentCommandLine",
		"process.parent.pid":          "ParentProcessId",
		"process.parent.name":         "ParentProcessName",

		// ECS User fields
		"user.name":   "User",
		"user.domain": "Domain",
		"user.id":     "UserId",

		// ECS Network fields
		"source.ip":          "SourceIp",
		"destination.ip":     "DestinationIp",
		"source.port":        "SourcePort",
		"destination.port":   "DestinationPort",
		"network.protocol":   "Protocol",
		"source.domain":      "SourceHostname",
		"destination.domain": "DestinationHostname",

		// ECS File fields
		"file.path":        "TargetFilename",
		"file.name":        "FileName",
		"file.extension":   "FileExtension",
		"file.size":        "FileSize",
		"file.hash.md5":    "MD5",
		"file.hash.sha1":   "SHA1",
		"file.hash.sha256": "SHA256",

		// ECS Event fields
		"event.code":     "EventID",
		"event.action":   "EventType",
		"event.category": "Category",
		"event.outcome":  "Outcome",
		"event.provider": "Provider",

		// ECS Host fields
		"host.name":       "Computer",
		"host.hostname":   "ComputerName",
		"host.os.name":    "OSName",
		"host.os.version": "OSVersion",

		// ECS Agent fields
		"agent.name":    "Agent",
		"agent.version": "AgentVersion",
		"agent.type":    "AgentType",
	}

	fm.LoadMappingsFromMap(ecsMappings)
}

// LoadOSSECMappings load OSSEC/Wazuh field mappings
func (fm *FieldMapper) LoadOSSECMappings() {
	ossecMappings := map[string]string{
		// OSSEC specific fields
		"dstip":    "DestinationIp",
		"srcip":    "SourceIp",
		"dstport":  "DestinationPort",
		"srcport":  "SourcePort",
		"dstuser":  "DestinationUser",
		"srcuser":  "SourceUser",
		"protocol": "Protocol",
		"action":   "Action",
		"status":   "Status",
		"url":      "URL",
		"data":     "Data",

		// File monitoring
		"filename":    "TargetFilename",
		"md5_after":   "MD5",
		"sha1_after":  "SHA1",
		"size_after":  "FileSize",
		"perm_after":  "Permissions",
		"owner_after": "Owner",
		"gid_after":   "GroupId",
		"uid_after":   "UserId",

		// System monitoring
		"command":       "CommandLine",
		"ppid":          "ParentProcessId",
		"pid":           "ProcessId",
		"program_name":  "ProcessName",
		"effective_uid": "EffectiveUserId",
		"effective_gid": "EffectiveGroupId",
		"loginuid":      "LoginUserId",
		"tty":           "TTY",
		"session":       "SessionId",
	}

	fm.LoadMappingsFromMap(ossecMappings)
}

// Clear clear all mappings
func (fm *FieldMapper) Clear() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.mappings = make(map[string]string)
	fm.reverseMappings = make(map[string]string)
}

// Count return number of mappings
func (fm *FieldMapper) Count() int {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	return len(fm.mappings)
}

// SetCaseSensitive set case sensitivity
func (fm *FieldMapper) SetCaseSensitive(caseSensitive bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.caseSensitive == caseSensitive {
		return // No change needed
	}

	fm.caseSensitive = caseSensitive

	// Rebuild mappings with new case sensitivity
	oldMappings := fm.mappings
	fm.mappings = make(map[string]string)
	fm.reverseMappings = make(map[string]string)

	for from, to := range oldMappings {
		normalizedFrom := from
		normalizedTo := to
		if !fm.caseSensitive {
			normalizedFrom = strings.ToLower(from)
			normalizedTo = strings.ToLower(to)
		}

		fm.mappings[normalizedFrom] = normalizedTo
		fm.reverseMappings[normalizedTo] = normalizedFrom
	}
}
