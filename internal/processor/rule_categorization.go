package processor

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// RuleCategory định nghĩa categories cho SIGMA rules
type RuleCategory struct {
	Name        string   `json:"name"`
	Directories []string `json:"directories"`
	Platform    string   `json:"platform"`
	Priority    int      `json:"priority"`
	Enabled     bool     `json:"enabled"`
	MaxRules    int      `json:"max_rules"`
}

// RuleConfig cấu hình cho rule management
type RuleConfig struct {
	Categories      []RuleCategory `json:"categories"`
	MaxTotalRules   int            `json:"max_total_rules"`
	EnablePlatforms []string       `json:"enable_platforms"`
}

// GetDefaultRuleConfig returns optimized rule configuration for EDR system
func GetDefaultRuleConfig() *RuleConfig {
	return &RuleConfig{
		MaxTotalRules:   -1, // UNLIMITED: Parse all 3,033 SIGMA rules
		EnablePlatforms: []string{"linux", "network", "application", "windows", "cloud", "web", "macos", "compliance"},
		Categories: []RuleCategory{
			// === HIGH PRIORITY LINUX RULES ===
			{
				Name:        "Linux Authentication",
				Platform:    "linux",
				Priority:    1,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"linux/builtin"},
			},
			{
				Name:        "Linux Process Monitoring",
				Platform:    "linux",
				Priority:    2,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"linux/process_creation", "linux/auditd"},
			},
			{
				Name:        "Linux Network & File Operations",
				Platform:    "linux",
				Priority:    3,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"linux/network_connection", "linux/file_event"},
			},

			// === NETWORK SECURITY RULES ===
			{
				Name:        "Network Security",
				Platform:    "network",
				Priority:    4,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"network/dns", "network/firewall", "network/cisco", "network/zeek", "network/juniper"},
			},

			// === APPLICATION LAYER SECURITY ===
			{
				Name:     "Application Security",
				Platform: "application",
				Priority: 5,
				Enabled:  true,
				MaxRules: -1, // Unlimited for comprehensive coverage
				Directories: []string{
					"application/opencanary", "application/django", "application/kubernetes",
					"application/sql", "application/python", "application/nodejs", "application/ruby",
					"application/jvm", "application/rpc_firewall", "application/spring", "application/velocity",
				},
			},

			// === WINDOWS SECURITY RULES ===
			{
				Name:        "Windows Authentication & Process",
				Platform:    "windows",
				Priority:    6,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"windows/builtin", "windows/process_creation", "windows/powershell"},
			},
			{
				Name:     "Windows System Operations",
				Platform: "windows",
				Priority: 7,
				Enabled:  true,
				MaxRules: -1, // Unlimited for comprehensive coverage
				Directories: []string{
					"windows/registry", "windows/file", "windows/network_connection",
					"windows/dns_query", "windows/driver_load", "windows/image_load",
					"windows/create_remote_thread", "windows/create_stream_hash",
					"windows/file_delete", "windows/file_event", "windows/file_rename",
				},
			},
			{
				Name:     "Windows Advanced Monitoring",
				Platform: "windows",
				Priority: 8,
				Enabled:  true,
				MaxRules: -1, // Unlimited for comprehensive coverage
				Directories: []string{
					"windows/pipe_created", "windows/process_access", "windows/wmi_event", "windows/sysmon",
					"windows/raw_access_thread", "windows/process_tampering",
				},
			},

			// === CLOUD & INFRASTRUCTURE ===
			{
				Name:        "Cloud Infrastructure",
				Platform:    "cloud",
				Priority:    9,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"cloud/aws", "cloud/azure", "cloud/gcp", "cloud/m365", "cloud/github", "cloud/okta"},
			},

			// === WEB & PROXY SECURITY ===
			{
				Name:        "Web Security",
				Platform:    "web",
				Priority:    10,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"web/webserver_generic", "web/proxy_generic"},
			},

			// === MACOS SECURITY ===
			{
				Name:        "macOS Security",
				Platform:    "macos",
				Priority:    11,
				Enabled:     true, // Enabled for comprehensive cross-platform coverage
				MaxRules:    -1,   // Unlimited for comprehensive coverage
				Directories: []string{"macos/process_creation", "macos/file_event"},
			},

			// === COMPLIANCE & SPECIALIZED ===
			{
				Name:        "Compliance & Antivirus",
				Platform:    "compliance",
				Priority:    12,
				Enabled:     true,
				MaxRules:    -1, // Unlimited for comprehensive coverage
				Directories: []string{"category/antivirus", "category/database", "compliance"},
			},
		},
	}
}

// LoadCategorizedRules loads SIGMA rules based on platform configuration
func LoadCategorizedRules(rulesDir string, config *RuleConfig, logger *logrus.Logger) ([]string, error) {
	var allRules []string
	totalLoaded := 0

	logger.WithFields(logrus.Fields{
		"max_total_rules":   config.MaxTotalRules,
		"enabled_platforms": config.EnablePlatforms,
		"categories":        len(config.Categories),
	}).Info("🎯 Starting categorized rule loading")

	// Sort categories by priority
	enabledCategories := getEnabledCategoriesByPriority(config)

	for _, category := range enabledCategories {
		if config.MaxTotalRules > 0 && totalLoaded >= config.MaxTotalRules {
			logger.WithField("total_loaded", totalLoaded).Info("📊 Reached maximum rule limit")
			break
		}

		// Check if platform is enabled
		if !isPlatformEnabled(category.Platform, config.EnablePlatforms) {
			logger.WithFields(logrus.Fields{
				"category": category.Name,
				"platform": category.Platform,
			}).Debug("⏭️ Platform disabled, skipping category")
			continue
		}

		// Load rules for this category
		categoryRules, err := loadCategoryRules(rulesDir, category, logger)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"category": category.Name,
				"error":    err.Error(),
			}).Warn("❌ Failed to load category rules")
			continue
		}

		// Apply category rule limit (only if limit is set)
		if category.MaxRules > 0 && len(categoryRules) > category.MaxRules {
			categoryRules = categoryRules[:category.MaxRules]
		}

		// Apply global rule limit (only if limit is set)
		if config.MaxTotalRules > 0 {
			remaining := config.MaxTotalRules - totalLoaded
			if len(categoryRules) > remaining {
				categoryRules = categoryRules[:remaining]
			}
		}

		allRules = append(allRules, categoryRules...)
		totalLoaded += len(categoryRules)

		logger.WithFields(logrus.Fields{
			"category":     category.Name,
			"platform":     category.Platform,
			"rules_loaded": len(categoryRules),
			"total_loaded": totalLoaded,
		}).Info("✅ Category rules loaded")
	}

	logger.WithFields(logrus.Fields{
		"total_rules":          len(allRules),
		"categories_processed": len(enabledCategories),
	}).Info("🎉 Categorized rule loading completed")

	return allRules, nil
}

// getEnabledCategoriesByPriority returns enabled categories sorted by priority
func getEnabledCategoriesByPriority(config *RuleConfig) []RuleCategory {
	var enabled []RuleCategory

	for _, category := range config.Categories {
		if category.Enabled {
			enabled = append(enabled, category)
		}
	}

	// Sort by priority (lower priority number = higher priority)
	for i := 0; i < len(enabled)-1; i++ {
		for j := i + 1; j < len(enabled); j++ {
			if enabled[i].Priority > enabled[j].Priority {
				enabled[i], enabled[j] = enabled[j], enabled[i]
			}
		}
	}

	return enabled
}

// isPlatformEnabled checks if a platform is enabled
func isPlatformEnabled(platform string, enabledPlatforms []string) bool {
	for _, p := range enabledPlatforms {
		if p == platform {
			return true
		}
	}
	return false
}

// loadCategoryRules loads rules for a specific category
func loadCategoryRules(rulesDir string, category RuleCategory, logger *logrus.Logger) ([]string, error) {
	var categoryRules []string

	for _, dir := range category.Directories {
		dirRules, err := loadRulesFromDirectory(rulesDir, dir, logger)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"category":  category.Name,
				"directory": dir,
				"error":     err.Error(),
			}).Debug("❌ Failed to load rules from directory")
			continue
		}

		categoryRules = append(categoryRules, dirRules...)
	}

	return categoryRules, nil
}

// loadRulesFromDirectory loads all rules from a specific directory
func loadRulesFromDirectory(rulesDir, subDir string, logger *logrus.Logger) ([]string, error) {
	fullPath := rulesDir + "/" + subDir
	var rules []string

	// Use filepath.Walk to recursively load rules
	err := walkDirectory(fullPath, func(path string, content string) {
		// Basic validation - check if it's a SIGMA rule
		if strings.Contains(content, "title:") && strings.Contains(content, "detection:") {
			rules = append(rules, content)
		}
	})

	if err != nil {
		logger.WithFields(logrus.Fields{
			"directory": subDir,
			"full_path": fullPath,
			"error":     err.Error(),
		}).Debug("❌ Failed to walk directory")
		return []string{}, err
	}

	logger.WithFields(logrus.Fields{
		"directory":    subDir,
		"rules_loaded": len(rules),
	}).Debug("📁 Directory rules loaded")

	return rules, nil
}

// UpdateRuleConfig allows runtime configuration updates
func (config *RuleConfig) UpdateRuleConfig(updates map[string]interface{}) {
	if maxRules, ok := updates["max_total_rules"].(int); ok {
		config.MaxTotalRules = maxRules
	}

	if platforms, ok := updates["enable_platforms"].([]string); ok {
		config.EnablePlatforms = platforms
	}
}

// EnableCategory enables a specific rule category
func (config *RuleConfig) EnableCategory(categoryName string) bool {
	for i := range config.Categories {
		if config.Categories[i].Name == categoryName {
			config.Categories[i].Enabled = true
			return true
		}
	}
	return false
}

// DisableCategory disables a specific rule category
func (config *RuleConfig) DisableCategory(categoryName string) bool {
	for i := range config.Categories {
		if config.Categories[i].Name == categoryName {
			config.Categories[i].Enabled = false
			return true
		}
	}
	return false
}

// GetCategoryStats returns statistics about loaded categories
func (config *RuleConfig) GetCategoryStats() map[string]interface{} {
	stats := make(map[string]interface{})

	enabledCount := 0
	totalMaxRules := 0

	for _, category := range config.Categories {
		if category.Enabled {
			enabledCount++
			totalMaxRules += category.MaxRules
		}
	}

	stats["total_categories"] = len(config.Categories)
	stats["enabled_categories"] = enabledCount
	stats["max_total_rules"] = config.MaxTotalRules
	stats["theoretical_max_rules"] = totalMaxRules
	stats["enabled_platforms"] = config.EnablePlatforms

	return stats
}

// walkDirectory walks through a directory and calls the provided function for each YAML file
func walkDirectory(dirPath string, fn func(path string, content string)) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files/dirs with errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check file extension
		ext := filepath.Ext(info.Name())
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		// Read file content
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return nil // Skip files that can't be read
		}

		// Call provided function with path and content
		fn(path, string(content))
		return nil
	})
}
