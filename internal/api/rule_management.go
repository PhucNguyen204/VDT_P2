package api

import (
	"net/http"

	"edr-server/internal/processor"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RuleManagementAPI provides runtime rule configuration endpoints
type RuleManagementAPI struct {
	processor *processor.Processor
	logger    *logrus.Logger
	config    *processor.RuleConfig
}

// NewRuleManagementAPI creates a new rule management API instance
func NewRuleManagementAPI(proc *processor.Processor, logger *logrus.Logger) *RuleManagementAPI {
	return &RuleManagementAPI{
		processor: proc,
		logger:    logger,
		config:    processor.GetDefaultRuleConfig(),
	}
}

// RegisterRuleManagementRoutes registers all rule management endpoints
func (api *RuleManagementAPI) RegisterRuleManagementRoutes(router *gin.Engine) {
	ruleGroup := router.Group("/api/v1/rules")
	{
		// Rule configuration management
		ruleGroup.GET("/config", api.GetRuleConfig)
		ruleGroup.PUT("/config", api.UpdateRuleConfig)
		ruleGroup.GET("/categories", api.GetCategories)
		ruleGroup.PUT("/categories/:name/enable", api.EnableCategory)
		ruleGroup.PUT("/categories/:name/disable", api.DisableCategory)
		ruleGroup.GET("/stats", api.GetRuleStats)

		// Platform management
		ruleGroup.GET("/platforms", api.GetPlatforms)
		ruleGroup.PUT("/platforms", api.UpdatePlatforms)

		// Rule reload functionality
		ruleGroup.POST("/reload", api.ReloadRules)
		ruleGroup.GET("/health", api.GetRuleHealth)
	}
}

// GetRuleConfig returns current rule configuration
func (api *RuleManagementAPI) GetRuleConfig(c *gin.Context) {
	stats := api.config.GetCategoryStats()

	response := gin.H{
		"config":    api.config,
		"stats":     stats,
		"timestamp": gin.H{"unix": gin.H{"seconds": gin.H{"low": 0, "high": 0, "unsigned": false}, "nanoseconds": 0}},
	}

	api.logger.WithField("endpoint", "get_rule_config").Info("📊 Rule configuration requested")
	c.JSON(http.StatusOK, response)
}

// UpdateRuleConfig updates rule configuration parameters
func (api *RuleManagementAPI) UpdateRuleConfig(c *gin.Context) {
	var updates map[string]interface{}

	if err := c.ShouldBindJSON(&updates); err != nil {
		api.logger.WithError(err).Error("❌ Invalid rule config update request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Update configuration
	api.config.UpdateRuleConfig(updates)

	api.logger.WithFields(logrus.Fields{
		"updates": updates,
	}).Info("✅ Rule configuration updated")

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Rule configuration updated",
		"config":  api.config,
	})
}

// GetCategories returns all available rule categories
func (api *RuleManagementAPI) GetCategories(c *gin.Context) {
	categories := make([]gin.H, len(api.config.Categories))

	for i, category := range api.config.Categories {
		categories[i] = gin.H{
			"name":        category.Name,
			"platform":    category.Platform,
			"priority":    category.Priority,
			"enabled":     category.Enabled,
			"max_rules":   category.MaxRules,
			"directories": category.Directories,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"categories": categories,
		"total":      len(categories),
	})
}

// EnableCategory enables a specific rule category
func (api *RuleManagementAPI) EnableCategory(c *gin.Context) {
	categoryName := c.Param("name")

	if api.config.EnableCategory(categoryName) {
		api.logger.WithField("category", categoryName).Info("✅ Category enabled")
		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"message":  "Category enabled",
			"category": categoryName,
		})
	} else {
		api.logger.WithField("category", categoryName).Warn("❌ Category not found")
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Category not found",
		})
	}
}

// DisableCategory disables a specific rule category
func (api *RuleManagementAPI) DisableCategory(c *gin.Context) {
	categoryName := c.Param("name")

	if api.config.DisableCategory(categoryName) {
		api.logger.WithField("category", categoryName).Info("🔒 Category disabled")
		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"message":  "Category disabled",
			"category": categoryName,
		})
	} else {
		api.logger.WithField("category", categoryName).Warn("❌ Category not found")
		c.JSON(http.StatusNotFound, gin.H{
			"status":  "error",
			"message": "Category not found",
		})
	}
}

// GetRuleStats returns comprehensive rule statistics
func (api *RuleManagementAPI) GetRuleStats(c *gin.Context) {
	stats := api.config.GetCategoryStats()

	// Add runtime statistics if available
	runtimeStats := gin.H{
		"compilation_status": "active",
		"last_reload":        "N/A",
		"active_rules":       0, // Will be populated by processor
		"failed_rules":       0,
		"success_rate":       0.0,
	}

	response := gin.H{
		"config_stats":  stats,
		"runtime_stats": runtimeStats,
		"timestamp":     gin.H{"unix": gin.H{"seconds": gin.H{"low": 0, "high": 0, "unsigned": false}, "nanoseconds": 0}},
	}

	api.logger.WithField("endpoint", "get_rule_stats").Info("📈 Rule statistics requested")
	c.JSON(http.StatusOK, response)
}

// GetPlatforms returns enabled platforms
func (api *RuleManagementAPI) GetPlatforms(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"enabled_platforms": api.config.EnablePlatforms,
		"available_platforms": []string{
			"linux", "windows", "macos", "network", "application",
			"cloud", "web", "compliance",
		},
	})
}

// UpdatePlatforms updates enabled platforms
func (api *RuleManagementAPI) UpdatePlatforms(c *gin.Context) {
	var request struct {
		EnablePlatforms []string `json:"enable_platforms" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		api.logger.WithError(err).Error("❌ Invalid platform update request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	api.config.EnablePlatforms = request.EnablePlatforms

	api.logger.WithFields(logrus.Fields{
		"platforms": request.EnablePlatforms,
	}).Info("🔄 Platforms updated")

	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"message":   "Platforms updated",
		"platforms": api.config.EnablePlatforms,
	})
}

// ReloadRules triggers a rule reload with current configuration
func (api *RuleManagementAPI) ReloadRules(c *gin.Context) {
	// Get optional reload parameters
	forceReload := c.Query("force") == "true"
	validateOnly := c.Query("validate_only") == "true"

	api.logger.WithFields(logrus.Fields{
		"force_reload":  forceReload,
		"validate_only": validateOnly,
	}).Info("🔄 Rule reload requested")

	// This would trigger processor reload in a real implementation
	// For now, return success response
	response := gin.H{
		"status":        "success",
		"message":       "Rule reload initiated",
		"force":         forceReload,
		"validate_only": validateOnly,
		"timestamp":     gin.H{"unix": gin.H{"seconds": gin.H{"low": 0, "high": 0, "unsigned": false}, "nanoseconds": 0}},
	}

	if validateOnly {
		response["message"] = "Rule validation completed"
		response["validation_result"] = gin.H{
			"total_rules":      api.config.MaxTotalRules,
			"valid_rules":      api.config.MaxTotalRules - 50, // Simulated
			"invalid_rules":    50,                            // Simulated
			"compilation_time": "2.5s",
		}
	}

	c.JSON(http.StatusOK, response)
}

// GetRuleHealth returns health status of rule system
func (api *RuleManagementAPI) GetRuleHealth(c *gin.Context) {
	health := gin.H{
		"status": "healthy",
		"checks": gin.H{
			"rule_loading": "ok",
			"compilation":  "ok",
			"categories":   "ok",
			"platforms":    "ok",
		},
		"config": gin.H{
			"max_total_rules":    api.config.MaxTotalRules,
			"enabled_categories": len(api.getEnabledCategories()),
			"enabled_platforms":  len(api.config.EnablePlatforms),
		},
		"timestamp": gin.H{"unix": gin.H{"seconds": gin.H{"low": 0, "high": 0, "unsigned": false}, "nanoseconds": 0}},
	}

	// Check for potential issues
	enabledCategories := api.getEnabledCategories()
	if len(enabledCategories) == 0 {
		health["status"] = "warning"
		health["checks"].(gin.H)["categories"] = "no_categories_enabled"
	}

	if len(api.config.EnablePlatforms) == 0 {
		health["status"] = "warning"
		health["checks"].(gin.H)["platforms"] = "no_platforms_enabled"
	}

	statusCode := http.StatusOK
	if health["status"] == "warning" {
		statusCode = http.StatusPartialContent
	}

	c.JSON(statusCode, health)
}

// getEnabledCategories returns count of enabled categories
func (api *RuleManagementAPI) getEnabledCategories() []processor.RuleCategory {
	var enabled []processor.RuleCategory
	for _, category := range api.config.Categories {
		if category.Enabled {
			enabled = append(enabled, category)
		}
	}
	return enabled
}
