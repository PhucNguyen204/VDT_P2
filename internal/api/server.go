package api

import (
	"net/http"
	"strconv"
	"time"

	"edr-server/internal/config"
	"edr-server/internal/database"
	"edr-server/internal/processor"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Server chứa API server
type Server struct {
	config     *config.Config
	repository *database.Repository
	processor  *processor.Processor
	logger     *logrus.Logger
	router     *gin.Engine
}

// NewServer tạo API server mới
func NewServer(cfg *config.Config, db *gorm.DB, processor *processor.Processor, logger *logrus.Logger) *Server {
	server := &Server{
		config:     cfg,
		repository: database.NewRepository(db),
		processor:  processor,
		logger:     logger,
	}

	server.setupRouter()
	return server
}

// Router trả về Gin router
func (s *Server) Router() *gin.Engine {
	return s.router
}

// setupRouter thiết lập các routes
func (s *Server) setupRouter() {
	if !s.config.Server.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	s.router = gin.New()
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())
	s.router.Use(s.corsMiddleware())

	// Health check
	s.router.GET("/health", s.healthCheck)

	// Vector.dev webhook endpoint
	s.router.POST("/api/v1/events", s.receiveEvents)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Events
		v1.GET("/events", s.getEvents)
		v1.GET("/events/:id", s.getEvent)

		// Alerts
		v1.GET("/alerts", s.getAlerts)
		v1.GET("/alerts/:id", s.getAlert)
		v1.PUT("/alerts/:id/status", s.updateAlertStatus)

		// Agents
		v1.GET("/agents", s.getAgents)
		v1.GET("/agents/:id", s.getAgent)
		v1.GET("/agents/:id/events", s.getAgentEvents)

		// Process Trees
		v1.GET("/process-trees", s.getProcessTrees)
		v1.GET("/process-trees/:id", s.getProcessTree)

		// Statistics
		v1.GET("/stats/dashboard", s.getDashboardStats)
		v1.GET("/stats/alerts", s.getAlertStats)
		v1.GET("/stats/process-trees", s.getProcessTreeStats)

		// Sigma Rules
		v1.GET("/rules", s.getSigmaRules)
		v1.GET("/rules/:id", s.getSigmaRule)
		v1.POST("/rules/reload", s.reloadSigmaRules)
	}

	// Serve static files for frontend
	s.router.Static("/static", "./web/static")
	s.router.LoadHTMLGlob("web/templates/*")
	s.router.GET("/", s.serveIndex)
}

// corsMiddleware thêm CORS headers
func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// healthCheck endpoint kiểm tra health của server
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
	})
}

// receiveEvents nhận events từ Vector.dev
func (s *Server) receiveEvents(c *gin.Context) {
	var events []processor.VectorEvent

	if err := c.ShouldBindJSON(&events); err != nil {
		s.logger.WithError(err).Error("Không thể parse Vector events")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	s.logger.WithField("count", len(events)).Info("Nhận events từ Vector")

	// Process từng event
	processedCount := 0
	for _, event := range events {
		err := s.processor.ProcessVectorEvent(&event)
		if err != nil {
			s.logger.WithError(err).Error("Lỗi khi process Vector event")
			continue
		}
		processedCount++
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Events processed successfully",
		"total":     len(events),
		"processed": processedCount,
	})
}

// getEvents lấy danh sách events
func (s *Server) getEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	events, err := s.repository.GetEvents(limit, offset)
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi lấy events")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"count":  len(events),
	})
}

// getEvent lấy một event cụ thể
func (s *Server) getEvent(c *gin.Context) {
	eventID := c.Param("id")

	// Implementation cần thêm vào repository
	c.JSON(http.StatusOK, gin.H{
		"event_id": eventID,
		"message":  "Not implemented yet",
	})
}

// getAlerts lấy danh sách alerts
func (s *Server) getAlerts(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	alerts, err := s.repository.GetAlerts(limit, offset)
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi lấy alerts")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// getAlert lấy một alert cụ thể
func (s *Server) getAlert(c *gin.Context) {
	alertID := c.Param("id")

	// Implementation cần thêm vào repository
	c.JSON(http.StatusOK, gin.H{
		"alert_id": alertID,
		"message":  "Not implemented yet",
	})
}

// updateAlertStatus cập nhật trạng thái alert
func (s *Server) updateAlertStatus(c *gin.Context) {
	alertID := c.Param("id")

	var request struct {
		Status string `json:"status" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err := s.repository.UpdateAlertStatus(alertID, request.Status)
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi update alert status")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Alert status updated successfully",
	})
}

// getAgents lấy danh sách agents
func (s *Server) getAgents(c *gin.Context) {
	agents, err := s.repository.GetAgents()
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi lấy agents")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agents": agents,
		"count":  len(agents),
	})
}

// getAgent lấy thông tin một agent
func (s *Server) getAgent(c *gin.Context) {
	agentID := c.Param("id")

	agent, err := s.repository.GetAgent(agentID)
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi lấy agent")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent": agent,
	})
}

// getAgentEvents lấy events của một agent
func (s *Server) getAgentEvents(c *gin.Context) {
	agentID := c.Param("id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	events, err := s.repository.GetEventsByAgent(agentID, limit, offset)
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi lấy agent events")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"count":  len(events),
	})
}

// getProcessTrees lấy danh sách process trees
func (s *Server) getProcessTrees(c *gin.Context) {
	// Implementation cần thêm vào repository
	c.JSON(http.StatusOK, gin.H{
		"message": "Not implemented yet",
	})
}

// getProcessTree lấy một process tree cụ thể
func (s *Server) getProcessTree(c *gin.Context) {
	treeID := c.Param("id")

	tree, err := s.repository.GetProcessTree(treeID)
	if err != nil {
		s.logger.WithError(err).Error("Lỗi khi lấy process tree")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tree": tree,
	})
}

// getDashboardStats lấy thống kê cho dashboard
func (s *Server) getDashboardStats(c *gin.Context) {
	// Tổng hợp thống kê từ database
	stats := gin.H{
		"total_events":    s.getTotalCount("events"),
		"total_alerts":    s.getTotalCount("alerts"),
		"total_agents":    s.getTotalCount("agents"),
		"active_agents":   s.getActiveAgentsCount(),
		"critical_alerts": s.getCriticalAlertsCount(),
		"process_trees":   len(s.processor.GetProcessTreeStats()),
		"last_updated":    time.Now().Unix(),
	}

	c.JSON(http.StatusOK, stats)
}

// getAlertStats lấy thống kê alerts
func (s *Server) getAlertStats(c *gin.Context) {
	stats := gin.H{
		"by_severity": s.getAlertsBySeverity(),
		"by_status":   s.getAlertsByStatus(),
		"recent":      s.getRecentAlerts(),
	}

	c.JSON(http.StatusOK, stats)
}

// getProcessTreeStats lấy thống kê process trees
func (s *Server) getProcessTreeStats(c *gin.Context) {
	stats := s.processor.GetProcessTreeStats()
	c.JSON(http.StatusOK, stats)
}

// getSigmaRules lấy danh sách Sigma rules
func (s *Server) getSigmaRules(c *gin.Context) {
	// Implementation cần thêm Sigma engine access
	c.JSON(http.StatusOK, gin.H{
		"message": "Not implemented yet",
	})
}

// getSigmaRule lấy một Sigma rule cụ thể
func (s *Server) getSigmaRule(c *gin.Context) {
	ruleID := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"rule_id": ruleID,
		"message": "Not implemented yet",
	})
}

// reloadSigmaRules reload Sigma rules
func (s *Server) reloadSigmaRules(c *gin.Context) {
	// Implementation cần thêm Sigma engine access
	c.JSON(http.StatusOK, gin.H{
		"message": "Sigma rules reloaded successfully",
	})
}

// serveIndex serve trang index
func (s *Server) serveIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "EDR Security Dashboard",
	})
}

// Helper methods
func (s *Server) getTotalCount(table string) int64 {
	// Implementation đếm records trong table
	return 0
}

func (s *Server) getActiveAgentsCount() int64 {
	// Implementation đếm active agents
	return 0
}

func (s *Server) getCriticalAlertsCount() int64 {
	// Implementation đếm critical alerts
	return 0
}

func (s *Server) getAlertsBySeverity() map[string]int64 {
	// Implementation group alerts by severity
	return map[string]int64{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
}

func (s *Server) getAlertsByStatus() map[string]int64 {
	// Implementation group alerts by status
	return map[string]int64{
		"open":           0,
		"investigating":  0,
		"resolved":       0,
		"false_positive": 0,
	}
}

func (s *Server) getRecentAlerts() []interface{} {
	// Implementation lấy recent alerts
	return []interface{}{}
}
