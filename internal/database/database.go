package database

import (
	"fmt"
	"time"

	"edr-server/internal/config"
	"edr-server/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitDB khởi tạo kết nối database và tự động migrate
func InitDB(cfg config.DatabaseConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=Asia/Ho_Chi_Minh",
		cfg.Host, cfg.Username, cfg.Password, cfg.Database, cfg.Port, cfg.SSLMode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("không thể kết nối database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Cấu hình connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto migrate
	err = db.AutoMigrate(
		&models.Agent{},
		&models.Event{},
		&models.Alert{},
		&models.Process{},
		&models.ProcessTree{},
		&models.SigmaRule{},
		&models.Detection{},
	)
	if err != nil {
		return nil, fmt.Errorf("không thể migrate database: %w", err)
	}

	return db, nil
}

// Repository chứa các phương thức truy vấn database
type Repository struct {
	db *gorm.DB
}

// NewRepository tạo repository mới
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// Events
func (r *Repository) CreateEvent(event *models.Event) error {
	return r.db.Create(event).Error
}

func (r *Repository) GetEvents(limit, offset int) ([]models.Event, error) {
	var events []models.Event
	err := r.db.Limit(limit).Offset(offset).Order("created_at desc").Find(&events).Error
	return events, err
}

func (r *Repository) GetEventsByAgent(agentID string, limit, offset int) ([]models.Event, error) {
	var events []models.Event
	err := r.db.Where("agent_id = ?", agentID).Limit(limit).Offset(offset).Order("created_at desc").Find(&events).Error
	return events, err
}

// Alerts
func (r *Repository) CreateAlert(alert *models.Alert) error {
	return r.db.Create(alert).Error
}

func (r *Repository) GetAlerts(limit, offset int) ([]models.Alert, error) {
	var alerts []models.Alert
	err := r.db.Preload("Events").Limit(limit).Offset(offset).Order("created_at desc").Find(&alerts).Error
	return alerts, err
}

func (r *Repository) UpdateAlertStatus(alertID string, status string) error {
	return r.db.Model(&models.Alert{}).Where("id = ?", alertID).Update("status", status).Error
}

// Process Trees
func (r *Repository) CreateProcessTree(tree *models.ProcessTree) error {
	return r.db.Create(tree).Error
}

func (r *Repository) GetProcessTree(processID string) (*models.ProcessTree, error) {
	var tree models.ProcessTree
	err := r.db.Preload("Processes").Where("root_process_id = ?", processID).First(&tree).Error
	return &tree, err
}

// Agents
func (r *Repository) CreateAgent(agent *models.Agent) error {
	return r.db.Create(agent).Error
}

func (r *Repository) CreateOrUpdateAgent(agent *models.Agent) error {
	return r.db.Save(agent).Error
}

func (r *Repository) GetAgents() ([]models.Agent, error) {
	var agents []models.Agent
	err := r.db.Find(&agents).Error
	return agents, err
}

func (r *Repository) GetAgent(agentID string) (*models.Agent, error) {
	var agent models.Agent
	err := r.db.Where("id = ?", agentID).First(&agent).Error
	return &agent, err
}

// UpdateAgentStatus cập nhật status và last_seen của agent
func (r *Repository) UpdateAgentStatus(agentID string, status string, lastSeen time.Time) error {
	return r.db.Model(&models.Agent{}).Where("id = ?", agentID).Updates(map[string]interface{}{
		"status":    status,
		"last_seen": lastSeen,
	}).Error
}
