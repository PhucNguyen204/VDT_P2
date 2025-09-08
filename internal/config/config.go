package config

import (
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config chứa toàn bộ cấu hình của hệ thống EDR
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	Redis     RedisConfig     `yaml:"redis"`
	Sigma     SigmaConfig     `yaml:"sigma"`
	Detection DetectionConfig `yaml:"detection"`
}

type ServerConfig struct {
	Port           int   `yaml:"port"`
	Debug          bool  `yaml:"debug"`
	MaxRequestSize int64 `yaml:"max_request_size"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"ssl_mode"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	Database int    `yaml:"database"`
}

type SigmaConfig struct {
	RulesPath      string        `yaml:"rules_path"`
	ReloadInterval time.Duration `yaml:"reload_interval"`
	MaxRules       int           `yaml:"max_rules"`
}

type DetectionConfig struct {
	ProcessTreeDepth  int `yaml:"process_tree_depth"`
	AlertThreshold    int `yaml:"alert_threshold"`
	ProcessingWorkers int `yaml:"processing_workers"`
	RetentionDays     int `yaml:"retention_days"`
}

// Load đọc cấu hình từ file YAML
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set default values
	if config.Server.Port == 0 {
		config.Server.Port = 8080
	}
	if config.Server.MaxRequestSize == 0 {
		config.Server.MaxRequestSize = 10 << 20 // 10MB
	}
	if config.Database.SSLMode == "" {
		config.Database.SSLMode = "disable"
	}
	if config.Sigma.ReloadInterval == 0 {
		config.Sigma.ReloadInterval = 5 * time.Minute
	}
	if config.Sigma.MaxRules == 0 {
		config.Sigma.MaxRules = 1000
	}
	if config.Detection.ProcessTreeDepth == 0 {
		config.Detection.ProcessTreeDepth = 10
	}
	if config.Detection.AlertThreshold == 0 {
		config.Detection.AlertThreshold = 5
	}
	if config.Detection.ProcessingWorkers == 0 {
		config.Detection.ProcessingWorkers = 4
	}
	if config.Detection.RetentionDays == 0 {
		config.Detection.RetentionDays = 30
	}

	// Override với environment variables nếu có
	overrideWithEnv(&config)

	return &config, nil
}

// overrideWithEnv override config với environment variables
func overrideWithEnv(config *Config) {
	if host := os.Getenv("DB_HOST"); host != "" {
		config.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.Database.Port = p
		}
	}
	if user := os.Getenv("DB_USER"); user != "" {
		config.Database.Username = user
	}
	if password := os.Getenv("DB_PASSWORD"); password != "" {
		config.Database.Password = password
	}
	if dbname := os.Getenv("DB_NAME"); dbname != "" {
		config.Database.Database = dbname
	}

	if redisHost := os.Getenv("REDIS_HOST"); redisHost != "" {
		config.Redis.Host = redisHost
	}
	if redisPort := os.Getenv("REDIS_PORT"); redisPort != "" {
		if p, err := strconv.Atoi(redisPort); err == nil {
			config.Redis.Port = p
		}
	}
}
