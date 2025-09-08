package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"edr-server/internal/api"
	"edr-server/internal/config"
	"edr-server/internal/database"
	"edr-server/internal/processor"

	"github.com/sirupsen/logrus"
)

func main() {
	// Khởi tạo logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load cấu hình
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		logger.Fatalf("Không thể load cấu hình: %v", err)
	}

	// Khởi tạo database
	db, err := database.InitDB(cfg.Database)
	if err != nil {
		logger.Fatalf("Không thể kết nối database: %v", err)
	}

	// Khởi tạo processor với integrated SIGMA Engine
	processor, err := processor.New(db, logger)
	if err != nil {
		logger.Fatalf("Không thể khởi tạo Processor với SIGMA Engine: %v", err)
	}

	// Khởi tạo API server
	apiServer := api.NewServer(cfg, db, processor, logger)

	// Chạy server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: apiServer.Router(),
	}

	go func() {
		logger.Infof("EDR Server đang chạy trên port %d", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server không thể khởi động: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Đang tắt server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server buộc phải tắt:", err)
	}

	logger.Info("Server đã tắt")
}
