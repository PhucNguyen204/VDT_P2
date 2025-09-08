# EDR Server Makefile

.PHONY: help build run test clean docker docker-up docker-down deps fmt lint vet

# Variables
APP_NAME := edr-server
GO_VERSION := 1.21
DOCKER_IMAGE := edr-server:latest
COMPOSE_FILE := docker-compose.yml

# Help target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development targets
deps: ## Install Go dependencies
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

fmt: ## Format Go code
	@echo "Formatting code..."
	go fmt ./...

lint: ## Run golangci-lint
	@echo "Running linter..."
	golangci-lint run ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Build targets
build: deps fmt ## Build the application
	@echo "Building $(APP_NAME)..."
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/$(APP_NAME) cmd/main.go

build-windows: deps fmt ## Build for Windows
	@echo "Building $(APP_NAME) for Windows..."
	GOOS=windows GOARCH=amd64 go build -o bin/$(APP_NAME).exe cmd/main.go

build-macos: deps fmt ## Build for macOS
	@echo "Building $(APP_NAME) for macOS..."
	GOOS=darwin GOARCH=amd64 go build -o bin/$(APP_NAME)-macos cmd/main.go

# Run targets
run: ## Run the application locally
	@echo "Running $(APP_NAME)..."
	go run cmd/main.go

run-dev: ## Run with live reload (requires air)
	@echo "Running $(APP_NAME) with live reload..."
	air

# Database targets
db-setup: ## Setup local database
	@echo "Setting up database..."
	createdb edr_db || true
	psql -d edr_db -f scripts/init-db.sql

db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	go run cmd/main.go --migrate

db-seed: ## Seed database with sample data
	@echo "Seeding database..."
	go run scripts/seed.go

# Docker targets
docker: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

docker-push: docker ## Push Docker image
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE)

docker-up: ## Start Docker Compose services
	@echo "Starting Docker Compose services..."
	docker-compose -f $(COMPOSE_FILE) up -d

docker-down: ## Stop Docker Compose services
	@echo "Stopping Docker Compose services..."
	docker-compose -f $(COMPOSE_FILE) down

docker-logs: ## Show Docker Compose logs
	@echo "Showing Docker Compose logs..."
	docker-compose -f $(COMPOSE_FILE) logs -f

docker-clean: ## Clean Docker images and containers
	@echo "Cleaning Docker images and containers..."
	docker-compose -f $(COMPOSE_FILE) down -v
	docker system prune -f
	docker rmi $(DOCKER_IMAGE) || true

# Deployment targets
deploy-dev: ## Deploy to development environment
	@echo "Deploying to development..."
	docker-compose -f $(COMPOSE_FILE) up -d --build

deploy-prod: ## Deploy to production
	@echo "Deploying to production..."
	docker-compose -f docker-compose.prod.yml up -d --build

# Security targets
security-scan: ## Run security scan
	@echo "Running security scan..."
	gosec ./...

vulnerability-check: ## Check for vulnerabilities
	@echo "Checking for vulnerabilities..."
	go list -json -deps ./... | nancy sleuth

# Monitoring targets
metrics: ## Show application metrics
	@echo "Application metrics available at http://localhost:8080/metrics"
	curl -s http://localhost:8080/metrics | head -20

health: ## Check application health
	@echo "Checking application health..."
	curl -s http://localhost:8080/health | jq .

# Rules management
rules-validate: ## Validate Sigma rules
	@echo "Validating Sigma rules..."
	find rules/ -name "*.yml" -exec yamllint {} \;

rules-reload: ## Reload Sigma rules
	@echo "Reloading Sigma rules..."
	curl -X POST http://localhost:8080/api/v1/rules/reload

# Testing targets
test-integration: ## Run integration tests
	@echo "Running integration tests..."
	go test -tags=integration -v ./tests/integration/...

test-load: ## Run load tests
	@echo "Running load tests..."
	go run tests/load/main.go

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Documentation targets
docs: ## Generate documentation
	@echo "Generating documentation..."
	go doc -all ./... > docs/api.md
	swagger generate spec -o docs/swagger.json

docs-serve: ## Serve documentation
	@echo "Serving documentation at http://localhost:6060"
	godoc -http=:6060

# Maintenance targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf coverage.out coverage.html
	rm -rf dist/
	go clean -cache
	go clean -modcache

update-deps: ## Update all dependencies
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Release targets
version: ## Show current version
	@echo "Current version: $(shell git describe --tags --always)"

release: test lint build ## Create a release
	@echo "Creating release..."
	goreleaser release --rm-dist

# CI/CD targets
ci: deps fmt lint vet test ## Run CI pipeline
	@echo "CI pipeline completed successfully"

setup-git-hooks: ## Setup Git hooks
	@echo "Setting up Git hooks..."
	cp scripts/hooks/pre-commit .git/hooks/
	chmod +x .git/hooks/pre-commit

# Installation targets
install: build ## Install the application
	@echo "Installing $(APP_NAME)..."
	sudo cp bin/$(APP_NAME) /usr/local/bin/

uninstall: ## Uninstall the application
	@echo "Uninstalling $(APP_NAME)..."
	sudo rm -f /usr/local/bin/$(APP_NAME)

# Default target
all: ci docker ## Run all checks and build

.DEFAULT_GOAL := help
