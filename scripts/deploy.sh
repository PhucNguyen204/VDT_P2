#!/bin/bash

# EDR Server Deployment Script
# This script automates the deployment process for the EDR server

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/your-org/edr-server.git"
APP_NAME="edr-server"
DEPLOY_DIR="/opt/edr-server"
SERVICE_NAME="edr-server"
BACKUP_DIR="/opt/edr-server/backups"
CONFIG_FILE="config/config.yaml"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("git" "go" "docker" "docker-compose" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' is not installed"
            exit 1
        fi
    done
    
    log_success "Prerequisites check passed"
}

backup_current_deployment() {
    if [[ -d "$DEPLOY_DIR" ]]; then
        log_info "Creating backup of current deployment..."
        
        local backup_name="backup-$(date +%Y%m%d-%H%M%S)"
        local backup_path="$BACKUP_DIR/$backup_name"
        
        mkdir -p "$BACKUP_DIR"
        cp -r "$DEPLOY_DIR" "$backup_path"
        
        log_success "Backup created at $backup_path"
        
        # Keep only last 5 backups
        ls -t "$BACKUP_DIR" | tail -n +6 | xargs -r rm -rf
    fi
}

stop_services() {
    log_info "Stopping services..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        log_success "Stopped $SERVICE_NAME service"
    fi
    
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose down
        log_success "Stopped Docker services"
    fi
}

deploy_application() {
    log_info "Deploying application..."
    
    # Create deploy directory
    mkdir -p "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"
    
    # Clone or update repository
    if [[ -d ".git" ]]; then
        log_info "Updating existing repository..."
        git fetch origin
        git reset --hard origin/main
    else
        log_info "Cloning repository..."
        git clone "$REPO_URL" .
    fi
    
    # Build application
    log_info "Building application..."
    go mod download
    go build -o bin/$APP_NAME cmd/main.go
    
    # Set permissions
    chmod +x bin/$APP_NAME
    
    log_success "Application built successfully"
}

setup_database() {
    log_info "Setting up database..."
    
    # Start PostgreSQL if using Docker
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose up -d postgres
        
        # Wait for PostgreSQL to be ready
        log_info "Waiting for PostgreSQL to be ready..."
        sleep 10
        
        # Run database initialization
        docker-compose exec -T postgres psql -U edr_user -d edr_db -f /docker-entrypoint-initdb.d/init-db.sql || true
    fi
    
    log_success "Database setup completed"
}

setup_systemd_service() {
    log_info "Setting up systemd service..."
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=EDR Security Server
After=network.target
Wants=postgresql.service
After=postgresql.service

[Service]
Type=simple
User=edr
Group=edr
WorkingDirectory=$DEPLOY_DIR
ExecStart=$DEPLOY_DIR/bin/$APP_NAME
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME
KillMode=mixed
KillSignal=SIGTERM

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DEPLOY_DIR/logs
ReadWritePaths=/var/log/edr

# Environment
Environment=GIN_MODE=release
EnvironmentFile=-$DEPLOY_DIR/.env

[Install]
WantedBy=multi-user.target
EOF

    # Create edr user if it doesn't exist
    if ! id "edr" &>/dev/null; then
        useradd -r -s /bin/false edr
        log_success "Created edr user"
    fi
    
    # Set ownership
    chown -R edr:edr "$DEPLOY_DIR"
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    log_success "Systemd service configured"
}

setup_nginx() {
    log_info "Setting up Nginx reverse proxy..."
    
    # Check if Nginx is installed
    if command -v nginx &> /dev/null; then
        cat > /etc/nginx/sites-available/edr-server << EOF
server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /static/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files \$uri =404;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://127.0.0.1:8080;
    }
}
EOF
        
        # Enable site
        ln -sf /etc/nginx/sites-available/edr-server /etc/nginx/sites-enabled/
        
        # Test configuration
        nginx -t
        systemctl reload nginx
        
        log_success "Nginx configured"
    else
        log_warning "Nginx not installed, skipping reverse proxy setup"
    fi
}

setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Create log directory
    mkdir -p /var/log/edr
    chown edr:edr /var/log/edr
    
    # Setup logrotate
    cat > /etc/logrotate.d/edr-server << EOF
/var/log/edr/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 edr edr
    postrotate
        systemctl reload $SERVICE_NAME
    endscript
}
EOF
    
    log_success "Monitoring setup completed"
}

start_services() {
    log_info "Starting services..."
    
    # Start application
    systemctl start "$SERVICE_NAME"
    
    # Start Docker services if needed
    if [[ -f "docker-compose.yml" ]]; then
        docker-compose up -d
    fi
    
    log_success "Services started"
}

verify_deployment() {
    log_info "Verifying deployment..."
    
    # Wait a moment for services to start
    sleep 5
    
    # Check service status
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "$SERVICE_NAME is running"
    else
        log_error "$SERVICE_NAME is not running"
        return 1
    fi
    
    # Check health endpoint
    if curl -f -s http://localhost:8080/health > /dev/null; then
        log_success "Health check passed"
    else
        log_error "Health check failed"
        return 1
    fi
    
    # Show status
    systemctl status "$SERVICE_NAME" --no-pager
    
    log_success "Deployment verification completed"
}

show_deployment_info() {
    echo
    log_success "Deployment completed successfully!"
    echo
    echo "Application Information:"
    echo "  Service: $SERVICE_NAME"
    echo "  Directory: $DEPLOY_DIR"
    echo "  URL: http://localhost:8080"
    echo "  Logs: journalctl -u $SERVICE_NAME -f"
    echo
    echo "Management Commands:"
    echo "  Start:   systemctl start $SERVICE_NAME"
    echo "  Stop:    systemctl stop $SERVICE_NAME"
    echo "  Restart: systemctl restart $SERVICE_NAME"
    echo "  Status:  systemctl status $SERVICE_NAME"
    echo "  Logs:    journalctl -u $SERVICE_NAME -f"
    echo
}

# Main deployment process
main() {
    echo "Starting EDR Server Deployment"
    echo "==============================="
    
    check_prerequisites
    backup_current_deployment
    stop_services
    deploy_application
    setup_database
    setup_systemd_service
    setup_nginx
    setup_monitoring
    start_services
    verify_deployment
    show_deployment_info
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "backup")
        backup_current_deployment
        ;;
    "stop")
        stop_services
        ;;
    "start")
        start_services
        ;;
    "restart")
        stop_services
        start_services
        ;;
    "status")
        systemctl status "$SERVICE_NAME"
        ;;
    "logs")
        journalctl -u "$SERVICE_NAME" -f
        ;;
    "update")
        backup_current_deployment
        stop_services
        deploy_application
        start_services
        verify_deployment
        ;;
    *)
        echo "Usage: $0 {deploy|backup|stop|start|restart|status|logs|update}"
        echo
        echo "Commands:"
        echo "  deploy  - Full deployment (default)"
        echo "  backup  - Create backup only"
        echo "  stop    - Stop services"
        echo "  start   - Start services"
        echo "  restart - Restart services"
        echo "  status  - Show service status"
        echo "  logs    - Show service logs"
        echo "  update  - Update application only"
        exit 1
        ;;
esac
