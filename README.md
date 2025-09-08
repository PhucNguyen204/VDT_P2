# EDR Security System

Hệ thống EDR (Endpoint Detection and Response) được xây dựng với Golang, sử dụng Sigma rules để detect các hành vi nguy hiểm từ logs endpoint agents (Vector.dev).

## Tính năng chính

- **Sigma Rule Engine**: Engine detect sử dụng Sigma rules (inspired từ Sigma Engine)
- **Real-time Event Processing**: Xử lý events real-time từ Vector.dev agents
- **Process Tree Analysis**: Phân tích và visualize process trees
- **Alert Management**: Quản lý cảnh báo với nhiều mức độ nghiêm trọng
- **Web Dashboard**: UI/UX hiện đại giống Wazuh
- **Response Automation**: Tự động response với các threats

## Kiến trúc hệ thống

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Endpoints     │───▶│   Vector.dev    │───▶│   EDR Server    │
│  (Windows/Linux)│    │    Agents       │    │   (Golang)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                               ┌───────▼───────┐
                                               │   Database    │
                                               │ (PostgreSQL)  │
                                               └───────────────┘
```

## Cài đặt

### Prerequisites

- Go 1.21+
- PostgreSQL 13+
- Redis (optional, cho caching)

### 1. Clone repository

```bash
git clone <repository-url>
cd edr-server
```

### 2. Install dependencies

```bash
go mod download
```

### 3. Setup database

```sql
CREATE DATABASE edr_db;
CREATE USER edr_user WITH PASSWORD 'edr_password';
GRANT ALL PRIVILEGES ON DATABASE edr_db TO edr_user;
```

### 4. Configuration

Chỉnh sửa file `config/config.yaml`:

```yaml
server:
  port: 8080
  debug: true

database:
  host: localhost
  port: 5432
  username: edr_user
  password: edr_password
  database: edr_db
  ssl_mode: disable

sigma:
  rules_path: "rules/"
  reload_interval: 300s
  max_rules: 1000

detection:
  process_tree_depth: 10
  alert_threshold: 5
  processing_workers: 4
  retention_days: 30
```

### 5. Run server

```bash
go run cmd/main.go
```

Server sẽ chạy trên `http://localhost:8080`

## Sigma Rules

Hệ thống sử dụng Sigma rules để detect threats. Rules được lưu trong thư mục `rules/`.

### Ví dụ Sigma rule:

```yaml
title: Suspicious PowerShell Activity
id: 4f5b4a8b-2c3d-4e5f-6789-0123456789ab
description: Detects suspicious PowerShell command execution
author: EDR Security Team
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ProcessName|contains: 'powershell.exe'
        CommandLine|contains:
            - 'IEX'
            - 'downloadstring'
            - '-EncodedCommand'
    condition: selection
```

## Vector.dev Configuration

Cấu hình Vector.dev agent để gửi logs tới EDR server:

```toml
[sources.windows_events]
type = "windows_eventlogs"
channels = ["Security", "System", "Application"]

[sources.sysmon]
type = "windows_eventlogs"
channels = ["Microsoft-Windows-Sysmon/Operational"]

[transforms.enrich]
type = "remap"
inputs = ["windows_events", "sysmon"]
source = '''
.host = get_hostname!()
.agent_id = .host
'''

[sinks.edr_server]
type = "http"
inputs = ["enrich"]
uri = "http://edr-server:8080/api/v1/events"
method = "post"
encoding.codec = "json"
```

## API Endpoints

### Events
- `POST /api/v1/events` - Nhận events từ Vector.dev
- `GET /api/v1/events` - Lấy danh sách events
- `GET /api/v1/events/:id` - Lấy chi tiết event

### Alerts
- `GET /api/v1/alerts` - Lấy danh sách alerts
- `GET /api/v1/alerts/:id` - Lấy chi tiết alert
- `PUT /api/v1/alerts/:id/status` - Cập nhật trạng thái alert

### Agents
- `GET /api/v1/agents` - Lấy danh sách agents
- `GET /api/v1/agents/:id` - Lấy thông tin agent
- `GET /api/v1/agents/:id/events` - Lấy events của agent

### Process Trees
- `GET /api/v1/process-trees` - Lấy danh sách process trees
- `GET /api/v1/process-trees/:id` - Lấy chi tiết process tree

### Sigma Rules
- `GET /api/v1/rules` - Lấy danh sách rules
- `GET /api/v1/rules/:id` - Lấy chi tiết rule
- `POST /api/v1/rules/reload` - Reload rules

### Statistics
- `GET /api/v1/stats/dashboard` - Thống kê tổng quan
- `GET /api/v1/stats/alerts` - Thống kê alerts
- `GET /api/v1/stats/process-trees` - Thống kê process trees

## Web Dashboard

Dashboard cung cấp interface để:

- Xem tổng quan hệ thống
- Quản lý alerts
- Phân tích events
- Monitor agents
- Visualize process trees
- Quản lý Sigma rules

Truy cập dashboard tại: `http://localhost:8080`

## Deployment

### Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o edr-server cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/edr-server .
COPY --from=builder /app/config ./config
COPY --from=builder /app/rules ./rules
COPY --from=builder /app/web ./web
CMD ["./edr-server"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  edr-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DB_HOST=postgres
      - DB_USER=edr_user
      - DB_PASSWORD=edr_password
      - DB_NAME=edr_db
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:13
    environment:
      - POSTGRES_USER=edr_user
      - POSTGRES_PASSWORD=edr_password
      - POSTGRES_DB=edr_db
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    
volumes:
  postgres_data:
```

## Detection Capabilities

### MITRE ATT&CK Coverage

Hệ thống detect các techniques sau:

- **T1059.001**: PowerShell execution
- **T1003**: Credential dumping (Mimikatz)
- **T1021.002**: Lateral movement (PsExec)
- **T1068**: Privilege escalation
- **T1055**: Process injection

### Process Tree Analysis

- Detect suspicious process trees
- Analyze parent-child relationships
- Identify process spawning anomalies
- Track process execution chains

### Behavioral Detection

- Unusual network connections
- Suspicious file modifications
- Registry changes
- Service installations

## Development

### Project Structure

```
edr-server/
├── cmd/
│   └── main.go              # Entry point
├── internal/
│   ├── api/                 # REST API handlers
│   ├── config/              # Configuration management
│   ├── database/            # Database layer
│   ├── detector/            # Detection engine
│   ├── models/              # Data models
│   ├── processor/           # Event processing
│   └── sigma/               # Sigma rule engine
├── rules/                   # Sigma rules
├── web/                     # Frontend assets
│   ├── static/
│   └── templates/
├── config/
│   └── config.yaml          # Configuration file
├── go.mod
└── README.md
```

### Adding New Sigma Rules

1. Tạo file `.yml` mới trong thư mục `rules/`
2. Restart server hoặc call API `/api/v1/rules/reload`
3. Rules sẽ được load và sẵn sàng detect

### Contributing

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

MIT License - xem file LICENSE để biết thêm chi tiết.

## Support

Để được hỗ trợ, vui lòng tạo issue trên GitHub repository.
