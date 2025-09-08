# Setup Database Script for Windows
# This script sets up PostgreSQL database for EDR server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "EDR Server Database Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Function to check if PostgreSQL is installed
function Test-PostgreSQL {
    try {
        $null = Get-Command psql -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# Function to check if PostgreSQL service is running
function Test-PostgreSQLService {
    $service = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
    return ($service -and $service.Status -eq "Running")
}

# Check if PostgreSQL is installed
if (-not (Test-PostgreSQL)) {
    Write-Host "PostgreSQL không được tìm thấy!" -ForegroundColor Red
    Write-Host "Bạn có thể cài đặt PostgreSQL bằng các cách sau:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Download từ: https://www.postgresql.org/download/windows/" -ForegroundColor Green
    Write-Host "2. Sử dụng Chocolatey: choco install postgresql" -ForegroundColor Green
    Write-Host "3. Sử dụng Scoop: scoop install postgresql" -ForegroundColor Green
    Write-Host "4. Sử dụng winget: winget install PostgreSQL.PostgreSQL" -ForegroundColor Green
    Write-Host ""
    Read-Host "Nhấn Enter để tiếp tục sau khi cài đặt PostgreSQL"
}

# Check if PostgreSQL service is running
if (-not (Test-PostgreSQLService)) {
    Write-Host "PostgreSQL service không chạy. Đang cố gắng khởi động..." -ForegroundColor Yellow
    try {
        Start-Service -Name "postgresql*" -ErrorAction Stop
        Write-Host "PostgreSQL service đã được khởi động!" -ForegroundColor Green
    }
    catch {
        Write-Host "Không thể khởi động PostgreSQL service. Vui lòng khởi động thủ công." -ForegroundColor Red
        Write-Host "Hoặc khởi động từ Services.msc" -ForegroundColor Yellow
        exit 1
    }
}

# Database configuration
$DB_HOST = "localhost"
$DB_PORT = "5432"
$DB_NAME = "edr_db"
$DB_USER = "edr_user"
$DB_PASSWORD = "edr_password"
$POSTGRES_USER = "postgres"

Write-Host "Đang tạo database và user..." -ForegroundColor Yellow

# Create database and user
$createDbScript = @"
-- Create user
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';

-- Create database
CREATE DATABASE $DB_NAME OWNER $DB_USER;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
GRANT CONNECT ON DATABASE $DB_NAME TO $DB_USER;

-- Additional permissions
ALTER USER $DB_USER CREATEDB;
"@

# Save script to temp file
$tempScript = [System.IO.Path]::GetTempFileName() + ".sql"
$createDbScript | Out-File -FilePath $tempScript -Encoding UTF8

try {
    # Execute the script
    Write-Host "Kết nối tới PostgreSQL để tạo database..." -ForegroundColor Yellow
    
    # Prompt for postgres password if needed
    Write-Host "Nhập password cho user postgres (mặc định thường là postgres password bạn đã set khi cài đặt):"
    $env:PGPASSWORD = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText
    
    # Execute the script
    psql -h $DB_HOST -p $DB_PORT -U $POSTGRES_USER -c "\i $tempScript"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Database đã được tạo thành công!" -ForegroundColor Green
    } else {
        Write-Host "Có lỗi khi tạo database. Thử cách thủ công:" -ForegroundColor Red
        Write-Host "1. Mở pgAdmin hoặc psql" -ForegroundColor Yellow
        Write-Host "2. Chạy các lệnh SQL sau:" -ForegroundColor Yellow
        Write-Host $createDbScript -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Lỗi khi thực thi script: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Vui lòng tạo database thủ công:" -ForegroundColor Yellow
    Write-Host $createDbScript -ForegroundColor Cyan
}
finally {
    # Clean up
    if (Test-Path $tempScript) {
        Remove-Item $tempScript
    }
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
}

# Test connection
Write-Host "Đang test kết nối database..." -ForegroundColor Yellow

$env:PGPASSWORD = $DB_PASSWORD
try {
    $testResult = psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "SELECT version();" -t
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Kết nối database thành công!" -ForegroundColor Green
        Write-Host "PostgreSQL Version: $($testResult.Trim())" -ForegroundColor Cyan
    } else {
        Write-Host "Không thể kết nối database. Kiểm tra lại cấu hình." -ForegroundColor Red
    }
}
catch {
    Write-Host "Lỗi test connection: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Database Setup Hoàn tất!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Connection String:" -ForegroundColor Green
Write-Host "host=$DB_HOST port=$DB_PORT user=$DB_USER password=$DB_PASSWORD dbname=$DB_NAME sslmode=disable" -ForegroundColor Cyan
Write-Host ""
Write-Host "Bây giờ bạn có thể chạy EDR server:" -ForegroundColor Green
Write-Host "go run cmd/main.go" -ForegroundColor Cyan

