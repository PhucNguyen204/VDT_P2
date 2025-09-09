FROM ubuntu:22.04

# Set timezone to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Ho_Chi_Minh

# Install attack tools and dependencies
RUN apt-get update && \
    apt-get install -y \
    hydra \
    openssh-client \
    netcat-openbsd \
    curl \
    wget \
    sshpass \
    nmap \
    iputils-ping \
    dnsutils \
    telnet \
    ftp \
    python3 \
    python3-pip \
    vim \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /usr/share/wordlists /var/log

# Copy attack scripts and wordlists
COPY attack_scripts.sh /usr/local/bin/attack_scripts.sh
COPY brute_force_attack.sh /usr/local/bin/brute_force_attack.sh
COPY passwords.txt /usr/share/wordlists/passwords.txt

# Make scripts executable
RUN chmod +x /usr/local/bin/attack_scripts.sh
RUN chmod +x /usr/local/bin/brute_force_attack.sh

# Set working directory
WORKDIR /root

# Default command - run brute force attack
CMD ["/bin/bash", "/usr/local/bin/brute_force_attack.sh"]