// EDR Dashboard JavaScript

class EDRDashboard {
    constructor() {
        this.apiBase = '/api/v1';
        this.refreshInterval = 30000; // 30 seconds
        this.charts = {};
        this.currentSection = 'dashboard';
        
        this.init();
    }

    init() {
        this.setupNavigation();
        this.loadDashboard();
        this.startAutoRefresh();
        this.setupEventListeners();
    }

    // Navigation
    setupNavigation() {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.getAttribute('href').substring(1);
                this.showSection(section);
            });
        });
    }

    showSection(section) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(el => {
            el.style.display = 'none';
        });

        // Show selected section
        const targetSection = document.getElementById(section);
        if (targetSection) {
            targetSection.style.display = 'block';
            this.currentSection = section;
        }

        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[href="#${section}"]`).classList.add('active');

        // Load section data
        this.loadSectionData(section);
    }

    loadSectionData(section) {
        switch(section) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'alerts':
                this.loadAlerts();
                break;
            case 'events':
                this.loadEvents();
                break;
            case 'agents':
                this.loadAgents();
                break;
            case 'process-trees':
                this.loadProcessTrees();
                break;
            case 'rules':
                this.loadSigmaRules();
                break;
        }
    }

    // Dashboard
    async loadDashboard() {
        try {
            const stats = await this.apiCall('/stats/dashboard');
            this.updateDashboardStats(stats);
            
            const alertStats = await this.apiCall('/stats/alerts');
            this.updateAlertCharts(alertStats);
            
            await this.loadRecentAlerts();
        } catch (error) {
            console.error('Error loading dashboard:', error);
            this.showNotification('Lỗi khi tải dashboard', 'error');
        }
    }

    updateDashboardStats(stats) {
        document.getElementById('total-events').textContent = this.formatNumber(stats.total_events || 0);
        document.getElementById('critical-alerts').textContent = this.formatNumber(stats.critical_alerts || 0);
        document.getElementById('active-agents').textContent = this.formatNumber(stats.active_agents || 0);
        document.getElementById('process-trees-count').textContent = this.formatNumber(stats.process_trees || 0);
    }

    updateAlertCharts(alertStats) {
        // Alert Severity Chart
        const severityCtx = document.getElementById('alertSeverityChart').getContext('2d');
        if (this.charts.severity) {
            this.charts.severity.destroy();
        }
        
        this.charts.severity = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        alertStats.by_severity?.critical || 0,
                        alertStats.by_severity?.high || 0,
                        alertStats.by_severity?.medium || 0,
                        alertStats.by_severity?.low || 0
                    ],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#6c757d']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Events Time Chart (placeholder data)
        const timeCtx = document.getElementById('eventsTimeChart').getContext('2d');
        if (this.charts.eventsTime) {
            this.charts.eventsTime.destroy();
        }
        
        this.charts.eventsTime = new Chart(timeCtx, {
            type: 'line',
            data: {
                labels: this.getLast24Hours(),
                datasets: [{
                    label: 'Sự kiện',
                    data: this.generateTimeSeriesData(),
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    async loadRecentAlerts() {
        try {
            const alerts = await this.apiCall('/alerts?limit=10');
            this.updateRecentAlertsTable(alerts.alerts || []);
        } catch (error) {
            console.error('Error loading recent alerts:', error);
        }
    }

    updateRecentAlertsTable(alerts) {
        const tbody = document.querySelector('#recent-alerts-table tbody');
        tbody.innerHTML = '';

        alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.formatDateTime(alert.created_at)}</td>
                <td>${this.escapeHtml(alert.title)}</td>
                <td><span class="badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
                <td>${this.escapeHtml(alert.agent_id)}</td>
                <td><span class="badge status-${alert.status}">${this.getStatusText(alert.status)}</span></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="dashboard.viewAlert('${alert.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    // Alerts
    async loadAlerts() {
        try {
            const response = await this.apiCall('/alerts');
            this.updateAlertsTable(response.alerts || []);
        } catch (error) {
            console.error('Error loading alerts:', error);
            this.showNotification('Lỗi khi tải cảnh báo', 'error');
        }
    }

    updateAlertsTable(alerts) {
        const tbody = document.querySelector('#alerts-table tbody');
        tbody.innerHTML = '';

        alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.escapeHtml(alert.id.substring(0, 8))}</td>
                <td>${this.formatDateTime(alert.created_at)}</td>
                <td>${this.escapeHtml(alert.title)}</td>
                <td><span class="badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span></td>
                <td>${this.escapeHtml(alert.agent_id)}</td>
                <td>${this.escapeHtml(alert.rule_name)}</td>
                <td><span class="badge status-${alert.status}">${this.getStatusText(alert.status)}</span></td>
                <td class="action-buttons">
                    <button class="btn btn-sm btn-primary" onclick="dashboard.viewAlert('${alert.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-success" onclick="dashboard.updateAlertStatus('${alert.id}', 'resolved')">
                        <i class="fas fa-check"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    // Events
    async loadEvents() {
        try {
            const response = await this.apiCall('/events');
            this.updateEventsTable(response.events || []);
        } catch (error) {
            console.error('Error loading events:', error);
            this.showNotification('Lỗi khi tải sự kiện', 'error');
        }
    }

    updateEventsTable(events) {
        const tbody = document.querySelector('#events-table tbody');
        tbody.innerHTML = '';

        events.forEach(event => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.formatDateTime(event.timestamp)}</td>
                <td>
                    <i class="fas fa-${this.getEventTypeIcon(event.event_type)} event-type-${event.event_type}"></i>
                    ${event.event_type}
                </td>
                <td>${this.escapeHtml(event.agent_id)}</td>
                <td>${this.escapeHtml(event.process_name || 'N/A')}</td>
                <td class="text-truncate" style="max-width: 300px;" title="${this.escapeHtml(event.command_line || '')}">
                    ${this.escapeHtml(event.command_line || 'N/A')}
                </td>
                <td>${this.escapeHtml(event.user_name || 'N/A')}</td>
                <td><span class="badge bg-secondary">${event.severity}</span></td>
            `;
            tbody.appendChild(row);
        });
    }

    // Agents
    async loadAgents() {
        try {
            const response = await this.apiCall('/agents');
            this.updateAgentsTable(response.agents || []);
        } catch (error) {
            console.error('Error loading agents:', error);
            this.showNotification('Lỗi khi tải agents', 'error');
        }
    }

    updateAgentsTable(agents) {
        const tbody = document.querySelector('#agents-table tbody');
        tbody.innerHTML = '';

        agents.forEach(agent => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.escapeHtml(agent.id.substring(0, 8))}</td>
                <td>${this.escapeHtml(agent.hostname || 'N/A')}</td>
                <td>${this.escapeHtml(agent.ip_address || 'N/A')}</td>
                <td>${this.escapeHtml(agent.os || 'N/A')}</td>
                <td>${this.escapeHtml(agent.agent_version || 'N/A')}</td>
                <td>
                    <span class="agent-status">
                        <span class="agent-status-indicator agent-status-${agent.status}"></span>
                        ${this.getStatusText(agent.status)}
                    </span>
                </td>
                <td>${this.formatDateTime(agent.last_seen)}</td>
                <td class="action-buttons">
                    <button class="btn btn-sm btn-primary" onclick="dashboard.viewAgentEvents('${agent.id}')">
                        <i class="fas fa-list"></i> Events
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    // Process Trees
    async loadProcessTrees() {
        try {
            const stats = await this.apiCall('/stats/process-trees');
            this.renderProcessTreeVisualization(stats);
        } catch (error) {
            console.error('Error loading process trees:', error);
            this.showNotification('Lỗi khi tải process trees', 'error');
        }
    }

    renderProcessTreeVisualization(stats) {
        const container = document.getElementById('process-tree-graph');
        container.innerHTML = '';

        // Simple visualization placeholder
        const svg = d3.select('#process-tree-graph')
            .append('svg')
            .attr('width', '100%')
            .attr('height', '100%');

        // Add sample data
        const data = [
            {id: 'root', name: 'System', x: 400, y: 50},
            {id: 'winlogon', name: 'winlogon.exe', x: 200, y: 150},
            {id: 'explorer', name: 'explorer.exe', x: 600, y: 150},
            {id: 'cmd', name: 'cmd.exe', x: 100, y: 250},
            {id: 'powershell', name: 'powershell.exe', x: 300, y: 250}
        ];

        const links = [
            {source: 'root', target: 'winlogon'},
            {source: 'root', target: 'explorer'},
            {source: 'winlogon', target: 'cmd'},
            {source: 'explorer', target: 'powershell'}
        ];

        // Draw links
        svg.selectAll('.process-link')
            .data(links)
            .enter()
            .append('line')
            .attr('class', 'process-link')
            .attr('x1', d => data.find(n => n.id === d.source).x)
            .attr('y1', d => data.find(n => n.id === d.source).y)
            .attr('x2', d => data.find(n => n.id === d.target).x)
            .attr('y2', d => data.find(n => n.id === d.target).y);

        // Draw nodes
        const nodes = svg.selectAll('.process-node')
            .data(data)
            .enter()
            .append('g');

        nodes.append('circle')
            .attr('class', 'process-node')
            .attr('cx', d => d.x)
            .attr('cy', d => d.y)
            .attr('r', 20);

        nodes.append('text')
            .attr('class', 'process-label')
            .attr('x', d => d.x)
            .attr('y', d => d.y + 35)
            .text(d => d.name);
    }

    // Sigma Rules
    async loadSigmaRules() {
        try {
            const response = await this.apiCall('/rules');
            this.updateRulesTable(response.rules || []);
        } catch (error) {
            console.error('Error loading Sigma rules:', error);
            this.showNotification('Lỗi khi tải Sigma rules', 'error');
        }
    }

    updateRulesTable(rules) {
        const tbody = document.querySelector('#rules-table tbody');
        tbody.innerHTML = '';

        // Placeholder data since rules endpoint isn't fully implemented
        const sampleRules = [
            {
                id: '1',
                title: 'Suspicious PowerShell Activity',
                level: 'high',
                status: 'stable',
                author: 'EDR Security Team',
                tags: ['attack.execution', 'attack.t1059.001'],
                enabled: true
            },
            {
                id: '2',
                title: 'Mimikatz Credential Dumping Detection',
                level: 'critical',
                status: 'stable',
                author: 'EDR Security Team',
                tags: ['attack.credential_access', 'attack.t1003'],
                enabled: true
            }
        ];

        sampleRules.forEach(rule => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${this.escapeHtml(rule.id.substring(0, 8))}</td>
                <td>${this.escapeHtml(rule.title)}</td>
                <td><span class="badge severity-${rule.level}">${rule.level.toUpperCase()}</span></td>
                <td>${this.escapeHtml(rule.status)}</td>
                <td>${this.escapeHtml(rule.author)}</td>
                <td>
                    ${rule.tags.map(tag => `<span class="mitre-tag">${tag}</span>`).join('')}
                </td>
                <td>
                    <i class="fas fa-${rule.enabled ? 'check text-success' : 'times text-danger'} rule-${rule.enabled ? 'enabled' : 'disabled'}"></i>
                </td>
                <td class="action-buttons">
                    <button class="btn btn-sm btn-primary" onclick="dashboard.viewRule('${rule.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    // API Methods
    async apiCall(endpoint, options = {}) {
        const url = this.apiBase + endpoint;
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        };

        const response = await fetch(url, { ...defaultOptions, ...options });
        
        if (!response.ok) {
            throw new Error(`API call failed: ${response.statusText}`);
        }

        return await response.json();
    }

    // Event Handlers
    setupEventListeners() {
        // Search functionality
        document.getElementById('search-input')?.addEventListener('input', 
            this.debounce(() => this.handleSearch(), 300));

        // Filter functionality
        document.getElementById('severity-filter')?.addEventListener('change', () => this.handleFilter());
        document.getElementById('status-filter')?.addEventListener('change', () => this.handleFilter());

        // Real-time updates (WebSocket would be better)
        setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.loadDashboard();
            }
        }, this.refreshInterval);
    }

    handleSearch() {
        const query = document.getElementById('search-input').value;
        // Implement search logic
        console.log('Searching for:', query);
    }

    handleFilter() {
        const severity = document.getElementById('severity-filter')?.value;
        const status = document.getElementById('status-filter')?.value;
        // Implement filter logic
        console.log('Filtering by:', { severity, status });
    }

    // Utility Methods
    startAutoRefresh() {
        setInterval(() => {
            this.loadSectionData(this.currentSection);
        }, this.refreshInterval);
    }

    formatNumber(num) {
        return new Intl.NumberFormat('vi-VN').format(num);
    }

    formatDateTime(dateString) {
        const date = new Date(dateString);
        return new Intl.DateTimeFormat('vi-VN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }).format(date);
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text?.toString().replace(/[&<>"']/g, m => map[m]) || '';
    }

    getStatusText(status) {
        const statusMap = {
            'open': 'Mở',
            'investigating': 'Đang điều tra',
            'resolved': 'Đã giải quyết',
            'false_positive': 'False Positive',
            'active': 'Hoạt động',
            'inactive': 'Không hoạt động',
            'offline': 'Offline'
        };
        return statusMap[status] || status;
    }

    getEventTypeIcon(eventType) {
        const iconMap = {
            'process': 'cog',
            'network': 'network-wired',
            'file': 'file',
            'registry': 'database',
            'logon': 'sign-in-alt',
            'system': 'desktop'
        };
        return iconMap[eventType] || 'question';
    }

    getLast24Hours() {
        const hours = [];
        for (let i = 23; i >= 0; i--) {
            const date = new Date();
            date.setHours(date.getHours() - i);
            hours.push(date.getHours() + ':00');
        }
        return hours;
    }

    generateTimeSeriesData() {
        return Array.from({ length: 24 }, () => Math.floor(Math.random() * 100));
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type === 'error' ? 'danger' : type} notification`;
        notification.innerHTML = `
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            ${message}
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }

    // Action Methods
    async viewAlert(alertId) {
        try {
            const alert = await this.apiCall(`/alerts/${alertId}`);
            // Show alert details in modal
            console.log('Viewing alert:', alert);
        } catch (error) {
            console.error('Error viewing alert:', error);
        }
    }

    async updateAlertStatus(alertId, status) {
        try {
            await this.apiCall(`/alerts/${alertId}/status`, {
                method: 'PUT',
                body: JSON.stringify({ status })
            });
            this.showNotification('Cập nhật trạng thái thành công', 'success');
            this.loadSectionData(this.currentSection);
        } catch (error) {
            console.error('Error updating alert status:', error);
            this.showNotification('Lỗi khi cập nhật trạng thái', 'error');
        }
    }

    async viewAgentEvents(agentId) {
        try {
            const events = await this.apiCall(`/agents/${agentId}/events`);
            console.log('Agent events:', events);
            // Show events in modal or navigate to events section with filter
        } catch (error) {
            console.error('Error viewing agent events:', error);
        }
    }

    async reloadRules() {
        try {
            await this.apiCall('/rules/reload', { method: 'POST' });
            this.showNotification('Reload Sigma rules thành công', 'success');
            this.loadSigmaRules();
        } catch (error) {
            console.error('Error reloading rules:', error);
            this.showNotification('Lỗi khi reload rules', 'error');
        }
    }

    viewRule(ruleId) {
        console.log('Viewing rule:', ruleId);
        // Implement rule details view
    }
}

// Global Functions
window.reloadRules = () => dashboard.reloadRules();
window.loadAlerts = () => dashboard.loadAlerts();

// Initialize Dashboard
const dashboard = new EDRDashboard();
