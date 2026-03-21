document.addEventListener('alpine:init', () => {
    Alpine.data('dashboard', () => ({
        tab: 'overview',
        wsConnected: false,
        overview: {},
        services: [],
        topology: null,

        // Dashboard overview cards
        dashMongo: {},
        dashNats: {},
        dashDragonfly: {},
        dashRedpanda: {},
        dashDebezium: {},
        dashNodes: [],

        // K8s
        k8sNamespace: 'default',
        pods: [],
        k8sEvents: [],

        // MongoDB
        mongoHealth: {},
        mongoReplicas: [],
        syncErrors: [],

        // NATS
        natsHealth: {},
        natsStreams: [],
        natsConsumers: [],

        // Redpanda + Debezium
        redpandaData: {},
        debeziumDetail: {},
        consumerLagData: { status: 'unknown', total_lag: 0, consumer_groups: [] },

        // Dragonfly
        dragonflyData: {},
        dragonflyBlocks: [],
        dragonflyLocks: [],

        // Autodetect (overview)
        autodetectRunning: false,
        autodetectResult: null,

        // Issues page
        issuesPageResult: null,
        issuesPageScanning: false,

        // AI Fix panel
        aiFixError: '',
        aiFixService: '',
        aiFixResult: null,
        aiFixLoading: false,
        aiFixLog: [],
        aiFixTaskId: null,
        aiFixEventSource: null,
        aiFixMsg: '',

        // NATS actions
        natsActionResult: '',

        // Certificates
        certificates: [],

        // Nodes
        nodeMetrics: [],
        podMetrics: [],
        podMetricsNs: 'default',

        // Issues
        issueCount: 0,
        issueResult: null,
        scanningIssues: false,
        fixingIssues: false,

        // OpenObserve
        o2Status: {},
        o2Service: 'PosServerBackend',
        o2Minutes: '60',
        o2Errors: [],
        o2Traces: [],
        o2Loading: false,

        // Logs
        logService: 'posserverbackend',
        useAI: false,
        analyzing: false,
        logResult: null,

        // Incidents
        incidents: [],

        // Remediation
        playbooks: [],
        playbookResults: {},

        // Log Monitor
        logMonitorServices: [],
        logMonitorIssues: [],
        logMonitorTickets: [],
        logMonitorSelectedSvc: '',
        logMonitorScanning: false,
        logMonitorLastScan: null,
        logMonitorAutoScan: false,
        logMonitorInterval: null,

        // Tickets tab
        ticketsList: [],
        ticketStats: { total: 0, active: 0, by_status: {}, by_severity: {} },
        ticketFilterStatus: '',
        ticketFilterSeverity: '',
        ticketFilterService: '',
        ticketViewType: 'all', // 'all', 'devops', 'app'

        // DevOps = infra/middleware (k8s, MongoDB, NATS, Redis/Dragonfly, Redpanda, certs, scheduling)
        // Service = application-level errors (exceptions, timeouts, auth, sync logic, data conversion, HTTP errors)
        _devopsCategories: ['Memory', 'Disk', 'Crash', 'CrashLoop', 'Image', 'Eviction', 'Probe', 'Restart',
            'Scheduling', 'Volume', 'CPU', 'Network', 'Certificate', 'CertManager',
            'MongoDB', 'NATS', 'NATS-DLQ', 'Redis', 'RedisLock', 'RateLimit',
            'Redpanda', 'Debezium', 'ChangeStream', 'ConnectionPool'],

        // Admin Tasks
        adminSearch: '',
        adminSearchResults: [],
        adminDropdownOpen: false,
        adminSelectedBusiness: null,
        adminCopyLoading: false,
        adminCopyResult: null,

        // AP Code (manual)
        apSearch: '',
        apSearchResults: [],
        apDropdownOpen: false,
        apSelectedBusiness: null,
        apCode: '',
        apDate: '',
        apCodeLoading: false,
        apCodeResult: null,

        // AP Code (bulk upload)
        apFileSelected: false,
        apFileName: '',
        apFileData: null,
        apBulkLoading: false,
        apBulkReport: null,

        // Overview AI Fix Modal
        aiFixModal: { show: false, component: '', context: '', log: [], taskId: null, loading: false, result: null, msg: '', eventSource: null },

        // Charts
        statusChart: null,
        ws: null,

        async init() {
            this.ws = new DashboardWebSocket(
                (event, data) => this.handleWsMessage(event, data),
                (connected) => { this.wsConnected = connected; }
            );
            this.ws.connect();

            await this.loadOverview();
            await this.loadServices();
            this.loadDashboardCards();
            this.loadTicketStats();

            this.statusChart = new ServiceStatusChart('statusChart');
            this.$nextTick(() => this.statusChart.init());

            setInterval(() => this.loadOverview(), 15000);
            setInterval(() => this.loadServices(), 30000);
            setInterval(() => this.loadDashboardCards(), 30000);
            setInterval(() => this.loadTicketStats(), 60000);
        },

        handleWsMessage(event, data) {
            if (event === 'incident' || event === 'incident_resolved') this.loadIncidents();
            if (event === 'service_critical') this.loadServices();
        },

        async api(path, options = {}) {
            try {
                const resp = await fetch(path, options);
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                return await resp.json();
            } catch (e) {
                console.error(`API error ${path}:`, e);
                return null;
            }
        },

        async loadOverview() {
            const data = await this.api('/api/v1/dashboard/overview');
            if (data) {
                this.overview = data;
                if (this.statusChart) {
                    this.statusChart.update(data.services_healthy || 0, data.services_degraded || 0, data.services_critical || 0);
                }
            }
        },

        async loadDashboardCards() {
            const [mongo, nats, dragonfly, redpanda, debezium, nodes] = await Promise.all([
                this.api('/api/v1/mongodb/health'),
                this.api('/api/v1/nats/health'),
                this.api('/api/v1/dragonfly/health'),
                this.api('/api/v1/redpanda/health'),
                this.api('/api/v1/redpanda/debezium'),
                this.api('/api/v1/nodes/metrics'),
            ]);
            if (mongo) this.dashMongo = mongo;
            if (nats) this.dashNats = nats;
            if (dragonfly) this.dashDragonfly = dragonfly;
            if (redpanda) this.dashRedpanda = redpanda;
            if (nodes) this.dashNodes = nodes;
            if (debezium?.connectors?.[0]) {
                const c = debezium.connectors[0];
                this.dashDebezium = { state: c.state, tasks: c.tasks, failed: c.failed_tasks };
            }
        },

        formatUptime(seconds) {
            if (!seconds) return 'N/A';
            const d = Math.floor(seconds / 86400);
            const h = Math.floor((seconds % 86400) / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            if (d > 0) return d + 'd ' + h + 'h';
            if (h > 0) return h + 'h ' + m + 'm';
            return m + 'm';
        },

        async loadServices() {
            const data = await this.api('/api/v1/services');
            if (data) this.services = data;
        },

        async renderTopology() {
            if (!this.topology) this.topology = await this.api('/api/v1/services/topology');
            if (this.topology) setTimeout(() => renderServiceTopology('topology-container', this.topology), 100);
        },

        async loadK8s() {
            const [pods, events] = await Promise.all([
                this.api(`/api/v1/k8s/pods?namespace=${this.k8sNamespace}`),
                this.api(`/api/v1/k8s/events?namespace=${this.k8sNamespace}`),
            ]);
            if (pods) this.pods = pods;
            if (events) this.k8sEvents = events;
        },

        async loadNodes() {
            const data = await this.api('/api/v1/nodes/metrics');
            if (data) this.nodeMetrics = data;
            await this.loadPodMetrics();
        },

        async loadPodMetrics() {
            const data = await this.api(`/api/v1/nodes/pods?namespace=${this.podMetricsNs}`);
            if (data) this.podMetrics = data;
        },

        async loadMongo() {
            const data = await this.api('/api/v1/mongodb/health');
            if (data) this.mongoHealth = data;
            await this.loadMongoReplicas();
        },

        async loadMongoReplicas() {
            const data = await this.api('/api/v1/mongodb/replicas');
            if (data) this.mongoReplicas = data;
        },

        async loadSyncErrors() {
            const data = await this.api('/api/v1/mongodb/sync-errors');
            if (data) this.syncErrors = data;
        },

        async loadNats() {
            const [health, streams, consumers] = await Promise.all([
                this.api('/api/v1/nats/health'),
                this.api('/api/v1/nats/streams'),
                this.api('/api/v1/nats/consumers'),
            ]);
            if (health) this.natsHealth = health;
            if (streams) this.natsStreams = streams;
            if (consumers) this.natsConsumers = consumers;
        },

        async runAutodetect() {
            this.autodetectRunning = true;
            this.autodetectResult = null;
            const data = await this.api('/api/v1/issues/autodetect', { method: 'POST' });
            if (data) {
                data.issues = (data.issues || []).map(i => ({ ...i, _fixing: false, _executing: false, _fixResult: null, _fixProgress: [], _agentLog: [], _manualCmd: '', _manualOutput: '', _aiMsg: '', _aiTaskId: null, _savingLearning: false, _learningNote: '' }));
                this.autodetectResult = data;
            }
            this.autodetectRunning = false;
        },

        async diagnoseIssue(issue) {
            issue._fixing = true;
            issue._fixProgress = [];
            issue._fixResult = null;
            issue._agentLog = [];
            issue._executing = false;
            issue._aiTaskId = null;
            issue._aiMsg = '';
            const data = await this.api('/api/v1/ai/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ issue: issue.detail, service: issue.service, auto_fix: true }),
            });
            if (!data?.task_id) {
                issue._fixProgress.push('ERROR: Failed to start AI investigation');
                issue._fixing = false;
                return;
            }
            issue._aiTaskId = data.task_id;
            this._streamAiEvents(issue, data.task_id);
        },

        _streamAiEvents(issue, taskId) {
            const evtSource = new EventSource(`/api/v1/ai/stream/${taskId}`);
            issue._aiEventSource = evtSource;
            evtSource.onmessage = (event) => {
                try {
                    const evt = JSON.parse(event.data);
                    if (evt.type === 'done') {
                        issue._fixing = false;
                        issue._fixResult = { diagnosis: evt.final_output || '' };
                        issue._fixProgress.push(`Complete (${(evt.duration_ms / 1000).toFixed(1)}s)`);
                        evtSource.close();
                        return;
                    }
                    issue._agentLog.push(evt);
                    if (issue._agentLog.length > 200) issue._agentLog.splice(0, 50);
                    this.$nextTick(() => {
                        const boxes = document.querySelectorAll('[x-ref="logbox"]');
                        boxes.forEach(b => { b.scrollTop = b.scrollHeight; });
                    });
                } catch (e) { console.error('SSE parse error:', e); }
            };
            evtSource.onerror = () => {
                issue._fixing = false;
                if (!issue._fixResult) issue._fixProgress.push('Connection lost');
                evtSource.close();
            };
        },

        async stopAi(issue) {
            if (!issue._aiTaskId) return;
            await this.api(`/api/v1/ai/stop/${issue._aiTaskId}`, { method: 'POST' });
            if (issue._aiEventSource) issue._aiEventSource.close();
            issue._fixing = false;
            issue._fixProgress.push('Stopped by user');
        },

        async sendAiMessage(issue) {
            if (!issue._aiTaskId || !issue._aiMsg?.trim()) return;
            const msg = issue._aiMsg;
            issue._aiMsg = '';
            issue._agentLog.push({ type: 'user', message: 'You: ' + msg });
            await this.api(`/api/v1/ai/message/${issue._aiTaskId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msg }),
            });
            issue._fixing = true;
        },

        async saveLearning(issue) {
            if (!issue._aiTaskId) return;
            issue._savingLearning = true;
            const note = issue._learningNote || '';
            issue._agentLog.push({ type: 'status', message: 'Saving learning to memory...' });
            issue._fixing = true;
            await this.api(`/api/v1/ai/save-learning/${issue._aiTaskId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ note }),
            });
            this._streamAiEvents(issue, issue._aiTaskId);
        },

        async runManualCmd(issue) {
            if (!issue._manualCmd?.trim()) return;
            issue._manualOutput = 'Running...';
            const data = await this.api('/api/v1/issues/run-step', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: issue._manualCmd }),
            });
            issue._manualOutput = data ? data.output : 'ERROR: Request failed';
            issue._fixProgress.push('Manual: ' + (data?.success ? 'OK' : 'FAILED'));
        },

        async runStep(issue, stepIndex, command) {
            if (!command) return;
            if (!issue._fixResult.executed_steps) issue._fixResult.executed_steps = [];
            while (issue._fixResult.executed_steps.length <= stepIndex) issue._fixResult.executed_steps.push(null);
            issue._fixResult.executed_steps[stepIndex] = { command, output: 'Running...', success: null };
            const data = await this.api('/api/v1/issues/run-step', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command }),
            });
            if (data) {
                issue._fixResult.executed_steps[stepIndex] = data;
                issue._fixProgress.push(`Step ${stepIndex+1}: ${data.success ? 'done' : 'FAILED'}`);
            }
        },

        async deployService(issue) {
            const cmd = issue._fixResult?.deploy_command;
            if (!cmd) return;
            const match = cmd.match(/deployment\/(\S+)\s+-n\s+(\S+)/);
            if (!match) { alert('Could not parse deploy command'); return; }
            const [, svc, ns] = match;
            if (!confirm(`Rolling restart ${svc} in ${ns}?`)) return;
            issue._fixProgress.push(`Deploying ${svc}...`);
            const data = await this.api(`/api/v1/issues/deploy?service=${svc}&namespace=${ns}`, { method: 'POST' });
            if (data) issue._fixProgress.push('Deploy: ' + (data.output || 'done'));
        },

        async natsAction(path, confirmMsg) {
            if (confirmMsg && !confirm(confirmMsg)) return;
            this.natsActionResult = 'Executing...';
            const data = await this.api('/api/v1/nats/' + path, { method: 'POST' });
            this.natsActionResult = data ? JSON.stringify(data, null, 2) : 'Failed';
            await this.loadNats();
        },

        async submitAiFix(autoExecute) {
            if (!this.aiFixError.trim()) return;
            if (autoExecute && !confirm('AI will investigate and apply safe fixes. Continue?')) return;
            this.aiFixLoading = true;
            this.aiFixResult = null;
            this.aiFixLog = [];
            this.aiFixMsg = '';
            const data = await this.api('/api/v1/analysis/ai-fix', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ error_text: this.aiFixError, service: this.aiFixService, auto_execute: autoExecute }),
            });
            if (!data?.task_id) {
                this.aiFixLoading = false;
                this.aiFixLog.push({ type: 'error', message: 'Failed to start AI investigation' });
                return;
            }
            this.aiFixTaskId = data.task_id;
            const evtSource = new EventSource(`/api/v1/ai/stream/${data.task_id}`);
            this.aiFixEventSource = evtSource;
            evtSource.onmessage = (event) => {
                try {
                    const evt = JSON.parse(event.data);
                    if (evt.type === 'done') {
                        this.aiFixLoading = false;
                        this.aiFixResult = { diagnosis: evt.final_output || '' };
                        evtSource.close();
                        return;
                    }
                    this.aiFixLog.push(evt);
                    if (this.aiFixLog.length > 200) this.aiFixLog.splice(0, 50);
                } catch (e) { console.error('SSE parse error:', e); }
            };
            evtSource.onerror = () => {
                this.aiFixLoading = false;
                if (!this.aiFixResult) this.aiFixLog.push({ type: 'error', message: 'Connection lost' });
                evtSource.close();
            };
        },

        async stopAiFixPanel() {
            if (this.aiFixTaskId) await this.api(`/api/v1/ai/stop/${this.aiFixTaskId}`, { method: 'POST' });
            if (this.aiFixEventSource) this.aiFixEventSource.close();
            this.aiFixLoading = false;
            this.aiFixLog.push({ type: 'status', message: 'Stopped by user' });
        },

        async sendAiFixMessage() {
            if (!this.aiFixTaskId || !this.aiFixMsg?.trim()) return;
            const msg = this.aiFixMsg;
            this.aiFixMsg = '';
            this.aiFixLog.push({ type: 'user', message: 'You: ' + msg });
            await this.api(`/api/v1/ai/message/${this.aiFixTaskId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msg }),
            });
        },

        async loadRedpanda() {
            const [health, debezium, detail, lag] = await Promise.all([
                this.api('/api/v1/redpanda/health'),
                this.api('/api/v1/redpanda/debezium'),
                this.api('/api/v1/redpanda/debezium/detail'),
                this.api('/api/v1/redpanda/consumer-lag'),
            ]);
            this.redpandaData = {
                broker: health || {},
                debezium_connectors: debezium?.connectors || [],
                debezium_failed: debezium?.connectors?.reduce((sum, c) => sum + (c.failed_tasks || 0), 0) || 0,
            };
            if (detail) this.debeziumDetail = detail;
            if (lag) this.consumerLagData = lag;
        },

        async restartDebezium(connector) {
            const data = await this.api(`/api/v1/redpanda/debezium/${connector}/restart`, { method: 'POST' });
            if (data) alert(`Restart result: ${data.status}`);
            await this.loadRedpanda();
        },

        async loadDragonfly() {
            const [health, blocks, locks] = await Promise.all([
                this.api('/api/v1/dragonfly/health'),
                this.api('/api/v1/dragonfly/blocks'),
                this.api('/api/v1/dragonfly/locks'),
            ]);
            if (health) this.dragonflyData = health;
            if (blocks) this.dragonflyBlocks = blocks;
            if (locks) this.dragonflyLocks = locks;
        },

        async unblockBusiness(businessId) {
            const data = await this.api(`/api/v1/dragonfly/blocks/${businessId}/unblock`, { method: 'POST' });
            if (data?.unblocked) await this.loadDragonfly();
        },

        async loadCerts() {
            const status = await this.api('/api/v1/certificates/status');
            const data = await this.api('/api/v1/certificates');
            if (data) this.certificates = Array.isArray(data) ? data : (data.certificates || data.certs || []);
        },

        async renewCert(name) {
            if (!confirm(`Trigger renewal for "${name}"?`)) return;
            const data = await this.api(`/api/v1/certificates/${name}/renew`, { method: 'POST' });
            if (data) alert(JSON.stringify(data));
            await this.loadCerts();
        },

        async loadIssues() {
            if (this.issuesPageResult) return;
            await this.scanIssuesPage();
        },

        async scanIssuesPage() {
            this.issuesPageScanning = true;
            const data = await this.api('/api/v1/issues/autodetect', { method: 'POST' });
            if (data) {
                data.issues = (data.issues || []).map(i => ({ ...i, _fixing: false, _executing: false, _fixResult: null, _fixProgress: [], _agentLog: [], _manualCmd: '', _manualOutput: '', _aiMsg: '', _aiTaskId: null, _savingLearning: false, _learningNote: '' }));
                this.issuesPageResult = data;
                this.issueCount = data.total || 0;
            }
            this.issuesPageScanning = false;
        },

        async scanIssues() {
            this.scanningIssues = true;
            const data = await this.api('/api/v1/issues/scan', { method: 'POST' });
            if (data) { this.issueResult = data; this.issueCount = data.total_issues || 0; }
            this.scanningIssues = false;
        },

        async analyzeAndFix(dryRun) {
            if (!dryRun && !confirm('Execute AI auto-fix on production?')) return;
            this.fixingIssues = true;
            this.aiFixResult = null;
            const data = await this.api(`/api/v1/issues/analyze-and-fix?dry_run=${dryRun}`, { method: 'POST' });
            if (data) this.aiFixResult = data;
            this.fixingIssues = false;
        },

        async loadO2() {
            const data = await this.api('/api/v1/openobserve/status');
            if (data) this.o2Status = data;
        },

        async loadO2Errors() {
            this.o2Loading = true;
            const data = await this.api(`/api/v1/openobserve/errors/${this.o2Service}?minutes=${this.o2Minutes}`);
            if (data) this.o2Errors = data;
            this.o2Loading = false;
        },

        async loadO2Traces() {
            const data = await this.api(`/api/v1/openobserve/traces/slow?minutes=${this.o2Minutes}`);
            if (data) this.o2Traces = data;
        },

        async analyzeLogs() {
            this.analyzing = true;
            this.logResult = null;
            const data = await this.api(`/api/v1/logs/${this.logService}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ use_ai: this.useAI }),
            });
            if (data) this.logResult = data;
            this.analyzing = false;
        },

        async loadIncidents() {
            const data = await this.api('/api/v1/incidents');
            if (data) this.incidents = data;
        },

        async resolveIncident(id) {
            await this.api(`/api/v1/incidents/${id}/resolve`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
            await this.loadIncidents();
        },

        async generatePostmortem(id) {
            const data = await this.api(`/api/v1/incidents/${id}/postmortem`, { method: 'POST' });
            if (data?.postmortem) alert(data.postmortem);
        },

        async loadPlaybooks() {
            const data = await this.api('/api/v1/remediation/playbooks');
            if (data) this.playbooks = data;
        },

        async executePlaybook(name, dryRun) {
            if (!dryRun && !confirm(`Execute "${name}" for real?`)) return;
            const data = await this.api('/api/v1/remediation/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ playbook: name, dry_run: dryRun, context: {} }),
            });
            if (data) this.playbookResults[name] = data;
        },

        // --- Log Monitor ---
        _logMonitorLoaded: false,

        async loadLogMonitor() {
            if (this._logMonitorLoaded) {
                await this.loadLogMonitorTickets();
                return;
            }
            this._logMonitorLoaded = true;
            await this.fetchLogMonitorData('/api/v1/logmonitor/latest');
            await this.loadLogMonitorTickets();
            if (!this.logMonitorInterval) {
                this.logMonitorInterval = setInterval(() => {
                    this._mergeLogMonitorData('/api/v1/logmonitor/latest');
                    this.loadLogMonitorTickets();
                }, 30000);
            }
        },

        async scanLogMonitor() {
            this.logMonitorScanning = true;
            await this.fetchLogMonitorData('/api/v1/logmonitor/scan', { method: 'POST' });
            this.logMonitorScanning = false;
        },

        async fetchLogMonitorData(url, options = {}) {
            const data = await this.api(url, options);
            if (data) {
                this.logMonitorServices = data.services || [];
                this.logMonitorIssues = (data.issues || []).map(i => ({
                    ...i, _ticketCreated: false, _ticket: null, _diagnosing: false, _diagResult: null,
                }));
                this.logMonitorLastScan = data.scanned_at || new Date().toISOString();
                if (!this.logMonitorSelectedSvc) {
                    const withIssues = this.logMonitorServices.find(s => s.issueCount > 0);
                    if (withIssues) this.logMonitorSelectedSvc = withIssues.name;
                    else if (this.logMonitorServices.length) this.logMonitorSelectedSvc = this.logMonitorServices[0].name;
                }
            }
        },

        async _mergeLogMonitorData(url) {
            const data = await this.api(url);
            if (!data) return;
            this.logMonitorServices = data.services || [];
            this.logMonitorLastScan = data.scanned_at || new Date().toISOString();
            const newIssues = data.issues || [];
            const existing = {};
            for (const i of this.logMonitorIssues) {
                existing[i.service + '|' + i.category + '|' + i.description] = i;
            }
            this.logMonitorIssues = newIssues.map(i => {
                const key = i.service + '|' + i.category + '|' + i.description;
                const prev = existing[key];
                if (prev) return { ...i, _ticketCreated: prev._ticketCreated, _ticket: prev._ticket, _diagnosing: prev._diagnosing, _diagResult: prev._diagResult };
                return { ...i, _ticketCreated: false, _ticket: null, _diagnosing: false, _diagResult: null };
            });
        },

        async loadLogMonitorTickets() {
            const data = await this.api('/api/v1/logmonitor/tickets');
            if (data) this.logMonitorTickets = data;
        },

        filteredLogIssues() {
            if (!this.logMonitorSelectedSvc) return this.logMonitorIssues;
            return this.logMonitorIssues.filter(i => i.service === this.logMonitorSelectedSvc);
        },

        async createTicketAndFix(issue) {
            issue._ticketCreated = true;
            const data = await this.api('/api/v1/logmonitor/ticket', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    service: issue.service, namespace: issue.namespace || 'default',
                    severity: issue.severity, category: issue.category,
                    description: issue.description, matched_line: issue.matched_line,
                    recommendation: issue.recommendation || '',
                }),
            });
            if (data?.ticket) {
                issue._ticket = data.ticket;
                this.logMonitorTickets.unshift(data.ticket);
                this.loadTicketStats();
            }
        },

        async diagnoseIssueFromMonitor(issue) {
            issue._diagnosing = true;
            issue._diagResult = null;
            const data = await this.api('/api/v1/logmonitor/diagnose', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ service: issue.service, description: issue.description, matched_line: issue.matched_line }),
            });
            if (data?.diagnosis) issue._diagResult = data.diagnosis;
            issue._diagnosing = false;
        },

        // --- Tickets Tab ---
        async resolveTicket(ticketId) {
            await this.api(`/api/v1/logmonitor/tickets/${ticketId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: 'resolved' }),
            });
            await this.loadTickets();
        },

        async reopenTicket(ticketId) {
            await this.api(`/api/v1/logmonitor/tickets/${ticketId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: 'investigating' }),
            });
            await this.loadTickets();
        },

        isDevopsTicket(ticket) {
            return this._devopsCategories.includes(ticket.category);
        },

        filteredTickets() {
            let list = this.ticketsList;
            if (this.ticketViewType === 'devops') list = list.filter(t => this.isDevopsTicket(t));
            else if (this.ticketViewType === 'app') list = list.filter(t => !this.isDevopsTicket(t));
            return list;
        },

        async resetAllTickets() {
            if (!confirm('Delete ALL tickets? This cannot be undone.')) return;
            const data = await this.api('/api/v1/logmonitor/tickets', { method: 'DELETE' });
            if (data) alert(`Deleted ${data.deleted} tickets`);
            await this.loadTickets();
        },

        async aiFixTicket(ticketId) {
            await this.api(`/api/v1/logmonitor/tickets/${ticketId}/ai-fix`, { method: 'POST' });
            alert('AI fix dispatched for ticket #' + ticketId);
            await this.loadTickets();
        },

        async loadTickets() {
            const params = new URLSearchParams();
            if (this.ticketFilterStatus) params.set('status', this.ticketFilterStatus);
            if (this.ticketFilterSeverity) params.set('severity', this.ticketFilterSeverity);
            if (this.ticketFilterService) params.set('service', this.ticketFilterService);
            params.set('limit', '100');
            const data = await this.api(`/api/v1/logmonitor/tickets?${params}`);
            if (data) this.ticketsList = data;
            await this.loadTicketStats();
        },

        async loadTicketStats() {
            const data = await this.api('/api/v1/logmonitor/ticket-stats');
            if (data) this.ticketStats = data;
        },

        // --- Overview AI Fix Modal ---
        startOverviewAiFix(component, context) {
            this.aiFixModal = { show: true, component, context, log: [], taskId: null, loading: false, result: null, msg: '', eventSource: null };
        },

        async runOverviewAiFix() {
            const m = this.aiFixModal;
            m.loading = true;
            m.result = null;
            m.log = [];
            const issue = `Check the ${m.component} component for any issues, errors, or degraded performance. Investigate and fix if needed.`;
            const data = await this.api('/api/v1/ai/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ issue, service: m.component, auto_fix: true }),
            });
            if (!data?.task_id) {
                m.loading = false;
                m.log.push({ type: 'error', message: 'Failed to start AI' });
                return;
            }
            m.taskId = data.task_id;
            const evtSource = new EventSource(`/api/v1/ai/stream/${data.task_id}`);
            m.eventSource = evtSource;
            evtSource.onmessage = (event) => {
                try {
                    const evt = JSON.parse(event.data);
                    if (evt.type === 'done') {
                        m.loading = false;
                        m.result = evt.final_output || '';
                        evtSource.close();
                        return;
                    }
                    m.log.push(evt);
                    if (m.log.length > 200) m.log.splice(0, 50);
                } catch (e) { console.error('SSE parse:', e); }
            };
            evtSource.onerror = () => {
                m.loading = false;
                if (!m.result) m.log.push({ type: 'error', message: 'Connection lost' });
                evtSource.close();
            };
        },

        async sendOverviewAiMsg() {
            const m = this.aiFixModal;
            if (!m.taskId || !m.msg?.trim()) return;
            const msg = m.msg;
            m.msg = '';
            m.log.push({ type: 'user', message: 'You: ' + msg });
            await this.api(`/api/v1/ai/message/${m.taskId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: msg }),
            });
            m.loading = true;
        },

        async stopOverviewAiFix() {
            const m = this.aiFixModal;
            if (m.taskId) await this.api(`/api/v1/ai/stop/${m.taskId}`, { method: 'POST' });
            if (m.eventSource) m.eventSource.close();
            m.loading = false;
            m.log.push({ type: 'status', message: 'Stopped by user' });
        },

        // --- Issues sorted (critical first) ---
        sortedServices() {
            const svcs = this.services || [];
            const order = { degraded: 0, unhealthy: 1, error: 2, warning: 3, healthy: 4, unknown: 5 };
            return [...svcs].sort((a, b) => (order[a.status] ?? 3) - (order[b.status] ?? 3));
        },

        sortedIssues() {
            const issues = this.issuesPageResult?.issues || [];
            return [...issues].sort((a, b) => {
                const order = { critical: 0, error: 1, warning: 2, info: 3 };
                return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
            });
        },

        // --- Passkey Registration ---
        async registerPasskey() {
            if (!window.PublicKeyCredential) {
                alert('Your browser does not support passkeys');
                return;
            }
            try {
                const optResp = await fetch('/api/v1/auth/passkey/register-options', { method: 'POST' });
                if (!optResp.ok) { alert('Failed to get registration options: ' + (await optResp.json()).detail); return; }
                const opts = await optResp.json();
                opts.challenge = this._b64ToArr(opts.challenge);
                opts.user.id = this._b64ToArr(opts.user.id);
                if (opts.excludeCredentials) opts.excludeCredentials = opts.excludeCredentials.map(c => ({...c, id: this._b64ToArr(c.id)}));
                const cred = await navigator.credentials.create({ publicKey: opts });
                const body = {
                    id: cred.id,
                    rawId: this._arrToB64(new Uint8Array(cred.rawId)),
                    type: cred.type,
                    response: {
                        attestationObject: this._arrToB64(new Uint8Array(cred.response.attestationObject)),
                        clientDataJSON: this._arrToB64(new Uint8Array(cred.response.clientDataJSON)),
                    }
                };
                const vResp = await fetch('/api/v1/auth/passkey/register', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) });
                if (vResp.ok) { alert('Passkey registered successfully! You can now use it to log in.'); }
                else { const e = await vResp.json(); alert('Registration failed: ' + (e.detail || 'Unknown error')); }
            } catch (e) {
                if (e.name === 'NotAllowedError') return;
                alert('Passkey error: ' + e.message);
            }
        },
        _b64ToArr(b) { const s = b.replace(/-/g, '+').replace(/_/g, '/'); const r = atob(s); const a = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) a[i] = r.charCodeAt(i); return a.buffer; },
        _arrToB64(a) { let s = ''; const b = new Uint8Array(a); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); },

        // --- Utilities ---
        formatBytes(bytes) {
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        formatAiAnalysis(text) {
            if (!text) return '';
            let safe = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            safe = safe.replace(/```\w*\n?/g, '');
            try {
                const parsed = JSON.parse(safe.trim());
                safe = JSON.stringify(parsed, null, 2).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            } catch (e) {}
            return safe;
        },

        // ---- Admin Tasks ----
        async searchBusinesses() {
            const q = this.adminSearch.trim();
            if (q.length < 2) { this.adminSearchResults = []; this.adminDropdownOpen = false; return; }
            const data = await this.api(`/api/v1/admin/search-businesses?q=${encodeURIComponent(q)}`);
            this.adminSearchResults = data?.businesses || [];
            this.adminDropdownOpen = this.adminSearchResults.length > 0;
        },

        selectAdminBusiness(b) {
            this.adminSelectedBusiness = b;
            this.adminSearch = b.businessName || '';
            this.adminDropdownOpen = false;
            this.adminCopyResult = null;
        },

        clearAdminBusiness() {
            this.adminSelectedBusiness = null;
            this.adminSearch = '';
            this.adminSearchResults = [];
            this.adminCopyResult = null;
        },

        async executeCopyCategories() {
            const b = this.adminSelectedBusiness;
            if (!b) return;
            if (!confirm(`Copy categories to "${b.businessName}" (${b.businessCity})?\n\nBusiness ID: ${b.businessId}`)) return;
            this.adminCopyLoading = true;
            this.adminCopyResult = null;
            const data = await this.api('/api/v1/admin/copy-categories', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ businessId: b.businessId, businessCity: b.businessCity }),
            });
            this.adminCopyLoading = false;
            if (data?.success) {
                this.adminCopyResult = { success: true, message: 'Categories copied successfully!' };
            } else {
                this.adminCopyResult = { success: false, message: 'Failed: ' + (data?.error || 'Unknown error') };
            }
        },

        // ---- AP Code (Manual) ----
        async searchApBusinesses() {
            const q = this.apSearch.trim();
            if (q.length < 2) { this.apSearchResults = []; this.apDropdownOpen = false; return; }
            const data = await this.api(`/api/v1/admin/search-businesses?q=${encodeURIComponent(q)}`);
            this.apSearchResults = data?.businesses || [];
            this.apDropdownOpen = this.apSearchResults.length > 0;
        },

        selectApBusiness(b) {
            this.apSelectedBusiness = b;
            this.apSearch = b.businessName || '';
            this.apDropdownOpen = false;
            this.apCodeResult = null;
        },

        clearApBusiness() {
            this.apSelectedBusiness = null;
            this.apSearch = '';
            this.apSearchResults = [];
            this.apCode = '';
            this.apDate = '';
            this.apCodeResult = null;
        },

        async executeUpdateApCode() {
            const b = this.apSelectedBusiness;
            if (!b || !this.apCode?.trim() || !this.apDate) return;
            const dateParts = this.apDate.split('-');
            const formattedDate = `${dateParts[2]}/${dateParts[1]}/${dateParts[0]}`;
            if (!confirm(`Update AP Code for "${b.businessName}"?\n\nAP Code: ${this.apCode}\nDate: ${formattedDate}`)) return;
            this.apCodeLoading = true;
            this.apCodeResult = null;
            const data = await this.api('/api/v1/admin/update-ap-code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ businessId: b.businessId, partnerCode: this.apCode.trim(), openStockAsOnDate: formattedDate }),
            });
            this.apCodeLoading = false;
            if (data?.success) {
                this.apCodeResult = { success: true, message: data.message || 'AP Code updated successfully!' };
            } else {
                this.apCodeResult = { success: false, message: 'Failed: ' + (data?.error || 'Unknown error') };
            }
        },

        // ---- AP Code (Bulk Upload) ----
        handleApFileSelect(event) {
            const file = event.target.files[0];
            if (file) {
                this.apFileSelected = true;
                this.apFileName = file.name;
                this.apFileData = file;
                this.apBulkReport = null;
            }
        },

        async uploadApCodes() {
            if (!this.apFileData) return;
            this.apBulkLoading = true;
            this.apBulkReport = null;
            const formData = new FormData();
            formData.append('file', this.apFileData);
            try {
                const resp = await fetch('/api/v1/admin/bulk-update-ap-codes', { method: 'POST', body: formData });
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                const data = await resp.json();
                this.apBulkReport = data;
            } catch (e) {
                this.apBulkReport = { successful: [], unmatched: [], failed: [{ partnerName: 'Upload', error: e.message }] };
            }
            this.apBulkLoading = false;
        },
    }));
});
