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
        syncErrors: [],

        // NATS
        natsHealth: {},
        natsStreams: [],
        natsConsumers: [],

        // Redpanda + Debezium
        redpandaData: {},
        debeziumDetail: {},

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
        aiFixResult: null,
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

        // Charts
        statusChart: null,
        ws: null,

        async init() {
            // WebSocket
            this.ws = new DashboardWebSocket(
                (event, data) => this.handleWsMessage(event, data),
                (connected) => { this.wsConnected = connected; }
            );
            this.ws.connect();

            // Initial loads
            await this.loadOverview();
            await this.loadServices();
            this.loadDashboardCards();

            // Status doughnut chart
            this.statusChart = new ServiceStatusChart('statusChart');
            this.$nextTick(() => this.statusChart.init());

            // Polling
            setInterval(() => this.loadOverview(), 15000);
            setInterval(() => this.loadServices(), 30000);
            setInterval(() => this.loadDashboardCards(), 30000);
        },

        handleWsMessage(event, data) {
            if (event === 'incident' || event === 'incident_resolved') {
                this.loadIncidents();
            }
            if (event === 'service_critical') {
                this.loadServices();
            }
            // fix_progress events are handled by Alpine reactivity on issue objects
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
                    this.statusChart.update(
                        data.services_healthy || 0,
                        data.services_degraded || 0,
                        data.services_critical || 0,
                    );
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
            // Debezium summary for dashboard card
            if (debezium?.connectors?.[0]) {
                const c = debezium.connectors[0];
                this.dashDebezium = { state: c.state, tasks: c.tasks, failed: c.failed_tasks,
                                       topics: debezium.connectors[0]?.task_states?.length || 0 };
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
            if (!this.topology) {
                this.topology = await this.api('/api/v1/services/topology');
            }
            if (this.topology) {
                setTimeout(() => renderServiceTopology('topology-container', this.topology), 100);
            }
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
                // Add UI state to each issue
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

            // Start streaming AI task
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
                    // Auto-scroll log box
                    this.$nextTick(() => {
                        const boxes = document.querySelectorAll('[x-ref="logbox"]');
                        boxes.forEach(b => { b.scrollTop = b.scrollHeight; });
                    });
                } catch (e) {
                    console.error('SSE parse error:', e);
                }
            };

            evtSource.onerror = () => {
                issue._fixing = false;
                if (!issue._fixResult) {
                    issue._fixProgress.push('Connection lost');
                }
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

            // Re-open SSE stream for the save operation
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
            // Initialize executed_steps array if needed
            if (!issue._fixResult.executed_steps) issue._fixResult.executed_steps = [];
            // Pad array to correct index
            while (issue._fixResult.executed_steps.length <= stepIndex) {
                issue._fixResult.executed_steps.push(null);
            }
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
            // Extract service and namespace from deploy command
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
            if (autoExecute && !confirm('AI will investigate and apply safe fixes on production. Continue?')) return;
            this.aiFixLoading = true;
            this.aiFixResult = null;
            this.aiFixLog = [];
            this.aiFixMsg = '';

            const data = await this.api('/api/v1/analysis/ai-fix', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    error_text: this.aiFixError,
                    service: this.aiFixService,
                    auto_execute: autoExecute,
                }),
            });

            if (!data?.task_id) {
                this.aiFixLoading = false;
                this.aiFixLog.push({ type: 'error', message: 'Failed to start AI investigation' });
                return;
            }

            this.aiFixTaskId = data.task_id;
            // Open SSE stream
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
                } catch (e) {
                    console.error('SSE parse error:', e);
                }
            };

            evtSource.onerror = () => {
                this.aiFixLoading = false;
                if (!this.aiFixResult) {
                    this.aiFixLog.push({ type: 'error', message: 'Connection lost' });
                }
                evtSource.close();
            };
        },

        async stopAiFixPanel() {
            if (this.aiFixTaskId) {
                await this.api(`/api/v1/ai/stop/${this.aiFixTaskId}`, { method: 'POST' });
            }
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
            const [health, debezium, detail] = await Promise.all([
                this.api('/api/v1/redpanda/health'),
                this.api('/api/v1/redpanda/debezium'),
                this.api('/api/v1/redpanda/debezium/detail'),
            ]);
            this.redpandaData = {
                broker: health || {},
                debezium_connectors: debezium?.connectors || [],
                debezium_failed: debezium?.connectors?.reduce((sum, c) => sum + (c.failed_tasks || 0), 0) || 0,
            };
            if (detail) this.debeziumDetail = detail;
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
            // First trigger a check to populate the certificates list
            const status = await this.api('/api/v1/certificates/status');
            // Then fetch the populated certificates
            const data = await this.api('/api/v1/certificates');
            if (data) {
                // Handle both array and object-with-array responses
                this.certificates = Array.isArray(data) ? data : (data.certificates || data.certs || []);
            }
        },

        async renewCert(name) {
            if (!confirm(`Trigger renewal for certificate "${name}"? This will delete the TLS secret.`)) return;
            const data = await this.api(`/api/v1/certificates/${name}/renew`, { method: 'POST' });
            if (data) alert(JSON.stringify(data));
            await this.loadCerts();
        },

        async loadIssues() {
            // Load issues for the dedicated Issues tab
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
            if (data) {
                this.issueResult = data;
                this.issueCount = data.total_issues || 0;
            }
            this.scanningIssues = false;
        },

        async analyzeAndFix(dryRun) {
            if (!dryRun && !confirm('Execute AI auto-fix on production? Low-risk fixes will be executed.')) return;
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
            if (!dryRun && !confirm(`Execute playbook "${name}" for real? This will take actions.`)) return;
            const data = await this.api('/api/v1/remediation/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ playbook: name, dry_run: dryRun, context: {} }),
            });
            if (data) this.playbookResults[name] = data;
        },

        formatBytes(bytes) {
            if (!bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        },

        formatAiAnalysis(text) {
            if (!text) return '';
            // Escape HTML
            let safe = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            // Strip markdown code fences (```json ... ``` or ``` ... ```)
            safe = safe.replace(/```\w*\n?/g, '');
            // Try to pretty-print JSON content
            try {
                const parsed = JSON.parse(safe.trim());
                safe = JSON.stringify(parsed, null, 2)
                    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            } catch (e) {
                // Not JSON, leave as-is
            }
            return safe;
        },
    }));
});
