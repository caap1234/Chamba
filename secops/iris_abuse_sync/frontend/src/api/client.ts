let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  if (csrfToken && options.method && options.method.toUpperCase() !== 'GET') {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (response.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/me')) {
    window.dispatchEvent(new CustomEvent('soc:unauthorized'));
    throw new Error('Sesión expirada o no autorizada.');
  }

  if (!response.ok) {
    let errorDetail = 'Error en la solicitud al servidor';
    try {
      const errJson = await response.json();
      if (typeof errJson.detail === 'string') {
        errorDetail = errJson.detail;
      } else if (Array.isArray(errJson.detail)) {
        errorDetail = errJson.detail.map((e: any) => e.msg || e.detail || JSON.stringify(e)).join('; ');
      } else if (errJson.detail && typeof errJson.detail === 'object') {
        errorDetail = errJson.detail.message || JSON.stringify(errJson.detail);
      } else if (errJson.message) {
        errorDetail = errJson.message;
      }
    } catch {
      // Ignore
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export const api = {
  // Auth
  async login(username: string, password: string) {
    const res = await request<any>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    if (res.csrf_token) {
      setCsrfToken(res.csrf_token);
    }
    return res;
  },

  async logout() {
    await request<any>('/api/v1/auth/logout', { method: 'POST' });
    setCsrfToken(null);
  },

  async getMe() {
    const res = await request<any>('/api/v1/auth/me');
    if (res.csrf_token) {
      setCsrfToken(res.csrf_token);
    }
    return res;
  },

  // Dashboard
  async getDashboardSummary() {
    return request<any>('/api/v1/dashboard/summary');
  },

  // Alerts
  async listAlerts(page = 1, perPage = 50, filters: Record<string, any> = {}) {
    const query = new URLSearchParams({ page: String(page), per_page: String(perPage), ...filters });
    return request<any>(`/api/v1/alerts?${query.toString()}`);
  },

  async getAlertDetail(alertId: number) {
    return request<any>(`/api/v1/alerts/${alertId}`);
  },

  async escalateAlertToCase(alertId: number, data?: { case_title?: string; note?: string; apply_default_playbook?: boolean }) {
    return request<any>(`/api/v1/alerts/${alertId}/escalate`, {
      method: 'POST',
      body: JSON.stringify(data || {}),
    });
  },

  async updateAlertStatus(alertId: number, statusId: number) {
    return request<any>(`/api/v1/alerts/${alertId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status_id: statusId }),
    });
  },

  // Cases
  async listCases(stateFilter = 'all') {
    return request<any>(`/api/v1/cases?state_filter=${stateFilter}`);
  },

  async getCaseBundle(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}`);
  },

  async updateCaseStructured(caseId: number, data: Record<string, any>) {
    return request<any>(`/api/v1/cases/${caseId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async updateCaseNote(caseId: number, noteId: number, content: string, title?: string, directoryId?: number) {
    return request<any>(`/api/v1/cases/${caseId}/notes/${noteId}`, {
      method: 'PUT',
      body: JSON.stringify({
        note_content: content,
        note_title: title,
        directory_id: directoryId,
      }),
    });
  },

  async addInvestigation(caseId: number, item: { source_consulted: string; commands_or_queries?: string; results_observed: string; fact_type: string }) {
    return request<any>(`/api/v1/cases/${caseId}/investigations`, {
      method: 'POST',
      body: JSON.stringify(item),
    });
  },

  async addAction(caseId: number, item: { title: string; action_type: string; status: string; result_notes?: string; responsible?: string }) {
    return request<any>(`/api/v1/cases/${caseId}/actions`, {
      method: 'POST',
      body: JSON.stringify(item),
    });
  },

  async updateActionStatus(caseId: number, actionId: number, status: string, resultNotes?: string) {
    return request<any>(`/api/v1/cases/${caseId}/actions/${actionId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, result_notes: resultNotes }),
    });
  },

  async uploadEvidence(caseId: number, file: File, description = '') {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('description', description);
    return request<any>(`/api/v1/cases/${caseId}/evidences/upload`, {
      method: 'POST',
      body: fd,
    });
  },

  getReportPdfUrl(caseId: number, download = false): string {
    return `/api/v1/cases/${caseId}/report.pdf${download ? '?download=1' : ''}`;
  },

  // Autosave Drafts
  async getCaseDrafts(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}/drafts`);
  },

  async saveCaseDraft(caseId: number, fieldKey: string, draftContent: string) {
    return request<any>(`/api/v1/cases/${caseId}/drafts/${fieldKey}`, {
      method: 'PUT',
      body: JSON.stringify({ draft_content: draftContent }),
    });
  },

  async deleteCaseDraft(caseId: number, fieldKey: string) {
    return request<any>(`/api/v1/cases/${caseId}/drafts/${fieldKey}`, {
      method: 'DELETE',
    });
  },

  // Ingest History
  async getIngestHistory() {
    return request<any>('/api/v1/ingest/history');
  },

  // Ingestion
  async ingestText(text: string, title?: string, organization = 'NBX', createIrisAlert = true, useGemini = true) {
    return request<any>('/api/v1/ingest/text', {
      method: 'POST',
      body: JSON.stringify({ text, title, organization, create_iris_alert: createIrisAlert, use_gemini: useGemini }),
    });
  },

  async ingestUpload(file: File, organization?: string, createIrisAlert = true, useGemini = true) {
    const fd = new FormData();
    fd.append('file', file);
    if (organization) fd.append('organization', organization);
    fd.append('create_iris_alert', String(createIrisAlert));
    fd.append('use_gemini', String(useGemini));
    return request<any>('/api/v1/ingest/upload', {
      method: 'POST',
      body: fd,
    });
  },

  async loadSampleTicket(key: string) {
    return request<any>(`/api/v1/ingest/sample/${key}?create_iris_alert=false`);
  },

  // Migration
  async listMigrationCases() {
    return request<any>('/api/v1/migration/cases');
  },

  async getMigrationPreview(caseId: number, useGemini = true) {
    return request<any>(`/api/v1/migration/cases/${caseId}/preview?use_gemini=${useGemini}`);
  },

  async approveMigration(caseId: number, payload?: any) {
    return request<any>(`/api/v1/migration/cases/${caseId}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
  },

  // Admin & Connectors
  async getAdminCatalogs() {
    return request<any>('/api/v1/admin/catalogs');
  },

  async getGeminiConfig() {
    return request<any>('/api/v1/admin/gemini');
  },

  async updateGeminiConfig(data: any) {
    return request<any>('/api/v1/admin/gemini', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async testGemini() {
    return request<any>('/api/v1/admin/gemini/test', {
      method: 'POST',
    });
  },

  async getConnectors() {
    return request<any>('/api/v1/admin/connectors');
  },

  async testConnector(id: number) {
    return request<any>(`/api/v1/admin/connectors/${id}/test`, { method: 'POST' });
  },

  async updateConnector(id: number, data: any) {
    return request<any>(`/api/v1/admin/connectors/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async getUsers() {
    return request<any>('/api/v1/auth/users');
  },

  async createUser(data: any) {
    return request<any>('/api/v1/auth/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateUser(userId: number, data: any) {
    return request<any>(`/api/v1/auth/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async getAuditLogs(page = 1, perPage = 50) {
    return request<any>(`/api/v1/admin/audit-logs?page=${page}&per_page=${perPage}`);
  },

  // Floating Contextual Copilot
  async chatWithCopilot(instruction: string, context: Record<string, any> = {}) {
    return request<any>('/api/v1/admin/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ instruction, context }),
    });
  },

  // Playbook Lifecycle & Execution
  async getSuggestedPlaybooks(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/suggested`);
  },

  async getCasePlaybookExecutions(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/executions`);
  },

  async startCasePlaybook(caseId: number, playbookCode: string) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/start`, {
      method: 'POST',
      body: JSON.stringify({ playbook_code: playbookCode }),
    });
  },

  async updatePlaybookStep(
    caseId: number,
    execId: number,
    stepOrder: number,
    data: { status: string; observations?: string; create_case_action?: boolean }
  ) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/executions/${execId}/step/${stepOrder}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  async updatePlaybookExecutionStatus(caseId: number, execId: number, status: string) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/executions/${execId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  },

  async addCustomPlaybookStep(
    caseId: number,
    execId: number,
    data: { title: string; description?: string; suggested_action_type?: string; mandatory?: boolean }
  ) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/executions/${execId}/step/custom`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async omitPlaybookStep(caseId: number, execId: number, stepOrder: number, omissionReason: string) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/executions/${execId}/step/${stepOrder}/omit`, {
      method: 'PATCH',
      body: JSON.stringify({ omission_reason: omissionReason }),
    });
  },

  async linkActivityToPlaybookStep(caseId: number, execId: number, stepOrder: number, activityId: number) {
    return request<any>(`/api/v1/cases/${caseId}/playbooks/executions/${execId}/step/${stepOrder}/link-activity`, {
      method: 'POST',
      body: JSON.stringify({ activity_id: activityId }),
    });
  },

  async unlinkActivityFromPlaybookStep(caseId: number, execId: number, stepOrder: number, activityId?: number) {
    const url = `/api/v1/cases/${caseId}/playbooks/executions/${execId}/step/${stepOrder}/unlink-activity${
      activityId !== undefined ? `?activity_id=${activityId}` : ''
    }`;
    return request<any>(url, {
      method: 'POST',
    });
  },

  async deleteCaseActivity(caseId: number, activityId: number) {
    return request<any>(`/api/v1/cases/${caseId}/activity/${activityId}`, {
      method: 'DELETE',
    });
  },

  async bulkDeleteCaseActivity(caseId: number, activityIds: number[]) {
    return request<any>(`/api/v1/cases/${caseId}/activity/bulk-delete`, {
      method: 'POST',
      body: JSON.stringify({ activity_ids: activityIds }),
    });
  },

  async getCaseIocs(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}/iocs`);
  },

  async addCaseIoc(caseId: number, payload: { ioc_value: string; ioc_type?: string; ioc_description?: string; ioc_tags?: string }) {
    return request<any>(`/api/v1/cases/${caseId}/iocs`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async deleteCaseIoc(caseId: number, iocId: number) {
    return request<any>(`/api/v1/cases/${caseId}/iocs/${iocId}`, {
      method: 'DELETE',
    });
  },

  async generateCaseTimelineAi(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}/timeline/generate-ai`, {
      method: 'POST',
    });
  },

  async deleteCaseAction(caseId: number, actionId: number) {
    return request<any>(`/api/v1/cases/${caseId}/actions/${actionId}`, {
      method: 'DELETE',
    });
  },

  async testGDriveConnection(payload: { folder_id?: string; service_account_json: string }) {
    return request<any>('/api/v1/retention/config/test-gdrive', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Bitácora Operativa Unificada & Sincronización IRIS
  async getCaseActivity(
    caseId: number,
    params?: { activity_type?: string; step_order?: number; playbook_execution_id?: number }
  ) {
    const q = new URLSearchParams();
    if (params?.activity_type) q.append('activity_type', params.activity_type);
    if (params?.step_order !== undefined) q.append('step_order', String(params.step_order));
    if (params?.playbook_execution_id !== undefined) q.append('playbook_execution_id', String(params.playbook_execution_id));
    return request<any>(`/api/v1/cases/${caseId}/activity?${q.toString()}`);
  },

  async addCaseActivity(
    caseId: number,
    data: {
      activity_type: string;
      title: string;
      content?: string;
      metadata_json?: any;
      action_status?: string;
      playbook_execution_id?: number;
      step_order?: number;
      sync_to_iris?: boolean;
    }
  ) {
    return request<any>(`/api/v1/cases/${caseId}/activity`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async uploadCaseActivityEvidence(
    caseId: number,
    data: {
      file?: File;
      base64_data?: string;
      filename?: string;
      title?: string;
      description?: string;
      step_order?: number;
      playbook_execution_id?: number;
    }
  ) {
    const fd = new FormData();
    if (data.file) fd.append('file', data.file);
    if (data.base64_data) fd.append('base64_data', data.base64_data);
    if (data.filename) fd.append('filename', data.filename);
    if (data.title) fd.append('title', data.title);
    if (data.description) fd.append('description', data.description);
    if (data.step_order !== undefined) fd.append('step_order', String(data.step_order));
    if (data.playbook_execution_id !== undefined) fd.append('playbook_execution_id', String(data.playbook_execution_id));

    return request<any>(`/api/v1/cases/${caseId}/activity/evidence`, {
      method: 'POST',
      body: fd,
    });
  },

  async updateCaseActivity(
    caseId: number,
    activityId: number,
    data: { title?: string; content?: string; action_status?: string; metadata_json?: any }
  ) {
    return request<any>(`/api/v1/cases/${caseId}/activity/${activityId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  async compileMarkdownNotesFromActivity(caseId: number) {
    return request<any>(`/api/v1/cases/${caseId}/compile-markdown-notes`, {
      method: 'POST',
    });
  },

  // Retention & Datastore Capacity
  async getRetentionSummary() {
    return request<any>('/api/v1/retention/summary');
  },

  async createCaseBackup(caseId: number, backupType = 'local') {
    return request<any>(`/api/v1/retention/cases/${caseId}/backup`, {
      method: 'POST',
      body: JSON.stringify({ backup_type: backupType }),
    });
  },

  async pruneCaseBinaries(caseId: number, confirmation = 'CONFIRMAR') {
    return request<any>(`/api/v1/retention/cases/${caseId}/prune-binaries`, {
      method: 'POST',
      body: JSON.stringify({ confirmation }),
    });
  },

  async getRetentionConfig() {
    return request<any>('/api/v1/retention/config');
  },

  async saveRetentionConfig(data: Record<string, any>) {
    return request<any>('/api/v1/retention/config', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async testFtpConnection(data: Record<string, any>) {
    return request<any>('/api/v1/retention/config/test-ftp', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async testGitHubConnection(data: Record<string, any>) {
    return request<any>('/api/v1/retention/config/test-github', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async startBulkRotation(data: { scope: string; action: string; min_age_days?: number }) {
    return request<any>('/api/v1/retention/jobs/bulk-rotation', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getRetentionJob(jobId: string) {
    return request<any>(`/api/v1/retention/jobs/${jobId}`);
  },

  async listRetentionJobs() {
    return request<any>('/api/v1/retention/jobs');
  },


  async createPlaybookTemplate(data: any) {
    return request<any>('/api/v1/admin/playbooks', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updatePlaybookTemplate(code: string, data: any) {
    return request<any>(`/api/v1/admin/playbooks/${code}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  // Blacklist Master Operativo
  async checkBlacklist(target: string, serverName?: string, organization = 'NBX', recordEpisode = false) {
    return request<any>('/api/v1/blacklist/check', {
      method: 'POST',
      body: JSON.stringify({
        target,
        server_name: serverName,
        organization,
        record_episode: recordEpisode,
      }),
    });
  },

  async getBlacklistEpisodes(params?: { status?: string; organization?: string; search?: string; limit?: number; offset?: number }) {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.organization) q.append('organization', params.organization);
    if (params?.search) q.append('search', params.search);
    if (params?.limit) q.append('limit', String(params.limit));
    if (params?.offset) q.append('offset', String(params.offset));
    return request<any>(`/api/v1/blacklist/episodes?${q.toString()}`);
  },

  async registerDelisting(episodeId: number, delistingReference?: string, notes?: string) {
    return request<any>('/api/v1/blacklist/delisting', {
      method: 'POST',
      body: JSON.stringify({
        episode_id: episodeId,
        delisting_reference: delistingReference,
        notes,
      }),
    });
  },

  async linkBlacklistEpisode(episodeId: number, caseId: number) {
    return request<any>(`/api/v1/blacklist/episodes/${episodeId}/link-case`, {
      method: 'POST',
      body: JSON.stringify({ case_id: caseId }),
    });
  },

  async getBlacklistStats() {
    return request<any>('/api/v1/blacklist/stats');
  },

  // Monitored IPs (Blacklist Master Monitoring System)
  async getMonitoredIps(params?: { organization?: string; status?: string; last_status?: string; search?: string; limit?: number; offset?: number }) {
    const q = new URLSearchParams();
    if (params?.organization) q.append('organization', params.organization);
    if (params?.status) q.append('status', params.status);
    if (params?.last_status) q.append('last_status', params.last_status);
    if (params?.search) q.append('search', params.search);
    if (params?.limit) q.append('limit', String(params.limit));
    if (params?.offset) q.append('offset', String(params.offset));
    return request<any>(`/api/v1/blacklist/monitored-ips?${q.toString()}`);
  },

  async createMonitoredIp(data: { ip_address: string; organization?: string; server_name?: string; description?: string; check_interval_minutes?: number }) {
    return request<any>('/api/v1/blacklist/monitored-ips', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async bulkCreateMonitoredIps(data: { raw_text: string; organization?: string; server_name?: string; description?: string; check_interval_minutes?: number }) {
    return request<any>('/api/v1/blacklist/monitored-ips/bulk', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateMonitoredIp(ipId: number, data: { server_name?: string; description?: string; status?: string; check_interval_minutes?: number }) {
    return request<any>(`/api/v1/blacklist/monitored-ips/${ipId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  async deleteMonitoredIp(ipId: number) {
    return request<any>(`/api/v1/blacklist/monitored-ips/${ipId}`, {
      method: 'DELETE',
    });
  },

  async checkMonitoredIp(ipId: number) {
    return request<any>(`/api/v1/blacklist/monitored-ips/${ipId}/check`, {
      method: 'POST',
    });
  },

  async runAllMonitoredChecks(forceAll = false) {
    return request<any>(`/api/v1/blacklist/monitored-ips/run-checks?force_all=${forceAll}`, {
      method: 'POST',
    });
  },

  // Alert Correlation & Management
  async getCompatibleCasesForAlert(alertId: number, search?: string) {
    const q = new URLSearchParams();
    if (search) q.append('search', search);
    return request<any>(`/api/v1/alerts/${alertId}/compatible-cases?${q.toString()}`);
  },

  async bulkMergeAlerts(data: { alert_ids: number[]; target_case_id: number; note?: string }) {
    return request<any>('/api/v1/alerts/bulk/merge', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async bulkDiscardAlerts(data: { alert_ids: number[]; discard_reason: string; verification_state?: string }) {
    return request<any>('/api/v1/alerts/bulk/discard', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async unlinkAlert(alertId: number) {
    return request<any>(`/api/v1/alerts/${alertId}/unlink`, {
      method: 'POST',
    });
  },

  async reopenAlert(alertId: number) {
    return request<any>(`/api/v1/alerts/${alertId}/reopen`, {
      method: 'POST',
    });
  },

  async deleteAlertPermanently(alertId: number, justification: string) {
    return request<any>(`/api/v1/alerts/${alertId}`, {
      method: 'DELETE',
      body: JSON.stringify({ justification }),
    });
  },

  // Case States (DFIR-IRIS)
  async getCaseStatesCatalog() {
    return request<any>('/api/v1/cases/states/catalog');
  },

  async updateCaseState(caseId: number, stateId: number) {
    return request<any>(`/api/v1/cases/${caseId}/state`, {
      method: 'PATCH',
      body: JSON.stringify({ state_id: stateId }),
    });
  },

  // Gemini Models
  async getGeminiModels() {
    return request<any>('/api/v1/admin/gemini/models');
  },
};

