export type Organization = 'NBX' | 'HP';

export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: 'admin' | 'supervisor' | 'analyst' | 'readonly';
  allowed_orgs: Organization[];
  iris_user_id?: number;
  is_active: boolean;
}

export interface DashboardSummary {
  iris: {
    status: 'online' | 'offline';
    instance: string;
    version?: string;
  };
  alerts: {
    total: number;
    pending: number;
    escalated: number;
    merged: number;
    closed: number;
    by_severity: Record<string, number>;
  };
  cases: {
    open: number;
    in_progress: number;
    closed: number;
    by_org: Record<Organization, number>;
    by_category: Record<string, number>;
  };
  active_episodes_count?: number;
}

export type ActionStatus =
  | 'propuesta'
  | 'autorizada'
  | 'pendiente'
  | 'en_ejecucion'
  | 'ejecutada'
  | 'verificada'
  | 'cancelada'
  | 'no_aplicable';

export interface CaseAction {
  id?: number;
  iris_case_id?: number;
  title: string;
  action_type: string;
  status: ActionStatus;
  responsible?: string;
  result_notes?: string;
  provenance?: string;
  executed_at?: string;
}

export interface InvestigationItem {
  id?: number;
  iris_case_id?: number;
  source_consulted: string;
  commands_or_queries?: string;
  results_observed: string;
  fact_type: 'reported_claim' | 'confirmed_fact' | 'technical_indicator' | 'hypothesis';
  provenance?: string;
  analyst_username?: string;
  executed_at?: string;
}

export interface FindingItem {
  id?: number;
  iris_case_id?: number;
  title: string;
  finding_nature?: string;
  verification_state?: string;
  severity?: string;
  description?: string;
}

export interface CaseExtension {
  iris_case_id: number;
  organization: Organization;
  customer_id: number;
  abuse_ticket_id?: string;
  holder_ticket_id?: string;
  client_id?: string;
  service_id?: string;
  domain_id?: string;
  service_plan?: string;
  primary_domain?: string;
  server_name?: string;
  hosting_ip?: string;
  reported_ip?: string;
  impersonated_brand?: string;
  reporter_name?: string;
  reporter_type?: string;
  category_code: string;
  reported_activity?: string;
  confirmed_incident_type?: string;
  entry_vector?: string;
  root_cause?: string;
  verification_state?: string;
  severity?: string;
  is_technical_compromise?: boolean;
  playbook_code?: string;
  schema_version?: string;
  field_provenance_json?: Record<string, string>;
  resolution_data_json?: Record<string, any>;
  closure_checklist_json?: Record<string, any>;
}

export interface AdminLinkAction {
  key: string;
  label: string;
  system: string;
  url: string;
  id_value: string;
}

export interface AdminLinksBundle {
  organization: Organization;
  organization_name: string;
  helpdesk_system: string;
  billing_system: string;
  actions: AdminLinkAction[];
  abuse_ticket_url?: string;
  holder_ticket_url?: string;
  client_summary_url?: string;
  hosting_service_url?: string;
  registered_domain_url?: string;
  iris_official_url?: string;
}

export interface PlaybookStepState {
  order: number;
  title: string;
  description: string;
  mandatory: boolean;
  status: 'pendiente' | 'en_progreso' | 'completado' | 'omitido' | 'bloqueado';
  observations?: string;
  suggested_action_type?: string;
  updated_by?: string;
  updated_at?: string;
  case_action_id?: number;
  is_custom?: boolean;
  linked_activity_id?: number;
}

export interface PlaybookExecutionRecord {
  id: number;
  playbook_code: string;
  playbook_name: string;
  playbook_version: string;
  status: 'in_progress' | 'completed' | 'suspended' | 'cancelled';
  started_by: string;
  started_at: string;
  completed_at?: string;
  steps_state: PlaybookStepState[];
}

export interface CaseBundle {
  iris_case: {
    case_id: number;
    case_name: string;
    case_description?: string;
    state_id?: number;
    state_name?: string;
    open_date?: string;
    close_date?: string;
    owner?: string;
    notes?: Array<{
      note_id: number;
      note_title: string;
      note_content: string;
      directory_name?: string;
    }>;
    iocs?: Array<{
      ioc_id: number;
      ioc_value: string;
      ioc_type: string;
      ioc_description?: string;
      ioc_tags?: string;
    }>;
    evidences?: Array<{
      id: number;
      filename: string;
      file_size: number;
      file_hash?: string;
      file_description?: string;
    }>;
    tasks?: Array<{
      task_id: number;
      task_title: string;
      task_status_id?: number;
    }>;
    timeline?: any[];
  };
  extension: CaseExtension;
  admin_links?: AdminLinksBundle;
  investigations: InvestigationItem[];
  findings: FindingItem[];
  actions: CaseAction[];
  communications: any[];
  playbooks?: any[];
  playbook_executions?: PlaybookExecutionRecord[];
  evidences?: any[];
}

export interface AlertItem {
  alert_id: number;
  alert_title: string;
  alert_description?: string;
  alert_status_id: number;
  alert_status_name: string;
  alert_severity_id: number;
  alert_severity_name: string;
  alert_customer_id: number;
  created_at: string;
  source?: string;
  source_ref?: string;
  category_code?: string;
  organization: Organization;
  primary_domain?: string;
  reported_ip?: string;
  hosting_ip?: string;
  server_name?: string;
  verification_state?: string;
  observation_count?: number;
  escalated_case_id?: number;
  escalated_case_name?: string;
}

export interface IngestResponse {
  status: string;
  ingest_event_id: number;
  iris_alert_id?: number;
  alert_title?: string;
  organization: Organization;
  evidence_package: {
    primary_sha256: string;
    primary_filename: string;
    package_dir: string;
  };
  normalized: {
    abuse_ticket_id?: string;
    holder_ticket_id?: string;
    client_id?: string;
    service_id?: string;
    primary_domain?: string;
    server_name?: string;
    hosting_ip?: string;
    reported_ip?: string;
    impersonated_brand?: string;
    report_summary?: string;
    indicators?: any[];
  };
  heuristics: {
    category_code: string;
    category_name: string;
    reported_activity: string;
    confirmed_incident_type: string;
    entry_vector: string;
    root_cause: string;
    is_technical_compromise: boolean;
    verification_state: string;
    severity: string;
    confidence_score: number;
  };
  gemini?: {
    ai_used: boolean;
    analysis?: any;
  };
}

export interface MigrationCaseRecord {
  case_id: number;
  case_name: string;
  organization: Organization;
  state_name: string;
  open_date?: string;
  migration_status: 'pending' | 'preview_ready' | 'migrated' | 'error';
  schema_version: string;
  snapshot_taken: boolean;
  snapshot_sha256?: string;
}

export interface MonitoredIp {
  id: number;
  ip_address: string;
  organization: Organization;
  server_name?: string;
  description?: string;
  status: 'active' | 'paused';
  last_status: 'clean' | 'listed' | 'error' | 'pending';
  listed_providers: string[];
  listed_count: number;
  last_checked_at?: string;
  next_check_at?: string;
  check_interval_minutes: number;
  last_alert_id?: number;
  last_case_id?: number;
  created_at?: string;
}

export interface CaseState {
  state_id: number;
  state_name: string;
  state_description?: string;
  protected?: boolean;
}

export interface GeminiModelInfo {
  id: string;
  display_name: string;
  description?: string;
  recommended: boolean;
  status: string;
  input_token_limit?: number;
  output_token_limit?: number;
}
