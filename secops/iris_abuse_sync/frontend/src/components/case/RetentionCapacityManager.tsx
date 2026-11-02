import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import {
  Database,
  HardDrive,
  Download,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Archive,
  ShieldCheck,
  FileCheck,
  Clock,
  X,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Settings,
  Server,
  Play,
  Check,
  FolderArchive,
  GitBranch
} from 'lucide-react';
import { api } from '../../api/client';
import { Button } from '../common/Button';
import { Badge } from '../common/Badge';

export const RetentionCapacityManager: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState<any>(null);
  const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);

  // Search, Filter & Pagination
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'candidates' | 'has_backup' | 'pruned'>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  // Prune Confirmation Modal
  const [pruningCase, setPruningCase] = useState<any | null>(null);
  const [confirmInput, setConfirmInput] = useState('');
  const [pruningLoading, setPruningLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Config Destination Modal
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [retentionConfig, setRetentionConfig] = useState<any>({
    destination: 'local',
    local_path: 'storage/backups',
    ftp: {
      host: '',
      port: 21,
      username: '',
      password: '',
      remote_path: '/backups/soc_iris',
      use_tls: false,
    },
    schedule: {
      enabled: true,
      time_utc: '03:00',
      prune_binaries_after_days: 90,
      archive_cases_after_days: 365,
      auto_prune_closed_cases: true,
    },
  });
  const [savingConfig, setSavingConfig] = useState(false);
  const [testingFtp, setTestingFtp] = useState(false);
  const [ftpTestResult, setFtpTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testingGDrive, setTestingGDrive] = useState(false);
  const [gdriveTestResult, setGDriveTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

  // Bulk Rotation Modal & Background Job
  const [showRotationModal, setShowRotationModal] = useState(false);
  const [rotationScope, setRotationScope] = useState<'all' | 'closed_only' | 'age_days'>('all');
  const [rotationAction, setRotationAction] = useState<'backup_only' | 'backup_and_prune'>('backup_only');
  const [rotationMinAge, setRotationMinAge] = useState(90);
  const [activeJob, setActiveJob] = useState<any | null>(null);
  const [startingJob, setStartingJob] = useState(false);

  const loadSummary = async () => {
    setLoading(true);
    setStatusMessage(null);
    try {
      const res = await api.getRetentionSummary();
      setSummary(res);
      if (res.config) setRetentionConfig(res.config);
    } catch (err: any) {
      console.error('Error cargando métricas de retención:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, []);

  // Poll background job if running
  useEffect(() => {
    if (!activeJob || activeJob.status === 'completed' || activeJob.status === 'failed') return;

    const interval = setInterval(async () => {
      try {
        const res = await api.getRetentionJob(activeJob.job_id);
        if (res.job) {
          setActiveJob(res.job);
          if (res.job.status === 'completed') {
            setStatusMessage(`Tarea masiva completada: ${res.job.message}`);
            await loadSummary();
          }
        }
      } catch (err) {
        console.error(err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeJob]);

  const handleCreateBackup = async (caseId: number) => {
    setActionLoadingId(caseId);
    setStatusMessage(null);
    try {
      const res = await api.createCaseBackup(caseId, retentionConfig.destination || 'local');
      setStatusMessage(`Respaldo .tar.gz generado exitosamente para Caso #${caseId} (SHA256: ${res.backup_sha256?.substring(0, 16)}...).`);
      await loadSummary();
    } catch (err: any) {
      alert('Error generando respaldo: ' + err.message);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleExecutePrune = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pruningCase || confirmInput.trim().toUpperCase() !== 'CONFIRMAR') return;

    setPruningLoading(true);
    try {
      const res = await api.pruneCaseBinaries(pruningCase.case_id, 'CONFIRMAR');
      setPruningCase(null);
      setConfirmInput('');
      setStatusMessage(`Purgado exitoso en Caso #${res.case_id}: ${res.deleted_count} binarios eliminados (${res.freed_bytes_human} liberados). Metadatos y hashes SHA-256 preservados.`);
      await loadSummary();
    } catch (err: any) {
      alert('Error en purgado forense: ' + err.message);
    } finally {
      setPruningLoading(false);
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingConfig(true);
    try {
      await api.saveRetentionConfig(retentionConfig);
      setShowConfigModal(false);
      setStatusMessage('Configuración de destino de respaldos guardada exitosamente.');
    } catch (err: any) {
      alert('Error guardando configuración: ' + err.message);
    } finally {
      setSavingConfig(false);
    }
  };

  const handleTestFtp = async () => {
    setTestingFtp(true);
    setFtpTestResult(null);
    try {
      const res = await api.testFtpConnection(retentionConfig.ftp || {});
      setFtpTestResult({ ok: true, msg: res.message || 'Conexión FTP exitosa.' });
    } catch (err: any) {
      setFtpTestResult({ ok: false, msg: err.message || 'Fallo de conexión FTP.' });
    } finally {
      setTestingFtp(false);
    }
  };

  const handleTestGDrive = async () => {
    setTestingGDrive(true);
    setGDriveTestResult(null);
    try {
      const res = await api.testGDriveConnection({
        folder_id: retentionConfig.gdrive?.folder_id,
        service_account_json: retentionConfig.gdrive?.service_account_json || '',
      });
      setGDriveTestResult({ ok: true, msg: res.message || 'Conexión a Google Drive exitosa.' });
    } catch (err: any) {
      setGDriveTestResult({ ok: false, msg: err.message || 'Fallo de autenticación con Google Drive.' });
    } finally {
      setTestingGDrive(false);
    }
  };

  const [testingGitHub, setTestingGitHub] = useState(false);
  const [githubTestResult, setGithubTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const handleTestGitHub = async () => {
    const token = retentionConfig.github?.token;
    const repo = retentionConfig.github?.repo;
    if (!token || !repo) {
      alert('Por favor introduce el Token de GitHub y el Repositorio (owner/repo).');
      return;
    }
    setTestingGitHub(true);
    setGithubTestResult(null);
    try {
      const res = await api.testGitHubConnection({ token, repo });
      setGithubTestResult({
        ok: true,
        msg: `✓ Conexión exitosa con ${res.repo_name} (${res.is_private ? 'Privado' : 'Público'}) — Rama: ${res.default_branch}`,
      });
    } catch (err: any) {
      setGithubTestResult({ ok: false, msg: `✗ Fallo de autenticación: ${err.message}` });
    } finally {
      setTestingGitHub(false);
    }
  };

  const handleStartBulkRotation = async () => {
    setStartingJob(true);
    try {
      const res = await api.startBulkRotation({
        scope: rotationScope,
        action: rotationAction,
        min_age_days: rotationMinAge,
      });
      setShowRotationModal(false);
      setActiveJob(res.job);
      setStatusMessage(`Tarea de rotación #${res.job_id} iniciada en segundo plano.`);
    } catch (err: any) {
      alert('Error iniciando rotación masiva: ' + err.message);
    } finally {
      setStartingJob(false);
    }
  };

  const casesList = summary?.all_cases || [];

  // Filter cases
  const filteredCases = casesList.filter((c: any) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesQuery =
      !q ||
      String(c.case_id).includes(q) ||
      (c.case_name || '').toLowerCase().includes(q) ||
      (c.state_name || '').toLowerCase().includes(q);

    if (!matchesQuery) return false;

    if (filterType === 'candidates') return c.is_candidate && c.archive_status !== 'pruned';
    if (filterType === 'has_backup') return c.archive_status === 'exported' || c.archive_status === 'pruned';
    if (filterType === 'pruned') return c.archive_status === 'pruned';
    return true;
  });

  // Pagination
  const totalPages = Math.ceil(filteredCases.length / pageSize) || 1;
  const paginatedCases = filteredCases.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-indigo-500" />
            <h3 className="text-sm font-bold text-text-primary">Gestión de Capacidad y Retención Forense</h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 font-semibold">
              DFIR-IRIS v2.4.29 Datastore
            </span>
          </div>
          <p className="text-xs text-text-muted mt-1">
            Respaldos <code className="font-mono text-text-primary">.tar.gz</code> completos con manifiesto, hashes SHA-256 inmutables y purgado seguro de binarios pesados.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setShowConfigModal(true)}
            icon={<Settings className="w-3.5 h-3.5" />}
          >
            Destino & Horario
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowRotationModal(true)}
            icon={<FolderArchive className="w-3.5 h-3.5" />}
          >
            Rotación Masiva
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={loadSummary}
            loading={loading}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Actualizar
          </Button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>{statusMessage}</span>
        </div>
      )}

      {/* Active Background Job Card */}
      {activeJob && (
        <div className="p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/30 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 font-bold text-indigo-400">
              <RefreshCw className="w-4 h-4 animate-spin" />
              <span>Tarea en Segundo Plano: #{activeJob.job_id}</span>
              <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300">
                {activeJob.status}
              </span>
            </div>
            <span className="font-mono font-bold text-indigo-400">{activeJob.progress_pct}%</span>
          </div>

          <div className="w-full h-2 rounded-full bg-surface-root overflow-hidden border border-border-subtle">
            <div
              className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-300"
              style={{ width: `${activeJob.progress_pct}%` }}
            />
          </div>

          <p className="text-[11px] text-text-muted font-mono">{activeJob.message}</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-1">
          <span className="text-xs text-text-muted font-medium">Consumo Total Datastore</span>
          <div className="text-lg font-bold text-text-primary font-mono">{summary?.total_bytes_human || '0 B'}</div>
          <span className="text-[11px] text-text-muted">{summary?.total_evidences || 0} archivos binarios</span>
        </div>

        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-1">
          <span className="text-xs text-text-muted font-medium">Casos Analizados</span>
          <div className="text-lg font-bold text-indigo-400 font-mono">{summary?.total_cases_analyzed || 0}</div>
          <span className="text-[11px] text-text-muted">Expedientes en DFIR-IRIS</span>
        </div>

        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-1">
          <span className="text-xs text-text-muted font-medium">Candidatos a Purgado</span>
          <div className="text-lg font-bold text-amber-500 font-mono">{summary?.candidates?.length || 0}</div>
          <span className="text-[11px] text-text-muted">Cerrados o antigüedad &gt; 90d</span>
        </div>

        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-1">
          <span className="text-xs text-text-muted font-medium">Destino de Respaldo</span>
          <div className="text-xs font-bold text-emerald-400 uppercase font-mono">
            {retentionConfig?.destination || 'LOCAL'}
          </div>
          <span className="text-[10px] text-text-muted">Cron nocturno 03:00 AM UTC</span>
        </div>
      </div>

      {/* Cases Table with Search, Filter and Pagination */}
      <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-3">
          <div>
            <h4 className="text-xs font-bold text-text-primary">
              Control de Expedientes y Retención ({filteredCases.length})
            </h4>
            <span className="text-[11px] text-text-muted">Todos los casos pueden respaldarse independientemente de su tamaño</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-text-muted absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Buscar caso por ID o nombre..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                className="text-xs pl-8 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500 w-52"
              />
            </div>

            {/* Filter Dropdown */}
            <select
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as any);
                setCurrentPage(1);
              }}
              className="text-xs px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500 font-medium"
            >
              <option value="all">Todos los Casos</option>
              <option value="candidates">Candidatos a Purgado</option>
              <option value="has_backup">Con Respaldo Verificado</option>
              <option value="pruned">Binarios Purgados</option>
            </select>
          </div>
        </div>

        <div className="border border-border-subtle rounded-xl overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-surface-root border-b border-border-subtle text-[11px] text-text-muted font-semibold">
                <th className="py-2.5 px-3">Caso</th>
                <th className="py-2.5 px-3">Estado</th>
                <th className="py-2.5 px-3">Antigüedad</th>
                <th className="py-2.5 px-3">Evidencias</th>
                <th className="py-2.5 px-3">Tamaño Datastore</th>
                <th className="py-2.5 px-3">Estado Retención</th>
                <th className="py-2.5 px-3 text-right">Acciones de Respaldo</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle font-sans">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-xs text-text-muted">
                    Calculando consumo de Datastore en DFIR-IRIS...
                  </td>
                </tr>
              ) : paginatedCases.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-xs text-text-muted">
                    No se encontraron casos con los criterios de búsqueda.
                  </td>
                </tr>
              ) : (
                paginatedCases.map((c: any) => {
                  const isActionLoading = actionLoadingId === c.case_id;
                  const hasBackup = c.archive_status === 'exported' || c.archive_status === 'pruned';
                  const isPruned = c.archive_status === 'pruned';

                  return (
                    <tr key={c.case_id} className="hover:bg-surface-elevated/40 transition-colors">
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-text-primary">#{c.case_id}</div>
                        <div className="text-[11px] text-text-muted line-clamp-1">{c.case_name}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border uppercase ${
                          c.is_closed
                            ? 'bg-slate-500/10 text-slate-400 border-slate-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                        }`}>
                          {c.state_name}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-text-secondary">
                        {c.age_days} días
                      </td>
                      <td className="py-2.5 px-3 font-mono text-text-primary">
                        {c.evidence_count}
                      </td>
                      <td className="py-2.5 px-3 font-mono font-semibold text-text-primary">
                        {c.total_bytes_human}
                      </td>
                      <td className="py-2.5 px-3">
                        {isPruned ? (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30 font-bold">
                            Binarios Purgados
                          </span>
                        ) : hasBackup ? (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-bold">
                            Respaldo Verificado
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-root text-text-muted border border-border-subtle">
                            Activo en Datastore
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleCreateBackup(c.case_id)}
                            disabled={isActionLoading}
                            className="px-2.5 py-1 text-xs font-medium rounded border border-border-subtle bg-surface-root hover:bg-surface-elevated text-text-primary disabled:opacity-40 transition-colors flex items-center gap-1"
                            title="Generar respaldo tar.gz completo con manifiesto y notas"
                          >
                            <Archive className="w-3 h-3 text-indigo-400" />
                            {hasBackup ? 'Actualizar .tar.gz' : 'Respaldar .tar.gz'}
                          </button>

                          {hasBackup && c.backup_path && (
                            <a
                              href={`/api/v1/retention/download/${c.backup_path.split('/').pop()}`}
                              download
                              className="px-2 py-1 text-xs font-medium rounded border border-border-subtle bg-surface-root hover:bg-surface-elevated text-emerald-400 transition-colors"
                              title="Descargar archivo .tar.gz"
                            >
                              <Download className="w-3 h-3" />
                            </a>
                          )}

                          {hasBackup && !isPruned && c.evidence_count > 0 && (
                            <button
                              type="button"
                              onClick={() => {
                                setPruningCase(c);
                                setConfirmInput('');
                              }}
                              className="px-2.5 py-1 text-xs font-semibold rounded border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 transition-colors flex items-center gap-1"
                              title="Purgar binarios pesados del Datastore (conservando metadatos y hashes)"
                            >
                              <Trash2 className="w-3 h-3" />
                              Purgar
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between pt-3 border-t border-border-subtle text-xs text-text-muted">
            <span>
              Página {currentPage} de {totalPages} ({filteredCases.length} casos)
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="secondary"
                size="sm"
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
                icon={<ChevronLeft className="w-3.5 h-3.5" />}
              >
                Anterior
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
                icon={<ChevronRight className="w-3.5 h-3.5" />}
              >
                Siguiente
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Modal: Destination & Schedule Config */}
      {showConfigModal && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-border-subtle rounded-2xl p-6 w-full max-w-lg shadow-xl space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <Settings className="w-4 h-4 text-indigo-500" />
                Configurar Destino de Respaldo & Política Automática
              </h3>
              <button onClick={() => setShowConfigModal(false)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveConfig} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-text-secondary block mb-1">Destino Principal de Respaldo</label>
                <select
                  value={retentionConfig.destination || 'local'}
                  onChange={(e) => setRetentionConfig({ ...retentionConfig, destination: e.target.value })}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500 font-semibold"
                >
                  <option value="local">Almacenamiento Local (storage/backups)</option>
                  <option value="ftp">Servidor FTP / SFTP Remoto</option>
                  <option value="gdrive">Google Drive</option>
                  <option value="github">Repositorio GitHub (Público o Privado)</option>
                </select>
              </div>

              {retentionConfig.destination === 'ftp' && (
                <div className="p-4 rounded-xl bg-surface-root border border-border-subtle space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                      <Server className="w-4 h-4 text-indigo-400" />
                      Parámetros FTP / SFTP
                    </span>
                    <button
                      type="button"
                      onClick={handleTestFtp}
                      disabled={testingFtp}
                      className="text-[11px] text-indigo-400 hover:underline flex items-center gap-1"
                    >
                      {testingFtp ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
                      Probar Conexión
                    </button>
                  </div>

                  {ftpTestResult && (
                    <div
                      className={`p-2 rounded text-[11px] ${
                        ftpTestResult.ok
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {ftpTestResult.msg}
                    </div>
                  )}

                  <div className="grid grid-cols-3 gap-2">
                    <div className="col-span-2">
                      <input
                        type="text"
                        placeholder="Host FTP (ej. backups.neubox.com)"
                        value={retentionConfig.ftp?.host || ''}
                        onChange={(e) =>
                          setRetentionConfig({
                            ...retentionConfig,
                            ftp: { ...retentionConfig.ftp, host: e.target.value },
                          })
                        }
                        className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary"
                      />
                    </div>
                    <div>
                      <input
                        type="number"
                        placeholder="Puerto (21)"
                        value={retentionConfig.ftp?.port || 21}
                        onChange={(e) =>
                          setRetentionConfig({
                            ...retentionConfig,
                            ftp: { ...retentionConfig.ftp, port: Number(e.target.value) },
                          })
                        }
                        className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      placeholder="Usuario FTP"
                      value={retentionConfig.ftp?.username || ''}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          ftp: { ...retentionConfig.ftp, username: e.target.value },
                        })
                      }
                      className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary"
                    />
                    <input
                      type="password"
                      placeholder="Contraseña"
                      value={retentionConfig.ftp?.password || ''}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          ftp: { ...retentionConfig.ftp, password: e.target.value },
                        })
                      }
                      className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary"
                    />
                  </div>

                  <input
                    type="text"
                    placeholder="Ruta Remota (ej. /backups/soc_iris)"
                    value={retentionConfig.ftp?.remote_path || ''}
                    onChange={(e) =>
                      setRetentionConfig({
                        ...retentionConfig,
                        ftp: { ...retentionConfig.ftp, remote_path: e.target.value },
                      })
                    }
                    className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary"
                  />
                </div>
              )}

              {retentionConfig.destination === 'gdrive' && (
                <div className="p-4 rounded-xl bg-surface-root border border-border-subtle space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                      <HardDrive className="w-4 h-4 text-emerald-400" />
                      Parámetros Google Drive (Service Account)
                    </span>
                    <button
                      type="button"
                      onClick={handleTestGDrive}
                      disabled={testingGDrive}
                      className="text-[11px] text-emerald-400 hover:underline flex items-center gap-1 cursor-pointer"
                    >
                      {testingGDrive ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
                      Probar Conexión Drive
                    </button>
                  </div>

                  {gdriveTestResult && (
                    <div
                      className={`p-2 rounded text-[11px] ${
                        gdriveTestResult.ok
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {gdriveTestResult.msg}
                    </div>
                  )}

                  <div>
                    <label className="text-[11px] text-text-muted block mb-1">
                      ID de Carpeta Destino (Google Drive Folder ID)
                    </label>
                    <input
                      type="text"
                      placeholder="ej. 1B2M3K4L5P6Q7R8S9T0U (Opcional, si se omite guarda en la raíz)"
                      value={retentionConfig.gdrive?.folder_id || ''}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          gdrive: { ...retentionConfig.gdrive, folder_id: e.target.value },
                        })
                      }
                      className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] text-text-muted block mb-1">
                      Credenciales de Service Account (JSON) *
                    </label>
                    <textarea
                      rows={5}
                      placeholder='Pega aquí el contenido JSON completo de la clave de Service Account de Google Cloud:
{
  "type": "service_account",
  "project_id": "...",
  "client_email": "soc-backup@...iam.gserviceaccount.com",
  ...
}'
                      value={retentionConfig.gdrive?.service_account_json || ''}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          gdrive: { ...retentionConfig.gdrive, service_account_json: e.target.value },
                        })
                      }
                      className="w-full text-xs p-2.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono text-[10px]"
                    />
                    <p className="text-[10px] text-text-muted mt-1 leading-relaxed">
                      💡 <b>Configuración Google Cloud</b>: En Google Cloud Console habilita <b>Google Drive API</b>, crea una Service Account, genera su clave JSON y comparte la carpeta de Drive con el correo de la cuenta con rol de <i>Editor</i>.
                    </p>
                  </div>
                </div>
              )}

              {retentionConfig.destination === 'github' && (
                <div className="p-4 rounded-xl bg-surface-root border border-border-subtle space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                      <GitBranch className="w-4 h-4 text-purple-400" />
                      Parámetros GitHub (Personal Access Token)
                    </span>
                    <button
                      type="button"
                      onClick={handleTestGitHub}
                      disabled={testingGitHub}
                      className="text-[11px] text-purple-400 hover:underline flex items-center gap-1 cursor-pointer"
                    >
                      {testingGitHub ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
                      Probar Conexión GitHub
                    </button>
                  </div>

                  {githubTestResult && (
                    <div
                      className={`p-2 rounded text-[11px] ${
                        githubTestResult.ok
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {githubTestResult.msg}
                    </div>
                  )}

                  <div>
                    <label className="text-[11px] text-text-muted block mb-1">
                      Personal Access Token (PAT) *
                    </label>
                    <input
                      type="password"
                      placeholder="ghp_... o github_pat_... con permisos de escritura 'repo'"
                      value={retentionConfig.github?.token || ''}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          github: { ...retentionConfig.github, token: e.target.value },
                        })
                      }
                      className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] text-text-muted block mb-1">
                        Repositorio (owner/repo) *
                      </label>
                      <input
                        type="text"
                        placeholder="ej. neubox-soc/iris-backups"
                        value={retentionConfig.github?.repo || ''}
                        onChange={(e) =>
                          setRetentionConfig({
                            ...retentionConfig,
                            github: { ...retentionConfig.github, repo: e.target.value },
                          })
                        }
                        className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-text-muted block mb-1">
                        Rama Destino
                      </label>
                      <input
                        type="text"
                        placeholder="main"
                        value={retentionConfig.github?.branch || 'main'}
                        onChange={(e) =>
                          setRetentionConfig({
                            ...retentionConfig,
                            github: { ...retentionConfig.github, branch: e.target.value },
                          })
                        }
                        className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="text-[11px] text-text-muted block mb-1">
                      Directorio de Destino en el Repo
                    </label>
                    <input
                      type="text"
                      placeholder="backups/cases"
                      value={retentionConfig.github?.path || 'backups/cases'}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          github: { ...retentionConfig.github, path: e.target.value },
                        })
                      }
                      className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                    />
                  </div>
                </div>
              )}

              {/* Schedule Section */}
              <div className="p-4 rounded-xl bg-surface-root border border-border-subtle space-y-3">
                <span className="text-xs font-bold text-text-primary flex items-center gap-1.5">
                  <Clock className="w-4 h-4 text-emerald-400" />
                  Política de Retención Automática (Madrugadas)
                </span>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="text-[11px] text-text-muted block mb-1">Hora de Ejecución (UTC)</label>
                    <input
                      type="text"
                      value={retentionConfig.schedule?.time_utc || '03:00'}
                      onChange={(e) =>
                        setRetentionConfig({
                          ...retentionConfig,
                          schedule: { ...retentionConfig.schedule, time_utc: e.target.value },
                        })
                      }
                      className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                    />
                  </div>

                  <div>
                    <label className="text-[11px] text-text-muted block mb-1">Purgar Evidencias tras</label>
                    <div className="flex items-center gap-1">
                      <input
                        type="number"
                        value={retentionConfig.schedule?.prune_binaries_after_days || 90}
                        onChange={(e) =>
                          setRetentionConfig({
                            ...retentionConfig,
                            schedule: {
                              ...retentionConfig.schedule,
                              prune_binaries_after_days: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-card border border-border-subtle text-text-primary font-mono"
                      />
                      <span className="text-text-muted">días</span>
                    </div>
                  </div>
                </div>

                <label className="flex items-center gap-2 text-xs text-text-primary cursor-pointer">
                  <input
                    type="checkbox"
                    checked={retentionConfig.schedule?.auto_prune_closed_cases ?? true}
                    onChange={(e) =>
                      setRetentionConfig({
                        ...retentionConfig,
                        schedule: {
                          ...retentionConfig.schedule,
                          auto_prune_closed_cases: e.target.checked,
                        },
                      })
                    }
                    className="w-3.5 h-3.5 rounded text-indigo-600 focus:ring-0"
                  />
                  <span>Purgar binarios automáticamente en casos cerrados con respaldo verificado</span>
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
                <Button variant="secondary" size="sm" type="button" onClick={() => setShowConfigModal(false)}>
                  Cancelar
                </Button>
                <Button variant="primary" size="sm" type="submit" loading={savingConfig}>
                  Guardar Parámetros
                </Button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* Modal: Bulk Rotation Execution */}
      {showRotationModal && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-border-subtle rounded-2xl p-6 w-full max-w-md shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <FolderArchive className="w-4 h-4 text-indigo-500" />
                Rotación Masiva de Almacenamiento
              </h3>
              <button onClick={() => setShowRotationModal(false)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <label className="font-semibold text-text-secondary block mb-1">Alcance de Casos a Procesar</label>
                <select
                  value={rotationScope}
                  onChange={(e) => setRotationScope(e.target.value as any)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-semibold"
                >
                  <option value="all">Todos los Casos de IRIS (Respaldo General Completo)</option>
                  <option value="closed_only">Solo Casos Cerrados / Resueltos</option>
                  <option value="age_days">Casos con Antigüedad Mayor a X días</option>
                </select>
              </div>

              {rotationScope === 'age_days' && (
                <div>
                  <label className="font-semibold text-text-secondary block mb-1">Días Mínimos de Antigüedad</label>
                  <input
                    type="number"
                    value={rotationMinAge}
                    onChange={(e) => setRotationMinAge(Number(e.target.value))}
                    className="w-full text-xs px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono"
                  />
                </div>
              )}

              <div>
                <label className="font-semibold text-text-secondary block mb-1">Acción a Ejecutar</label>
                <select
                  value={rotationAction}
                  onChange={(e) => setRotationAction(e.target.value as any)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-semibold"
                >
                  <option value="backup_only">Solo Generar Respaldos .tar.gz (Sin Purgar)</option>
                  <option value="backup_and_prune">Respaldar y Purgar Binarios Pesados del Datastore</option>
                </select>
              </div>

              <p className="text-[11px] text-text-muted bg-surface-root p-2.5 rounded border border-border-subtle">
                La tarea se ejecutará de forma asíncrona en segundo plano sin bloquear tu navegación ni saturar el servidor.
              </p>

              <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
                <Button variant="secondary" size="sm" type="button" onClick={() => setShowRotationModal(false)}>
                  Cancelar
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  type="button"
                  loading={startingJob}
                  onClick={handleStartBulkRotation}
                  icon={<Play className="w-3.5 h-3.5" />}
                >
                  Iniciar Rotación en 2do Plano
                </Button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Modal: Explicit Prune Confirmation */}
      {pruningCase && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-rose-500/40 rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-rose-500" />
                <h3 className="text-sm font-bold text-text-primary">
                  Autorización Explícita de Purgado Forense
                </h3>
              </div>
              <button onClick={() => setPruningCase(null)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs text-text-muted leading-relaxed">
              <p>
                Está a punto de vaciar los archivos binarios pesados del Datastore de IRIS para el <b>Caso #{pruningCase.case_id}</b> ({pruningCase.case_name}):
              </p>
              <ul className="list-disc pl-5 space-y-1 font-mono text-[11px] text-text-secondary">
                <li>Archivos binarios a eliminar: <b>{pruningCase.evidence_count}</b></li>
                <li>Espacio a liberar: <b>{pruningCase.total_bytes_human}</b></li>
                <li>Respaldo verificado existente: <span className="text-emerald-400">SÍ (.tar.gz disponible)</span></li>
                <li>Metadatos, notas y hashes SHA-256: <span className="text-indigo-400">Permanecen intactos</span></li>
              </ul>
            </div>

            <form onSubmit={handleExecutePrune} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-rose-400 block mb-1">
                  Escriba <b>CONFIRMAR</b> para autorizar la operación:
                </label>
                <input
                  type="text"
                  placeholder="CONFIRMAR"
                  value={confirmInput}
                  onChange={(e) => setConfirmInput(e.target.value)}
                  className="w-full text-xs font-mono uppercase px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-rose-500"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
                <Button variant="secondary" size="sm" type="button" onClick={() => setPruningCase(null)}>
                  Cancelar
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  type="submit"
                  loading={pruningLoading}
                  disabled={confirmInput.trim().toUpperCase() !== 'CONFIRMAR'}
                  className="bg-rose-600 hover:bg-rose-500 text-white border-rose-500"
                >
                  Confirmar y Purgar
                </Button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};
