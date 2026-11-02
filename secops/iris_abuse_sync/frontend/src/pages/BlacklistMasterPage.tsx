import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  RefreshCw,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  ExternalLink,
  Link as LinkIcon,
  Filter,
  Send,
  Building2,
  Server,
  FileText,
  Plus,
  Play,
  Pause,
  Trash2,
  ShieldAlert,
  Layers,
  Activity,
  Check
} from 'lucide-react';
import { api } from '../api/client';
import { Badge, OrgBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Modal } from '../components/common/Modal';
import { ConfirmModal } from '../components/common/ConfirmModal';
import { MonitoredIp } from '../types';

export const BlacklistMasterPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'monitored' | 'episodes' | 'query'>('monitored');

  // Stats
  const [stats, setStats] = useState<any | null>(null);

  // Monitored IPs state
  const [monitoredIps, setMonitoredIps] = useState<MonitoredIp[]>([]);
  const [loadingMonitored, setLoadingMonitored] = useState(false);
  const [monitoredOrgFilter, setMonitoredOrgFilter] = useState<string>('all');
  const [monitoredStatusFilter, setMonitoredStatusFilter] = useState<string>('all');
  const [monitoredRepFilter, setMonitoredRepFilter] = useState<string>('all');
  const [monitoredSearch, setMonitoredSearch] = useState('');
  const [runningAllChecks, setRunningAllChecks] = useState(false);
  const [checkingSingleId, setCheckingSingleId] = useState<number | null>(null);

  // Add single IP modal
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newIpForm, setNewIpForm] = useState({
    ip_address: '',
    organization: 'NBX' as 'NBX' | 'HP',
    server_name: '',
    description: '',
    check_interval_minutes: 60,
  });
  const [savingNewIp, setSavingNewIp] = useState(false);

  // Add bulk IPs modal
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  const [bulkText, setBulkText] = useState('');
  const [bulkOrg, setBulkOrg] = useState<'NBX' | 'HP'>('NBX');
  const [savingBulk, setSavingBulk] = useState(false);

  // Real-time Query state
  const [targetInput, setTargetInput] = useState('');
  const [serverInput, setServerInput] = useState('');
  const [orgInput, setOrgInput] = useState<'NBX' | 'HP'>('NBX');
  const [recordEpisode, setRecordEpisode] = useState(true);
  const [checking, setChecking] = useState(false);
  const [queryResult, setQueryResult] = useState<any | null>(null);

  // Episodes table state
  const [episodes, setEpisodes] = useState<any[]>([]);
  const [loadingEpisodes, setLoadingEpisodes] = useState(false);
  const [episodeStatusFilter, setEpisodeStatusFilter] = useState<string>('all');
  const [episodeOrgFilter, setEpisodeOrgFilter] = useState<string>('all');
  const [episodeSearchFilter, setEpisodeSearchFilter] = useState('');

  // Modals for episodes
  const [delistingModalOpen, setDelistingModalOpen] = useState(false);
  const [selectedEpisode, setSelectedEpisode] = useState<any | null>(null);
  const [delistingRef, setDelistingRef] = useState('');
  const [delistingNotes, setDelistingNotes] = useState('');
  const [savingDelisting, setSavingDelisting] = useState(false);

  const [linkModalOpen, setLinkModalOpen] = useState(false);
  const [linkCaseId, setLinkCaseId] = useState('');
  const [linkingCase, setLinkingCase] = useState(false);

  const fetchStats = async () => {
    try {
      const res = await api.getBlacklistStats();
      setStats(res);
    } catch (err: any) {
      console.error('Error fetching blacklist stats:', err);
    }
  };

  const fetchMonitoredIps = async () => {
    setLoadingMonitored(true);
    try {
      const params: any = {};
      if (monitoredOrgFilter !== 'all') params.organization = monitoredOrgFilter;
      if (monitoredStatusFilter !== 'all') params.status = monitoredStatusFilter;
      if (monitoredRepFilter !== 'all') params.last_status = monitoredRepFilter;
      if (monitoredSearch.trim()) params.search = monitoredSearch.trim();
      const res = await api.getMonitoredIps(params);
      setMonitoredIps(res.items || []);
    } catch (err: any) {
      console.error('Error fetching monitored IPs:', err);
    } finally {
      setLoadingMonitored(false);
    }
  };

  const fetchEpisodes = async () => {
    setLoadingEpisodes(true);
    try {
      const params: any = { limit: 100 };
      if (episodeStatusFilter !== 'all') params.status = episodeStatusFilter;
      if (episodeOrgFilter !== 'all') params.organization = episodeOrgFilter;
      if (episodeSearchFilter.trim()) params.search = episodeSearchFilter.trim();
      const res = await api.getBlacklistEpisodes(params);
      setEpisodes(res.episodes || []);
    } catch (err: any) {
      console.error('Error fetching episodes:', err);
    } finally {
      setLoadingEpisodes(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    if (activeTab === 'monitored') {
      fetchMonitoredIps();
    } else if (activeTab === 'episodes') {
      fetchEpisodes();
    }
  }, [activeTab, monitoredOrgFilter, monitoredStatusFilter, monitoredRepFilter, episodeStatusFilter, episodeOrgFilter]);

  // Handle Add Single IP
  const handleSaveNewIp = async () => {
    if (!newIpForm.ip_address.trim()) {
      alert('Ingresa una dirección IP válida');
      return;
    }
    setSavingNewIp(true);
    try {
      await api.createMonitoredIp({
        ip_address: newIpForm.ip_address.trim(),
        organization: newIpForm.organization,
        server_name: newIpForm.server_name.trim() || undefined,
        description: newIpForm.description.trim() || undefined,
        check_interval_minutes: newIpForm.check_interval_minutes || 60,
      });
      setIsAddModalOpen(false);
      setNewIpForm({
        ip_address: '',
        organization: 'NBX',
        server_name: '',
        description: '',
        check_interval_minutes: 60,
      });
      fetchMonitoredIps();
      fetchStats();
      alert('✓ Dirección IP agregada al monitoreo continuo.');
    } catch (err: any) {
      alert('Error agregando IP: ' + err.message);
    } finally {
      setSavingNewIp(false);
    }
  };

  // Handle Add Bulk IPs
  const handleSaveBulk = async () => {
    if (!bulkText.trim()) {
      alert('Ingresa al menos una línea con formato IP[,servidor,descripcion]');
      return;
    }
    setSavingBulk(true);
    try {
      const res = await api.bulkCreateMonitoredIps({
        raw_text: bulkText.trim(),
        organization: bulkOrg,
      });
      setIsBulkModalOpen(false);
      setBulkText('');
      fetchMonitoredIps();
      fetchStats();
      alert(`✓ ${res.created_count || 0} IPs añadidas exitosamente al catálogo.`);
    } catch (err: any) {
      alert('Error importando lote: ' + err.message);
    } finally {
      setSavingBulk(false);
    }
  };

  // Run Check on Single IP
  const handleCheckSingle = async (ip: MonitoredIp) => {
    setCheckingSingleId(ip.id);
    try {
      const res = await api.checkMonitoredIp(ip.id);
      fetchMonitoredIps();
      fetchStats();
      if (res.is_listed) {
        alert(`⚠ IP ${ip.ip_address} se encuentra LISTADA en ${res.listed_providers?.join(', ')}`);
      } else {
        alert(`✓ IP ${ip.ip_address} verificada LIMPIA en todos los proveedores RBL.`);
      }
    } catch (err: any) {
      alert('Error ejecutando verificación: ' + err.message);
    } finally {
      setCheckingSingleId(null);
    }
  };

  // Toggle Monitored IP Status (Active / Paused)
  const handleToggleStatus = async (ip: MonitoredIp) => {
    const nextStatus = ip.status === 'active' ? 'paused' : 'active';
    try {
      await api.updateMonitoredIp(ip.id, { status: nextStatus });
      fetchMonitoredIps();
    } catch (err: any) {
      alert('Error cambiando estado: ' + err.message);
    }
  };

  const [confirmDeleteIp, setConfirmDeleteIp] = useState<MonitoredIp | null>(null);

  // Delete Monitored IP
  const handleDeleteIp = (ip: MonitoredIp) => {
    setConfirmDeleteIp(ip);
  };

  const handleExecuteDeleteIp = async () => {
    if (!confirmDeleteIp) return;
    try {
      await api.deleteMonitoredIp(confirmDeleteIp.id);
      setConfirmDeleteIp(null);
      fetchMonitoredIps();
      fetchStats();
    } catch (err: any) {
      alert('Error eliminando IP: ' + err.message);
    }
  };

  // Run All Active Monitoring Checks
  const handleRunAllChecks = async () => {
    setRunningAllChecks(true);
    try {
      const res = await api.runAllMonitoredChecks(false);
      fetchMonitoredIps();
      fetchStats();
      alert(`✓ Ciclo de monitoreo ejecutado: ${res.checked_count || 0} IPs verificadas, ${res.listed_count || 0} listadas.`);
    } catch (err: any) {
      alert('Error ejecutando ciclo de monitoreo: ' + err.message);
    } finally {
      setRunningAllChecks(false);
    }
  };

  // Real-time Query Handlers
  const handleRunCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    setChecking(true);
    setQueryResult(null);
    try {
      const res = await api.checkBlacklist(targetInput.trim(), serverInput.trim() || undefined, orgInput, recordEpisode);
      setQueryResult(res);
      if (recordEpisode) {
        fetchStats();
      }
    } catch (err: any) {
      alert('Error en consulta RBL: ' + (err.message || 'Error de conexión'));
    } finally {
      setChecking(false);
    }
  };

  // Delisting Modal Handlers
  const handleOpenDelistingModal = (ep: any) => {
    setSelectedEpisode(ep);
    setDelistingRef('');
    setDelistingNotes('');
    setDelistingModalOpen(true);
  };

  const handleSaveDelisting = async () => {
    if (!selectedEpisode) return;
    setSavingDelisting(true);
    try {
      await api.registerDelisting(selectedEpisode.id, delistingRef.trim(), delistingNotes.trim());
      setDelistingModalOpen(false);
      fetchEpisodes();
      fetchStats();
    } catch (err: any) {
      alert('Error registrando solicitud de delisting: ' + err.message);
    } finally {
      setSavingDelisting(false);
    }
  };

  // Link Case Handlers
  const handleOpenLinkModal = (ep: any) => {
    setSelectedEpisode(ep);
    setLinkCaseId('');
    setLinkModalOpen(true);
  };

  const handleLinkCase = async () => {
    if (!selectedEpisode || !linkCaseId.trim()) return;
    const cid = parseInt(linkCaseId.trim(), 10);
    if (isNaN(cid)) {
      alert('ID de caso no válido');
      return;
    }
    setLinkingCase(true);
    try {
      await api.linkBlacklistEpisode(selectedEpisode.id, cid);
      setLinkModalOpen(false);
      fetchEpisodes();
    } catch (err: any) {
      alert('Error vinculando caso IRIS: ' + err.message);
    } finally {
      setLinkingCase(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold text-text-primary tracking-tight flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            Blacklist Master & Monitoreo de Reputación
          </h2>
          <p className="text-xs text-text-muted mt-0.5">
            Monitoreo continuo de servidores de correo, detección RBL inteligente y gestión formal de delisting
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              fetchStats();
              if (activeTab === 'monitored') fetchMonitoredIps();
              else if (activeTab === 'episodes') fetchEpisodes();
            }}
          >
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
            Actualizar
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
          <span className="text-[10px] uppercase font-bold text-text-muted block">IPs Bajo Monitoreo</span>
          <span className="text-2xl font-bold font-mono text-indigo-500 mt-1 block">
            {stats?.monitored_ips_count ?? monitoredIps.length}
          </span>
          <span className="text-[10px] text-text-muted">Servidores bajo vigilancia activa</span>
        </div>

        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
          <span className="text-[10px] uppercase font-bold text-text-muted block">Listados Activos RBL</span>
          <span className="text-2xl font-bold font-mono text-red-500 mt-1 block">
            {stats?.active_listings ?? 0}
          </span>
          <span className="text-[10px] text-text-muted">IPs actualmente bloqueadas</span>
        </div>

        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
          <span className="text-[10px] uppercase font-bold text-text-muted block">En Proceso de Delisting</span>
          <span className="text-2xl font-bold font-mono text-amber-500 mt-1 block">
            {stats?.delisting_in_progress ?? 0}
          </span>
          <span className="text-[10px] text-text-muted">Solicitudes enviadas a RBL</span>
        </div>

        <div className="p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
          <span className="text-[10px] uppercase font-bold text-text-muted block">Proveedores Monitoreados</span>
          <span className="text-2xl font-bold font-mono text-emerald-500 mt-1 block">
            {stats?.monitored_providers_count ?? 6}
          </span>
          <span className="text-[10px] text-text-muted">Spamhaus, Barracuda, SpamCop...</span>
        </div>
      </div>

      {/* Navigation Subtabs */}
      <div className="flex items-center gap-2 border-b border-border-subtle text-xs font-semibold select-none">
        <button
          onClick={() => setActiveTab('monitored')}
          className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
            activeTab === 'monitored'
              ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
              : 'border-transparent text-text-muted hover:text-text-primary'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>IPs Monitoreadas ({monitoredIps.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('episodes')}
          className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
            activeTab === 'episodes'
              ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
              : 'border-transparent text-text-muted hover:text-text-primary'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Historial de Episodios RBL ({episodes.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('query')}
          className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
            activeTab === 'query'
              ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
              : 'border-transparent text-text-muted hover:text-text-primary'
          }`}
        >
          <Search className="w-3.5 h-3.5" />
          <span>Diagnóstico RBL Inmediato</span>
        </button>
      </div>

      {/* TAB 1: MONITORED IPS */}
      {activeTab === 'monitored' && (
        <div className="space-y-4">
          {/* Action bar and filters */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Buscar IP o servidor..."
                  value={monitoredSearch}
                  onChange={(e) => setMonitoredSearch(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && fetchMonitoredIps()}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary focus:outline-none focus:border-indigo-500 w-48"
                />
              </div>

              <select
                value={monitoredOrgFilter}
                onChange={(e) => setMonitoredOrgFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary"
              >
                <option value="all">Todas las Orgs</option>
                <option value="NBX">NEUBOX (NBX)</option>
                <option value="HP">Hospedando (HP)</option>
              </select>

              <select
                value={monitoredRepFilter}
                onChange={(e) => setMonitoredRepFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary"
              >
                <option value="all">Todas las Reputaciones</option>
                <option value="clean">Solo Limpias</option>
                <option value="listed">Solo Listadas en RBL</option>
                <option value="pending">Pendientes de Check</option>
              </select>

              <select
                value={monitoredStatusFilter}
                onChange={(e) => setMonitoredStatusFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary"
              >
                <option value="all">Todos los Estados</option>
                <option value="active">Solo Activas</option>
                <option value="paused">Solo Pausadas</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                icon={<Play className={`w-3.5 h-3.5 ${runningAllChecks ? 'animate-spin' : ''}`} />}
                loading={runningAllChecks}
                onClick={handleRunAllChecks}
                title="Ejecutar ciclo de verificación en todas las IPs activas"
              >
                Ejecutar Monitoreo Ahora
              </Button>
              <Button
                variant="secondary"
                size="sm"
                icon={<Layers className="w-3.5 h-3.5" />}
                onClick={() => setIsBulkModalOpen(true)}
              >
                + En Lote
              </Button>
              <Button
                variant="primary"
                size="sm"
                icon={<Plus className="w-3.5 h-3.5" />}
                onClick={() => setIsAddModalOpen(true)}
              >
                + Agregar IP
              </Button>
            </div>
          </div>

          {/* Monitored IPs Table */}
          <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm">
            <div className="overflow-x-auto min-w-full">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-surface-elevated/80 text-text-muted uppercase text-[10px] font-mono border-b border-border-subtle">
                  <tr>
                    <th className="py-3 px-4">Dirección IP</th>
                    <th className="py-3 px-4">Organización</th>
                    <th className="py-3 px-4">Servidor / Hostname</th>
                    <th className="py-3 px-4">Reputación RBL</th>
                    <th className="py-3 px-4">Proveedores Listados</th>
                    <th className="py-3 px-4">Última Revisión</th>
                    <th className="py-3 px-4">Monitoreo</th>
                    <th className="py-3 px-4 text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle font-sans">
                  {loadingMonitored ? (
                    <tr>
                      <td colSpan={8} className="py-10 text-center text-text-muted">
                        <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-indigo-500" />
                        Cargando catálogo de IPs monitoreadas...
                      </td>
                    </tr>
                  ) : monitoredIps.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-10 text-center text-text-muted">
                        No hay direcciones IP registradas bajo monitoreo. Haz clic en <b>"+ Agregar IP"</b> o <b>"+ En Lote"</b> para comenzar a vigilar tu infraestructura.
                      </td>
                    </tr>
                  ) : (
                    monitoredIps.map((ip) => {
                      const isListed = ip.last_status === 'listed' || (ip.listed_providers && ip.listed_providers.length > 0);
                      const isPending = ip.last_status === 'pending';
                      const isCheckingThis = checkingSingleId === ip.id;

                      return (
                        <tr key={ip.id} className="hover:bg-surface-elevated/30">
                          <td className="py-3 px-4 font-mono font-bold text-text-primary">
                            {ip.ip_address}
                          </td>
                          <td className="py-3 px-4">
                            <OrgBadge org={ip.organization} />
                          </td>
                          <td className="py-3 px-4 font-mono text-text-secondary">
                            {ip.server_name || '—'}
                          </td>
                          <td className="py-3 px-4">
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              isListed
                                ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950/80 dark:text-red-300'
                                : isPending
                                ? 'bg-slate-200 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300'
                                : 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300'
                            }`}>
                              {isListed ? (
                                <>
                                  <XCircle className="w-3 h-3 text-red-500" />
                                  LISTADA ({ip.listed_providers?.length || 1})
                                </>
                              ) : isPending ? (
                                <>
                                  <Clock className="w-3 h-3 text-slate-400" />
                                  PENDIENTE
                                </>
                              ) : (
                                <>
                                  <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                                  LIMPIA
                                </>
                              )}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            {ip.listed_providers && ip.listed_providers.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {ip.listed_providers.map((p, idx) => (
                                  <span key={idx} className="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px] font-mono">
                                    {p}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-text-muted text-[11px]">—</span>
                            )}
                          </td>
                          <td className="py-3 px-4 font-mono text-text-muted text-[11px]">
                            {ip.last_checked_at ? new Date(ip.last_checked_at).toLocaleString('es-MX') : 'Nunca'}
                          </td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              ip.status === 'active'
                                ? 'bg-indigo-100 text-indigo-800 border-indigo-300 dark:bg-indigo-950/80 dark:text-indigo-300'
                                : 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-400'
                            }`}>
                              {ip.status === 'active' ? 'Activo' : 'Pausado'}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                onClick={() => handleCheckSingle(ip)}
                                disabled={isCheckingThis}
                                className="px-2 py-1 rounded bg-surface-root hover:bg-surface-hover text-text-primary text-[11px] font-medium border border-border-subtle transition-colors flex items-center gap-1"
                                title="Verificar reputación en vivo ahora"
                              >
                                <RefreshCw className={`w-3 h-3 ${isCheckingThis ? 'animate-spin' : ''}`} />
                                Verificar
                              </button>
                              <button
                                onClick={() => handleToggleStatus(ip)}
                                className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-surface-hover transition-colors"
                                title={ip.status === 'active' ? 'Pausar monitoreo' : 'Reanudar monitoreo'}
                              >
                                {ip.status === 'active' ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                              </button>
                              <button
                                onClick={() => handleDeleteIp(ip)}
                                className="p-1 rounded text-rose-500 hover:bg-rose-500/10 transition-colors"
                                title="Retirar IP del catálogo"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: HISTORICAL EPISODES */}
      {activeTab === 'episodes' && (
        <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-text-primary">
                Bitácora de Episodios RBL & Seguimiento de Delisting
              </h3>
              <p className="text-xs text-text-muted">
                Historial de IPs detectadas en listas negras, tickets de remediación y solicitudes a proveedores
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={episodeStatusFilter}
                onChange={(e) => setEpisodeStatusFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary"
              >
                <option value="all">Todos los Estados</option>
                <option value="active">Solo Activos (Listados)</option>
                <option value="delisting_requested">Delisting Solicitado</option>
                <option value="delisted">Resueltos / Delisted</option>
              </select>

              <select
                value={episodeOrgFilter}
                onChange={(e) => setEpisodeOrgFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary"
              >
                <option value="all">Todas las Orgs</option>
                <option value="NBX">NEUBOX (NBX)</option>
                <option value="HP">Hospedando (HP)</option>
              </select>
            </div>
          </div>

          {/* Episodes Table */}
          <div className="border border-border-subtle rounded-xl overflow-hidden">
            <div className="overflow-x-auto min-w-full">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-surface-elevated/80 text-text-muted uppercase text-[10px] font-mono border-b border-border-subtle">
                  <tr>
                    <th className="py-3 px-4 w-12">#</th>
                    <th className="py-3 px-4 w-28">Org</th>
                    <th className="py-3 px-4">Dirección IP</th>
                    <th className="py-3 px-4">Servidor</th>
                    <th className="py-3 px-4">Proveedor RBL</th>
                    <th className="py-3 px-4">Estado</th>
                    <th className="py-3 px-4">Detecciones</th>
                    <th className="py-3 px-4">Caso IRIS</th>
                    <th className="py-3 px-4 text-right">Gestión</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle font-sans">
                  {loadingEpisodes ? (
                    <tr>
                      <td colSpan={9} className="py-10 text-center text-text-muted">
                        <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-indigo-500" />
                        Cargando episodios RBL...
                      </td>
                    </tr>
                  ) : episodes.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-10 text-center text-text-muted">
                        No se encontraron episodios con los filtros seleccionados.
                      </td>
                    </tr>
                  ) : (
                    episodes.map((ep) => (
                      <tr key={ep.id} className="hover:bg-surface-elevated/30">
                        <td className="py-3 px-4 font-mono text-text-muted font-bold">
                          #{ep.id}
                        </td>
                        <td className="py-3 px-4">
                          <OrgBadge org={ep.organization} />
                        </td>
                        <td className="py-3 px-4 font-mono font-bold text-text-primary">
                          {ep.ip_address}
                        </td>
                        <td className="py-3 px-4 font-mono text-text-secondary">
                          {ep.server_name || '—'}
                        </td>
                        <td className="py-3 px-4 text-text-primary font-medium">
                          {ep.rbl_provider}
                        </td>
                        <td className="py-3 px-4">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            ep.status === 'active'
                              ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950/80 dark:text-red-300'
                              : ep.status === 'delisting_requested'
                              ? 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/80 dark:text-amber-300'
                              : 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300'
                          }`}>
                            {ep.status === 'active'
                              ? 'Listada Activa'
                              : ep.status === 'delisting_requested'
                              ? 'Delisting Solicitado'
                              : 'Delisted / Limpia'}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-text-secondary">
                          {ep.check_count} veces
                        </td>
                        <td className="py-3 px-4">
                          {ep.iris_case_id ? (
                            <a
                              href={`/cases/${ep.iris_case_id}`}
                              className="font-mono text-blue-500 font-bold hover:underline"
                            >
                              Caso #{ep.iris_case_id}
                            </a>
                          ) : (
                            <span className="text-text-muted text-[11px]">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {ep.status === 'active' && (
                              <button
                                onClick={() => handleOpenDelistingModal(ep)}
                                className="px-2 py-1 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-500 text-[11px] font-medium border border-amber-500/30 transition-colors"
                              >
                                Delisting
                              </button>
                            )}
                            {!ep.iris_case_id && (
                              <button
                                onClick={() => handleOpenLinkModal(ep)}
                                className="px-2 py-1 rounded bg-surface-root hover:bg-surface-hover text-text-secondary hover:text-text-primary text-[11px] font-medium border border-border-subtle transition-colors flex items-center gap-1"
                              >
                                <LinkIcon className="w-3 h-3" />
                                Vincular
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: REAL-TIME RBL QUERY TOOL */}
      {activeTab === 'query' && (
        <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
          <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
            <Search className="w-4 h-4 text-blue-500" />
            Consulta Operativa de Reputación IP / Dominio
          </h3>

          <form onSubmit={handleRunCheck} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
            <div className="md:col-span-5">
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                IP o Dominio a Diagnosticar *
              </label>
              <input
                type="text"
                required
                placeholder="ej. 209.59.180.25 o dominio.com"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="md:col-span-3">
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Servidor Asociado (Opcional)
              </label>
              <input
                type="text"
                placeholder="ej. svgt190"
                value={serverInput}
                onChange={(e) => setServerInput(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary font-mono focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Organización
              </label>
              <select
                value={orgInput}
                onChange={(e) => setOrgInput(e.target.value as any)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary font-medium focus:outline-none focus:border-blue-500"
              >
                <option value="NBX">NEUBOX (NBX)</option>
                <option value="HP">Hospedando (HP)</option>
              </select>
            </div>

            <div className="md:col-span-2 flex items-center">
              <Button
                type="submit"
                variant="primary"
                size="md"
                loading={checking}
                className="w-full"
                icon={<Search className="w-3.5 h-3.5" />}
              >
                Consultar RBLs
              </Button>
            </div>
          </form>

          <div className="flex items-center gap-2 pt-1">
            <input
              type="checkbox"
              id="recEpisode"
              checked={recordEpisode}
              onChange={(e) => setRecordEpisode(e.target.checked)}
              className="rounded border-border-subtle text-blue-600 focus:ring-0"
            />
            <label htmlFor="recEpisode" className="text-xs text-text-secondary cursor-pointer">
              Registrar automáticamente como episodio en bitácora si resulta listada
            </label>
          </div>

          {/* Query Result Card */}
          {queryResult && (
            <div className="mt-4 pt-4 border-t border-border-subtle space-y-4 animate-fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-surface-elevated/50 border border-border-subtle">
                <div>
                  <span className="text-xs text-text-muted block font-mono">
                    Target: <b className="text-text-primary">{queryResult.target}</b> &bull; IP Resuelta: <b className="text-text-primary font-mono">{queryResult.resolved_ip}</b>
                  </span>
                  <span className="text-[10px] text-text-muted">
                    Consulta realizada a las {new Date(queryResult.query_timestamp).toLocaleTimeString('es-MX')}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase border ${
                    queryResult.summary.is_clean
                      ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300'
                      : queryResult.summary.listed > 0
                      ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950/80 dark:text-red-300'
                      : 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/80 dark:text-amber-300'
                  }`}>
                    {queryResult.summary.is_clean
                      ? '✓ LIMPIA EN TODOS LOS RBLs'
                      : `LISTADA EN ${queryResult.summary.listed} PROVEEDOR(ES)`}
                  </span>
                </div>
              </div>

              {/* Providers Result Table */}
              <div className="border border-border-subtle rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-surface-elevated/80 text-text-muted uppercase text-[10px] font-mono border-b border-border-subtle">
                    <tr>
                      <th className="py-2.5 px-4">Proveedor RBL</th>
                      <th className="py-2.5 px-4">Zona DNS</th>
                      <th className="py-2.5 px-4">Estado</th>
                      <th className="py-2.5 px-4">Código / Detalle Observado</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle font-sans">
                    {queryResult.providers.map((p: any) => (
                      <tr key={p.provider_name} className="hover:bg-surface-elevated/30">
                        <td className="py-2.5 px-4 font-semibold text-text-primary">
                          {p.provider_name}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-[11px] text-text-muted">
                          {p.provider_zone}
                        </td>
                        <td className="py-2.5 px-4">
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            p.status === 'listed'
                              ? 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300'
                              : p.status === 'clean'
                              ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300'
                              : 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300'
                          }`}>
                            {p.status === 'listed' && <XCircle className="w-3 h-3 text-red-500" />}
                            {p.status === 'clean' && <CheckCircle2 className="w-3 h-3 text-emerald-500" />}
                            {p.status === 'error' && <AlertTriangle className="w-3 h-3 text-amber-500" />}
                            {p.status === 'listed' ? 'LISTADA' : p.status === 'clean' ? 'LIMPIA' : 'ERROR CONSULTA'}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-text-secondary text-xs">
                          {p.details}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Add Single IP Modal */}
      {isAddModalOpen && (
        <Modal
          isOpen={isAddModalOpen}
          onClose={() => setIsAddModalOpen(false)}
          title="Agregar Dirección IP al Monitoreo Continuo"
          subtitle="Vigilancia recurrente de reputación y correlación automática con DFIR-IRIS"
        >
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Dirección IP *
                </label>
                <input
                  type="text"
                  required
                  placeholder="ej. 209.59.180.25"
                  value={newIpForm.ip_address}
                  onChange={(e) => setNewIpForm({ ...newIpForm, ip_address: e.target.value.trim() })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Organización *
                </label>
                <select
                  value={newIpForm.organization}
                  onChange={(e) => setNewIpForm({ ...newIpForm, organization: e.target.value as any })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                >
                  <option value="NBX">NEUBOX (NBX)</option>
                  <option value="HP">Hospedando (HP)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Servidor / Hostname (Opcional)
                </label>
                <input
                  type="text"
                  placeholder="ej. svgt190 o relay01.neubox.net"
                  value={newIpForm.server_name}
                  onChange={(e) => setNewIpForm({ ...newIpForm, server_name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Intervalo de Chequeo (minutos)
                </label>
                <input
                  type="number"
                  min={15}
                  max={1440}
                  value={newIpForm.check_interval_minutes}
                  onChange={(e) => setNewIpForm({ ...newIpForm, check_interval_minutes: parseInt(e.target.value) || 60 })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Descripción / Rol del Servidor
              </label>
              <textarea
                rows={2}
                placeholder="ej. Servidor de hosting compartido cPanel Guadalajara con 120 clientes"
                value={newIpForm.description}
                onChange={(e) => setNewIpForm({ ...newIpForm, description: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
              <Button variant="secondary" size="sm" onClick={() => setIsAddModalOpen(false)}>
                Cancelar
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={savingNewIp}
                onClick={handleSaveNewIp}
                icon={<Plus className="w-3.5 h-3.5" />}
              >
                Agregar al Monitoreo
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Add Bulk IPs Modal */}
      {isBulkModalOpen && (
        <Modal
          isOpen={isBulkModalOpen}
          onClose={() => setIsBulkModalOpen(false)}
          title="Importación Masiva de IPs para Monitoreo"
          subtitle="Pega múltiples IPs separadas por líneas (formato: IP[,servidor,descripcion])"
        >
          <div className="space-y-4 text-xs">
            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Organización por Defecto
              </label>
              <select
                value={bulkOrg}
                onChange={(e) => setBulkOrg(e.target.value as any)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              >
                <option value="NBX">NEUBOX (NBX)</option>
                <option value="HP">Hospedando (HP)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Lista de Direcciones IP (Una por línea)
              </label>
              <textarea
                rows={8}
                placeholder="209.59.180.25,svgt190,Hosting Compartido cPanel&#10;198.51.100.14,svlw415,Relay Saliente&#10;192.0.2.80"
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
              <Button variant="secondary" size="sm" onClick={() => setIsBulkModalOpen(false)}>
                Cancelar
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={savingBulk}
                onClick={handleSaveBulk}
                icon={<Layers className="w-3.5 h-3.5" />}
              >
                Importar IPs
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Delisting Modal */}
      <Modal
        isOpen={delistingModalOpen}
        onClose={() => setDelistingModalOpen(false)}
        title="Registrar Solicitud de Delisting ante RBL"
        subtitle={`IP: ${selectedEpisode?.ip_address} | Proveedor: ${selectedEpisode?.rbl_provider}`}
      >
        <div className="space-y-4 text-xs">
          <div>
            <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
              Referencia / Ticket del Proveedor RBL (Opcional)
            </label>
            <input
              type="text"
              placeholder="ej. SPAMHAUS-REM-98231 o Ticket #801912"
              value={delistingRef}
              onChange={(e) => setDelistingRef(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
              Notas y Acciones de Remediación Previas al Delisting *
            </label>
            <textarea
              rows={3}
              placeholder="Indica qué acciones de contención se realizaron en el servidor (ej. suspensión de cuenta comprometida, cambio de contraseña, escaneo ClamAV/Imunify)..."
              value={delistingNotes}
              onChange={(e) => setDelistingNotes(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
            <Button variant="secondary" size="sm" onClick={() => setDelistingModalOpen(false)}>
              Cancelar
            </Button>
            <Button
              variant="primary"
              size="sm"
              loading={savingDelisting}
              onClick={handleSaveDelisting}
              icon={<Send className="w-3.5 h-3.5" />}
            >
              Confirmar Solicitud de Delisting
            </Button>
          </div>
        </div>
      </Modal>

      {/* Link to Case Modal */}
      <Modal
        isOpen={linkModalOpen}
        onClose={() => setLinkModalOpen(false)}
        title="Vincular Episodio RBL a Caso IRIS"
        subtitle={`IP: ${selectedEpisode?.ip_address} (${selectedEpisode?.rbl_provider})`}
      >
        <div className="space-y-4 text-xs">
          <div>
            <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
              Número de Caso en DFIR-IRIS *
            </label>
            <input
              type="number"
              placeholder="ej. 21"
              value={linkCaseId}
              onChange={(e) => setLinkCaseId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
            <Button variant="secondary" size="sm" onClick={() => setLinkModalOpen(false)}>
              Cancelar
            </Button>
            <Button
              variant="primary"
              size="sm"
              loading={linkingCase}
              disabled={!linkCaseId.trim()}
              onClick={handleLinkCase}
              icon={<LinkIcon className="w-3.5 h-3.5" />}
            >
              Vincular al Caso
            </Button>
          </div>
        </div>
      </Modal>

      {/* In-app Confirmation Modal for Deleting Monitored IP */}
      <ConfirmModal
        isOpen={confirmDeleteIp !== null}
        title="Retirar IP de Monitoreo"
        message={`¿Deseas retirar ${confirmDeleteIp?.ip_address} del monitoreo continuo de reputación y listas negras?`}
        confirmLabel="Retirar IP"
        cancelLabel="Cancelar"
        variant="danger"
        onConfirm={handleExecuteDeleteIp}
        onClose={() => setConfirmDeleteIp(null)}
      />
    </div>
  );
};
