import React, { useEffect, useState } from 'react';
import {
  Bell,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ShieldAlert,
  ArrowUpRight,
  Sparkles,
  X,
  Layers,
  ChevronRight,
  ChevronLeft,
  AlertCircle,
  Link as LinkIcon,
  Unlink,
  RotateCcw,
  Trash2,
  CheckSquare,
  Square,
  Clock,
  Eye
} from 'lucide-react';
import { Badge, OrgBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Modal } from '../components/common/Modal';
import { ConfirmModal } from '../components/common/ConfirmModal';
import { api } from '../api/client';
import { AlertItem, Organization } from '../types';
import { useCopilot } from '../context/CopilotContext';

interface AlertsPageProps {
  onNavigate?: (path: string) => void;
  onOpenCase?: (caseId: number) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onNavigate, onOpenCase }) => {
  const { setActiveContext, setIsOpen: openCopilot } = useCopilot();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [orgFilter, setOrgFilter] = useState<'ALL' | 'NBX' | 'HP'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'pending' | 'escalated' | 'discarded' | 'all'>('pending');
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [escalating, setEscalating] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Multi-select state
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([]);

  // Modal: Link / Merge to Case
  const [isMergeModalOpen, setIsMergeModalOpen] = useState(false);
  const [targetAlertsForMerge, setTargetAlertsForMerge] = useState<number[]>([]);
  const [compatibleCases, setCompatibleCases] = useState<any[]>([]);
  const [loadingCompatible, setLoadingCompatible] = useState(false);
  const [compatibleSearch, setCompatibleSearch] = useState('');
  const [selectedTargetCaseId, setSelectedTargetCaseId] = useState<number | null>(null);
  const [mergeNotes, setMergeNotes] = useState('');
  const [merging, setMerging] = useState(false);

  // Modal: Discard with Reason
  const [isDiscardModalOpen, setIsDiscardModalOpen] = useState(false);
  const [targetAlertsForDiscard, setTargetAlertsForDiscard] = useState<number[]>([]);
  const [discardReason, setDiscardReason] = useState('');
  const [discarding, setDiscarding] = useState(false);

  // Delete Permanently Modal (Admin)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [targetAlertForDelete, setTargetAlertForDelete] = useState<number | null>(null);
  const [deleteJustification, setDeleteJustification] = useState('');
  const [deleting, setDeleting] = useState(false);

  const fetchAlerts = () => {
    setLoading(true);
    api
      .listAlerts(1, 100)
      .then((res) => {
        setAlerts(res.alerts || []);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  const handleSelectAlert = (a: AlertItem) => {
    setSelectedAlert(a);
    setActiveContext({
      type: 'alert',
      id: a.alert_id,
      title: a.alert_title,
      data: a,
    });
  };

  const handleToggleSelectRow = (alertId: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (selectedAlertIds.includes(alertId)) {
      setSelectedAlertIds(selectedAlertIds.filter(id => id !== alertId));
    } else {
      setSelectedAlertIds([...selectedAlertIds, alertId]);
    }
  };

  const handleSelectAll = () => {
    if (selectedAlertIds.length === filteredAlerts.length) {
      setSelectedAlertIds([]);
    } else {
      setSelectedAlertIds(filteredAlerts.map(a => a.alert_id));
    }
  };

  // Escalate to NEW Case
  const handleEscalate = async (alertId: number) => {
    setEscalating(true);
    try {
      const res = await api.escalateAlertToCase(alertId);
      if (res.case_id) {
        if (onOpenCase) {
          onOpenCase(res.case_id);
        } else if (onNavigate) {
          onNavigate(`/cases/${res.case_id}`);
        }
      } else {
        fetchAlerts();
        setSelectedAlert(null);
      }
    } catch (err: any) {
      alert(`Error al escalar: ${err.message}`);
    } finally {
      setEscalating(false);
    }
  };

  // Open Compatible Cases Modal
  const handleOpenMergeModal = async (alertIds: number[]) => {
    setTargetAlertsForMerge(alertIds);
    setSelectedTargetCaseId(null);
    setMergeNotes('');
    setIsMergeModalOpen(true);
    setLoadingCompatible(true);

    const refAlertId = alertIds[0];
    try {
      const res = await api.getCompatibleCasesForAlert(refAlertId);
      setCompatibleCases(res.compatible_cases || []);
    } catch (err: any) {
      console.warn('Error fetching compatible cases:', err);
    } finally {
      setLoadingCompatible(false);
    }
  };

  const handleSearchCompatibleCases = async () => {
    if (!targetAlertsForMerge.length) return;
    setLoadingCompatible(true);
    try {
      const res = await api.getCompatibleCasesForAlert(targetAlertsForMerge[0], compatibleSearch.trim());
      setCompatibleCases(res.compatible_cases || []);
    } catch (err: any) {
      console.warn('Error searching compatible cases:', err);
    } finally {
      setLoadingCompatible(false);
    }
  };

  // Confirm Merge / Link to Case
  const handleConfirmMerge = async () => {
    if (!selectedTargetCaseId) {
      alert('Selecciona un caso destino para vincular las alertas.');
      return;
    }
    setMerging(true);
    try {
      await api.bulkMergeAlerts({
        alert_ids: targetAlertsForMerge,
        target_case_id: selectedTargetCaseId,
        note: mergeNotes.trim() || undefined,
      });
      setIsMergeModalOpen(false);
      setSelectedAlertIds([]);
      fetchAlerts();
      if (selectedAlert && targetAlertsForMerge.includes(selectedAlert.alert_id)) {
        setSelectedAlert(null);
      }
      alert(`✓ ${targetAlertsForMerge.length} alerta(s) vinculadas exitosamente al Caso #${selectedTargetCaseId}.`);
    } catch (err: any) {
      alert('Error vinculando alertas a caso: ' + err.message);
    } finally {
      setMerging(false);
    }
  };

  // Open Discard Modal
  const handleOpenDiscardModal = (alertIds: number[]) => {
    setTargetAlertsForDiscard(alertIds);
    setDiscardReason('');
    setIsDiscardModalOpen(true);
  };

  // Confirm Bulk Discard
  const handleConfirmDiscard = async () => {
    if (!discardReason.trim()) {
      alert('Por favor ingresa el motivo formal del descarte para el registro de auditoría.');
      return;
    }
    setDiscarding(true);
    try {
      await api.bulkDiscardAlerts({
        alert_ids: targetAlertsForDiscard,
        discard_reason: discardReason.trim(),
      });
      setIsDiscardModalOpen(false);
      setSelectedAlertIds([]);
      fetchAlerts();
      if (selectedAlert && targetAlertsForDiscard.includes(selectedAlert.alert_id)) {
        setSelectedAlert(null);
      }
      alert(`✓ ${targetAlertsForDiscard.length} alerta(s) descartadas con justificación en bitácora.`);
    } catch (err: any) {
      alert('Error descartando alertas: ' + err.message);
    } finally {
      setDiscarding(false);
    }
  };

  // Reopen Discarded Alert
  const handleReopenAlert = async (alertId: number) => {
    try {
      await api.reopenAlert(alertId);
      fetchAlerts();
      setSelectedAlert(null);
      alert(`✓ Alerta #${alertId} reabierta y devuelta a la bandeja de pendientes.`);
    } catch (err: any) {
      alert('Error reabriendo alerta: ' + err.message);
    }
  };

  const [confirmUnlinkAlertId, setConfirmUnlinkAlertId] = useState<number | null>(null);

  // Unlink Alert from Case
  const handleUnlinkAlert = (alertId: number) => {
    setConfirmUnlinkAlertId(alertId);
  };

  const handleExecuteUnlinkAlert = async () => {
    if (confirmUnlinkAlertId === null) return;
    try {
      await api.unlinkAlert(confirmUnlinkAlertId);
      setConfirmUnlinkAlertId(null);
      fetchAlerts();
      setSelectedAlert(null);
    } catch (err: any) {
      alert('Error desvinculando alerta: ' + err.message);
    }
  };

  // Permanent Delete (Admin)
  const handleConfirmDeletePermanent = async () => {
    if (!targetAlertForDelete) return;
    if (!deleteJustification.trim()) {
      alert('Debes ingresar la justificación obligatoria para la eliminación definitiva.');
      return;
    }
    setDeleting(true);
    try {
      await api.deleteAlertPermanently(targetAlertForDelete, deleteJustification.trim());
      setIsDeleteModalOpen(false);
      fetchAlerts();
      setSelectedAlert(null);
      alert(`✓ Alerta #${targetAlertForDelete} eliminada definitivamente.`);
    } catch (err: any) {
      alert('Error eliminando alerta: ' + err.message);
    } finally {
      setDeleting(false);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (orgFilter !== 'ALL' && a.organization !== orgFilter) return false;
    
    // Status filters
    const isClosed = a.alert_status_id === 6 || (a.alert_status_name || '').toLowerCase() === 'closed';
    const isEscalated = Boolean(a.escalated_case_id);

    if (statusFilter === 'pending' && (isClosed || isEscalated)) return false;
    if (statusFilter === 'escalated' && !isEscalated) return false;
    if (statusFilter === 'discarded' && !isClosed) return false;

    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchTitle = (a.alert_title || '').toLowerCase().includes(term);
      const matchDomain = (a.primary_domain || '').toLowerCase().includes(term);
      const matchRef = (a.source_ref || '').toLowerCase().includes(term);
      return matchTitle || matchDomain || matchRef;
    }
    return true;
  });

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, orgFilter, statusFilter, pageSize]);

  const totalPages = Math.ceil(filteredAlerts.length / pageSize) || 1;
  const paginatedAlerts = filteredAlerts.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      <div className="flex-1 flex overflow-hidden">
        {/* Main Alerts List Table */}
        <div className="flex-1 flex flex-col p-6 md:p-8 overflow-y-auto space-y-4">
          {/* Header & Controls */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
            <div className="flex items-center gap-3 flex-1 min-w-[280px] flex-wrap">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Buscar por dominio, ticket o título..."
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
                />
              </div>

              {/* Org Selector */}
              <div className="flex items-center rounded-lg bg-surface-root border border-border-subtle p-0.5 text-xs">
                {(['ALL', 'NBX', 'HP'] as const).map((org) => (
                  <button
                    key={org}
                    onClick={() => setOrgFilter(org)}
                    className={`px-3 py-1 rounded-md font-semibold text-[11px] transition-colors ${
                      orgFilter === org
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {org === 'ALL' ? 'Todas' : org}
                  </button>
                ))}
              </div>

              {/* Status Filter Tabs */}
              <div className="flex items-center rounded-lg bg-surface-root border border-border-subtle p-0.5 text-xs">
                <button
                  onClick={() => setStatusFilter('pending')}
                  className={`px-2.5 py-1 rounded-md font-semibold text-[11px] transition-colors ${
                    statusFilter === 'pending'
                      ? 'bg-amber-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Pendientes
                </button>
                <button
                  onClick={() => setStatusFilter('escalated')}
                  className={`px-2.5 py-1 rounded-md font-semibold text-[11px] transition-colors ${
                    statusFilter === 'escalated'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Escaladas / Vinculadas
                </button>
                <button
                  onClick={() => setStatusFilter('discarded')}
                  className={`px-2.5 py-1 rounded-md font-semibold text-[11px] transition-colors ${
                    statusFilter === 'discarded'
                      ? 'bg-slate-700 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Descartadas
                </button>
                <button
                  onClick={() => setStatusFilter('all')}
                  className={`px-2.5 py-1 rounded-md font-semibold text-[11px] transition-colors ${
                    statusFilter === 'all'
                      ? 'bg-blue-600 text-white shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Todas
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                onClick={() => onNavigate && onNavigate('/ingest')}
                icon={<Bell className="w-3.5 h-3.5" />}
              >
                + Nueva Ingesta
              </Button>
            </div>
          </div>

          {/* Bulk Actions Notification Bar */}
          {selectedAlertIds.length > 0 && (
            <div className="p-3 rounded-xl bg-indigo-950/60 border border-indigo-700/60 flex items-center justify-between gap-3 animate-fade-in shadow-md">
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full bg-indigo-500 text-white text-[10px] font-bold flex items-center justify-center">
                  {selectedAlertIds.length}
                </span>
                <span className="text-xs font-semibold text-white">
                  alerta(s) seleccionadas para triage en lote
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="primary"
                  size="sm"
                  icon={<LinkIcon className="w-3.5 h-3.5 mr-1" />}
                  onClick={() => handleOpenMergeModal(selectedAlertIds)}
                >
                  Vincular a Caso Existente
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<XCircle className="w-3.5 h-3.5 mr-1 text-rose-400" />}
                  onClick={() => handleOpenDiscardModal(selectedAlertIds)}
                >
                  Descartar Seleccionadas
                </Button>
                <button
                  onClick={() => setSelectedAlertIds([])}
                  className="p-1 rounded text-slate-400 hover:text-white"
                  title="Limpiar selección"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Alerts Table */}
          <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm flex-1">
            <div className="overflow-x-auto min-w-full">
              <table className="w-full text-left text-xs whitespace-nowrap">
                <thead className="bg-surface-elevated/70 text-slate-400 uppercase font-bold text-[10px] tracking-wider border-b border-border-subtle">
                  <tr>
                    <th className="py-3 px-3 w-8">
                      <button
                        onClick={handleSelectAll}
                        className="p-1 text-slate-400 hover:text-white"
                        title={selectedAlertIds.length === filteredAlerts.length ? 'Deseleccionar todo' : 'Seleccionar todo'}
                      >
                        {selectedAlertIds.length > 0 && selectedAlertIds.length === filteredAlerts.length ? (
                          <CheckSquare className="w-4 h-4 text-indigo-400" />
                        ) : (
                          <Square className="w-4 h-4 text-slate-500" />
                        )}
                      </button>
                    </th>
                    <th className="py-3 px-4">ID</th>
                    <th className="py-3 px-4">Org</th>
                    <th className="py-3 px-4">Alerta / Activo Reportado</th>
                    <th className="py-3 px-4">Severidad</th>
                    <th className="py-3 px-4">Fuente</th>
                    <th className="py-3 px-4">Estado</th>
                    <th className="py-3 px-4 text-right">Triage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle text-slate-200">
                  {loading ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-slate-400">
                        Cargando alertas desde DFIR-IRIS...
                      </td>
                    </tr>
                  ) : filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-slate-500 italic">
                        No se encontraron alertas para los criterios seleccionados.
                      </td>
                    </tr>
                  ) : (
                    paginatedAlerts.map((a) => {
                      const isSelected = selectedAlert?.alert_id === a.alert_id;
                      const isChecked = selectedAlertIds.includes(a.alert_id);
                      const isEscalated = Boolean(a.escalated_case_id);
                      const obsCount = a.observation_count || 1;

                      return (
                        <tr
                          key={a.alert_id}
                          onClick={() => handleSelectAlert(a)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-blue-900/20 border-l-4 border-l-blue-500'
                              : 'hover:bg-surface-elevated/40'
                          } ${isChecked ? 'bg-indigo-950/30' : ''}`}
                        >
                          <td className="py-3.5 px-3" onClick={(e) => handleToggleSelectRow(a.alert_id, e)}>
                            <button className="p-0.5 text-slate-400 hover:text-white">
                              {isChecked ? (
                                <CheckSquare className="w-4 h-4 text-indigo-400" />
                              ) : (
                                <Square className="w-4 h-4 text-slate-600" />
                              )}
                            </button>
                          </td>
                          <td className="py-3.5 px-4 font-mono font-bold text-slate-400">
                            #{a.alert_id}
                          </td>
                          <td className="py-3.5 px-4">
                            <OrgBadge org={a.organization} />
                          </td>
                          <td className="py-3.5 px-4">
                            <div className="flex flex-col">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-white max-w-lg truncate">
                                  {a.alert_title}
                                </span>
                                {obsCount > 1 && (
                                  <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[10px] font-mono font-bold" title="Incidentes / repeticiones observadas">
                                    {obsCount} obs
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 mt-0.5">
                                {a.primary_domain && (
                                  <span className="text-[11px] font-mono text-cyan-300">
                                    {a.primary_domain}
                                  </span>
                                )}
                                {isEscalated && (
                                  <span className="text-[10px] text-indigo-400 font-mono flex items-center gap-1">
                                    <LinkIcon className="w-2.5 h-2.5" />
                                    Caso #{a.escalated_case_id}
                                  </span>
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="py-3.5 px-4">
                            <Badge
                              variant={
                                a.alert_severity_name?.toLowerCase() === 'high'
                                  ? 'high'
                                  : a.alert_severity_name?.toLowerCase() === 'critical'
                                  ? 'critical'
                                  : 'medium'
                              }
                            >
                              {a.alert_severity_name || 'Medium'}
                            </Badge>
                          </td>
                          <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                            {a.source || 'Manual/Email'}
                          </td>
                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${
                              isEscalated
                                ? 'bg-indigo-950/80 text-indigo-300 border-indigo-700/60'
                                : a.alert_status_id === 6
                                ? 'bg-slate-800 text-slate-400 border-slate-700'
                                : 'bg-surface-elevated text-slate-300 border-border-subtle'
                            }`}>
                              {isEscalated ? 'Escalada / Caso' : a.alert_status_name || 'New'}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <Button size="sm" variant="outline" icon={<ChevronRight className="w-3.5 h-3.5" />}>
                              Triar
                            </Button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Bar */}
            {!loading && filteredAlerts.length > 0 && (
              <div className="px-4 pr-20 py-3 border-t border-border-subtle bg-surface-elevated/40 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
                <div className="flex items-center gap-2">
                  <span>
                    Mostrando <strong className="text-white">{(currentPage - 1) * pageSize + 1}</strong> a{' '}
                    <strong className="text-white">{Math.min(currentPage * pageSize, filteredAlerts.length)}</strong> de{' '}
                    <strong className="text-white">{filteredAlerts.length}</strong> alertas
                  </span>
                  <div className="flex items-center gap-1.5 ml-4">
                    <span>Por pág:</span>
                    <select
                      value={pageSize}
                      onChange={(e) => setPageSize(Number(e.target.value))}
                      className="px-2 py-0.5 rounded bg-surface-card border border-border-subtle text-white text-xs focus:outline-none"
                    >
                      <option value={10}>10</option>
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="p-1.5 rounded border border-border-subtle hover:bg-surface-elevated text-slate-300 disabled:opacity-30 disabled:pointer-events-none transition-colors"
                    title="Página anterior"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                  </button>
                  <span className="px-2 text-xs font-mono text-white">
                    Página {currentPage} de {totalPages}
                  </span>
                  <button
                    type="button"
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="p-1.5 rounded border border-border-subtle hover:bg-surface-elevated text-slate-300 disabled:opacity-30 disabled:pointer-events-none transition-colors"
                    title="Página siguiente"
                  >
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Side-by-Side Triage Drawer */}
        {selectedAlert && (
          <div className="w-[480px] bg-surface-sidebar border-l border-border-subtle shadow-2xl flex flex-col animate-slide-left z-20">
            {/* Drawer Header */}
            <div className="px-6 py-4 border-b border-border-subtle bg-surface-card flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold text-slate-400">
                    ALERTA #{selectedAlert.alert_id}
                  </span>
                  <OrgBadge org={selectedAlert.organization} />
                  {selectedAlert.observation_count && selectedAlert.observation_count > 1 && (
                    <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[10px] font-mono font-bold">
                      {selectedAlert.observation_count} observaciones
                    </span>
                  )}
                </div>
                <h3 className="text-sm font-bold text-white truncate max-w-sm">
                  {selectedAlert.alert_title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-surface-elevated"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs">
              {/* Linked Case Notice */}
              {selectedAlert.escalated_case_id && (
                <div className="p-3.5 rounded-xl bg-indigo-950/40 border border-indigo-700/60 flex items-center justify-between gap-3">
                  <div>
                    <span className="text-[10px] uppercase font-bold text-indigo-400 block">
                      Vinculada a Expediente
                    </span>
                    <a
                      href={`/cases/${selectedAlert.escalated_case_id}`}
                      className="text-xs font-bold text-white hover:underline flex items-center gap-1 mt-0.5"
                    >
                      <span>Caso #{selectedAlert.escalated_case_id}</span>
                      <ExternalLink className="w-3 h-3 text-indigo-400" />
                    </a>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleUnlinkAlert(selectedAlert.alert_id)}
                    icon={<Unlink className="w-3.5 h-3.5 text-rose-400" />}
                  >
                    Desvincular
                  </Button>
                </div>
              )}

              {/* Description & Report */}
              <div>
                <h4 className="text-[10px] uppercase font-bold text-slate-400 mb-1.5">
                  Reporte Original Recibido
                </h4>
                <div className="p-3.5 rounded-xl bg-surface-root border border-border-subtle text-slate-300 font-mono text-[11px] whitespace-pre-wrap leading-relaxed max-h-48 overflow-y-auto">
                  {selectedAlert.alert_description || 'Sin descripción adicional.'}
                </div>
              </div>

              {/* Extracted Parameters Grid */}
              <div>
                <h4 className="text-[10px] uppercase font-bold text-slate-400 mb-1.5">
                  Parámetros Extraídos
                </h4>
                <div className="grid grid-cols-2 gap-2 p-3 rounded-xl bg-surface-card border border-border-subtle">
                  <div>
                    <span className="text-[10px] text-slate-400 block">Dominio Reportado:</span>
                    <span className="font-mono text-cyan-300 font-semibold">{selectedAlert.primary_domain || 'Por corroborar'}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block">Servidor:</span>
                    <span className="font-mono text-slate-200">{selectedAlert.server_name || 'No detectado'}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block">IP Hosting:</span>
                    <span className="font-mono text-slate-200">{selectedAlert.hosting_ip || '—'}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block">IP Reportada:</span>
                    <span className="font-mono text-slate-200">{selectedAlert.reported_ip || '—'}</span>
                  </div>
                </div>
              </div>

              {/* Gemini Copilot Assistant Callout */}
              <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/60 space-y-2">
                <div className="flex items-center gap-2 text-cyan-300 font-bold">
                  <Sparkles className="w-4 h-4" />
                  <span>Asistente Gemini para Triage</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  ¿Requieres validar si la evidencia es verídica o evaluar el impacto técnico?
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => openCopilot(true)}
                  className="w-full text-cyan-300 border-cyan-700/60 hover:bg-cyan-950/60"
                  icon={<Sparkles className="w-3.5 h-3.5" />}
                >
                  Consultar con Copiloto
                </Button>
              </div>

              {/* Triage Decision Actions */}
              <div className="pt-4 border-t border-border-subtle space-y-2.5">
                <h4 className="text-[10px] uppercase font-bold text-slate-400">
                  Decisión de Triage & Escalamiento
                </h4>

                {/* If already discarded, offer reopen */}
                {selectedAlert.alert_status_id === 6 ? (
                  <Button
                    variant="primary"
                    onClick={() => handleReopenAlert(selectedAlert.alert_id)}
                    className="w-full py-2.5 bg-amber-600 hover:bg-amber-500"
                    icon={<RotateCcw className="w-4 h-4" />}
                  >
                    Reabrir Alerta para Re-evaluación
                  </Button>
                ) : (
                  <>
                    <Button
                      variant="primary"
                      loading={escalating}
                      onClick={() => handleEscalate(selectedAlert.alert_id)}
                      className="w-full py-2.5"
                      icon={<ArrowUpRight className="w-4 h-4" />}
                    >
                      Escalar a NUEVO Caso en DFIR-IRIS
                    </Button>

                    <Button
                      variant="secondary"
                      onClick={() => handleOpenMergeModal([selectedAlert.alert_id])}
                      className="w-full py-2"
                      icon={<LinkIcon className="w-4 h-4" />}
                    >
                      Vincular a Caso IRIS Existente
                    </Button>

                    <div className="grid grid-cols-2 gap-2 pt-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleOpenDiscardModal([selectedAlert.alert_id])}
                        icon={<XCircle className="w-3.5 h-3.5 text-slate-400" />}
                      >
                        Descartar Alerta
                      </Button>
                      <a
                        href={`https://iris.tokyo-03.com/alerts?alert_id=${selectedAlert.alert_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center justify-center font-medium rounded-lg px-2.5 py-1 text-xs gap-1.5 border border-border-subtle hover:border-slate-500 text-slate-300 hover:text-white bg-transparent transition-colors"
                      >
                        <span>Ver en IRIS</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </>
                )}

                {/* Admin-only Permanent Delete */}
                <div className="pt-3 border-t border-border-subtle flex justify-end">
                  <button
                    onClick={() => {
                      setTargetAlertForDelete(selectedAlert.alert_id);
                      setDeleteJustification('');
                      setIsDeleteModalOpen(true);
                    }}
                    className="text-[11px] text-rose-400 hover:text-rose-300 flex items-center gap-1 hover:underline"
                  >
                    <Trash2 className="w-3 h-3" />
                    Eliminar alerta definitivamente (Admin)
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modal: Link / Merge Alerts to Compatible Case */}
      {isMergeModalOpen && (
        <Modal
          isOpen={isMergeModalOpen}
          onClose={() => setIsMergeModalOpen(false)}
          title={`Vincular ${targetAlertsForMerge.length} Alerta(s) a Caso Existente`}
          subtitle="Selecciona un caso compatible por dominio, servidor o ticket para unificar la investigación"
        >
          <div className="space-y-4 text-xs">
            {/* Search Box */}
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Buscar caso por número, dominio o ticket..."
                value={compatibleSearch}
                onChange={(e) => setCompatibleSearch(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearchCompatibleCases()}
                className="flex-1 px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
              <Button
                variant="secondary"
                size="sm"
                onClick={handleSearchCompatibleCases}
                icon={<Search className="w-3.5 h-3.5" />}
              >
                Buscar
              </Button>
            </div>

            {/* Compatible Cases List */}
            <div className="border border-border-subtle rounded-xl max-h-60 overflow-y-auto divide-y divide-border-subtle">
              {loadingCompatible ? (
                <div className="p-6 text-center text-text-muted">
                  Buscando expedientes compatibles en DFIR-IRIS...
                </div>
              ) : compatibleCases.length === 0 ? (
                <div className="p-6 text-center text-text-muted">
                  No se encontraron casos directamente coincidentes. Realiza una búsqueda manual arriba.
                </div>
              ) : (
                compatibleCases.map((c) => {
                  const isSelected = selectedTargetCaseId === c.case_id;
                  return (
                    <div
                      key={c.case_id}
                      onClick={() => setSelectedTargetCaseId(c.case_id)}
                      className={`p-3 cursor-pointer transition-colors flex items-center justify-between ${
                        isSelected
                          ? 'bg-indigo-950/60 border-l-4 border-l-indigo-500'
                          : 'hover:bg-surface-elevated/40'
                      }`}
                    >
                      <div className="flex flex-col">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-indigo-400">
                            Caso #{c.case_id}
                          </span>
                          <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-surface-root text-text-muted">
                            {c.state_name || 'Abierto'}
                          </span>
                        </div>
                        <span className="text-text-primary font-medium mt-0.5">
                          {c.case_name}
                        </span>
                      </div>
                      <div className="text-right">
                        <span className="text-[10px] text-text-muted block">
                          {c.primary_domain || c.server_name || ''}
                        </span>
                        <input
                          type="radio"
                          checked={isSelected}
                          onChange={() => setSelectedTargetCaseId(c.case_id)}
                          className="mt-1"
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Note / Justification */}
            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Nota de Vinculación (Se adjuntará a la bitácora del caso)
              </label>
              <textarea
                rows={2}
                placeholder="Indica el motivo de vinculación (ej. Mismo vector de ataque detectado en log Exim)..."
                value={mergeNotes}
                onChange={(e) => setMergeNotes(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
              <Button variant="secondary" size="sm" onClick={() => setIsMergeModalOpen(false)}>
                Cancelar
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={merging}
                disabled={!selectedTargetCaseId}
                onClick={handleConfirmMerge}
                icon={<LinkIcon className="w-3.5 h-3.5" />}
              >
                Confirmar Vinculación al Caso #{selectedTargetCaseId || ''}
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Modal: Bulk Discard with Reason */}
      {isDiscardModalOpen && (
        <Modal
          isOpen={isDiscardModalOpen}
          onClose={() => setIsDiscardModalOpen(false)}
          title={`Descartar ${targetAlertsForDiscard.length} Alerta(s)`}
          subtitle="Registra el motivo formal de descarte para trazabilidad y auditoría"
        >
          <div className="space-y-4 text-xs">
            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Motivo / Justificación del Descarte *
              </label>
              <textarea
                rows={3}
                required
                placeholder="ej. Falso positivo confirmado tras verificación en Bastion y logs Apache. El activo no hospeda contenido malicioso..."
                value={discardReason}
                onChange={(e) => setDiscardReason(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
              <Button variant="secondary" size="sm" onClick={() => setIsDiscardModalOpen(false)}>
                Cancelar
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={discarding}
                onClick={handleConfirmDiscard}
                icon={<XCircle className="w-3.5 h-3.5" />}
                className="bg-rose-600 hover:bg-rose-500"
              >
                Confirmar Descarte
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Modal: Delete Permanently (Admin) */}
      {isDeleteModalOpen && (
        <Modal
          isOpen={isDeleteModalOpen}
          onClose={() => setIsDeleteModalOpen(false)}
          title={`Eliminar Definitivamente Alerta #${targetAlertForDelete}`}
          subtitle="Acción irreversible restringida a roles de administración"
        >
          <div className="space-y-4 text-xs">
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-700/60 text-rose-300">
              <p className="font-semibold">Atención: Esta acción eliminará el registro de alerta tanto de DFIR-IRIS como de la base de datos local.</p>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Justificación de Auditoría Obligatoria *
              </label>
              <textarea
                rows={3}
                required
                placeholder="Motivo estricto por el cual se requiere la eliminación permanente..."
                value={deleteJustification}
                onChange={(e) => setDeleteJustification(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-rose-500"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
              <Button variant="secondary" size="sm" onClick={() => setIsDeleteModalOpen(false)}>
                Cancelar
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={deleting}
                onClick={handleConfirmDeletePermanent}
                icon={<Trash2 className="w-3.5 h-3.5" />}
                className="bg-rose-600 hover:bg-rose-500"
              >
                Eliminar Definitivamente
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* In-app Confirmation Modal for Unlinking Alert */}
      <ConfirmModal
        isOpen={confirmUnlinkAlertId !== null}
        title="Desvincular Alerta de Expediente"
        message={`¿Deseas desvincular la Alerta #${confirmUnlinkAlertId} de su expediente de caso asociado? Podrá volver a ser triada o vinculada posteriormente.`}
        confirmLabel="Desvincular Alerta"
        cancelLabel="Cancelar"
        variant="warning"
        onConfirm={handleExecuteUnlinkAlert}
        onClose={() => setConfirmUnlinkAlertId(null)}
      />
    </div>
  );
};
