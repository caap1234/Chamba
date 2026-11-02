import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  RefreshCw,
  FileText,
  ShieldCheck,
  AlertCircle,
  Eye,
  CheckCircle2,
  XCircle,
  Play,
  ExternalLink,
  Lock,
} from 'lucide-react';
import { Badge, OrgBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Modal } from '../components/common/Modal';
import { api } from '../api/client';

interface IngestHistoryPageProps {
  onNavigate?: (path: string) => void;
  onOpenCase?: (caseId: number) => void;
}

export const IngestHistoryPage: React.FC<IngestHistoryPageProps> = ({ onNavigate, onOpenCase }) => {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [orgFilter, setOrgFilter] = useState<'ALL' | 'NBX' | 'HP'>('ALL');
  const [statusFilter, setStatusFilter] = useState('all');
  
  // Detail Modal
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [reprocessing, setReprocessing] = useState(false);

  const fetchHistory = () => {
    setLoading(true);
    api
      .getIngestHistory()
      .then((res) => {
        setEvents(res.events || []);
      })
      .catch((err) => console.error('Error fetching ingest history:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleReprocess = async (eventId: number) => {
    setReprocessing(true);
    try {
      const res = await fetch(`/api/v1/ingest/events/${eventId}/reprocess`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Error reprocesando');
      alert('✓ Evento reprocesado con éxito.');
      fetchHistory();
      if (selectedEvent && selectedEvent.id === eventId) {
        setSelectedEvent({
          ...selectedEvent,
          processing_status: 'processed',
          error_message: null,
        });
      }
    } catch (err: any) {
      alert('Error: ' + err.message);
    } finally {
      setReprocessing(false);
    }
  };

  const filteredEvents = events.filter((ev) => {
    if (orgFilter !== 'ALL' && ev.organization !== orgFilter) return false;
    if (statusFilter !== 'all' && ev.processing_status !== statusFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchSub = (ev.subject || '').toLowerCase().includes(term);
      const matchSrc = (ev.source_type || '').toLowerCase().includes(term);
      const matchRep = (ev.reporter || '').toLowerCase().includes(term);
      const matchHash = (ev.evidence_sha256 || '').toLowerCase().includes(term);
      return matchSub || matchSrc || matchRep || matchHash;
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Page Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 dark:text-white light:text-slate-900 tracking-tight flex items-center gap-2">
            <History className="w-5 h-5 text-indigo-400" />
            Historial de Ingesta & Auditoría de Fuentes
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-400 light:text-slate-600 mt-0.5">
            Trazabilidad completa de reportes recibidos por IMAP, Zammad, Webhooks, PDF y entrada manual
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchHistory}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          >
            Actualizar
          </Button>
          {onNavigate && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => onNavigate('/ingest')}
              icon={<FileText className="w-3.5 h-3.5" />}
            >
              Nueva Ingesta
            </Button>
          )}
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por asunto, remitente, hash SHA-256 o fuente..."
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
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-border-subtle bg-surface-elevated text-xs font-semibold text-slate-300 focus:outline-none"
          >
            <option value="all">Todos los Estados</option>
            <option value="processed">Procesados Exitosos</option>
            <option value="alert_created">Alerta Creada</option>
            <option value="case_created">Caso Creado</option>
            <option value="failed">Con Error / Fallidos</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm">
        <div className="overflow-x-auto min-w-full">
          <table className="w-full text-left text-xs whitespace-nowrap">
            <thead className="bg-surface-elevated/70 text-slate-400 uppercase font-bold text-[10px] tracking-wider border-b border-border-subtle">
              <tr>
                <th className="py-3 px-4">Fecha / Hora</th>
                <th className="py-3 px-4">Org</th>
                <th className="py-3 px-4">Canal / Fuente</th>
                <th className="py-3 px-4">Asunto / Resumen</th>
                <th className="py-3 px-4">Evidencia SHA-256</th>
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4">Destino IRIS</th>
                <th className="py-3 px-4 text-right">Detalle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle text-slate-200">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    Cargando historial de ingestas...
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 italic">
                    No se registraron eventos con los filtros seleccionados.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const isSuccess = ['processed', 'alert_created', 'case_created'].includes(ev.processing_status);
                  return (
                    <tr key={ev.id} className="hover:bg-surface-elevated/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                        {ev.received_at ? new Date(ev.received_at).toLocaleString() : '—'}
                      </td>
                      <td className="py-3.5 px-4">
                        <OrgBadge org={ev.organization} />
                      </td>
                      <td className="py-3.5 px-4 font-mono">
                        <span className="px-2 py-0.5 rounded bg-surface-elevated text-indigo-300 border border-indigo-900/40 text-[10px] font-semibold uppercase">
                          {ev.source_type}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 max-w-xs truncate font-medium text-slate-100 dark:text-white light:text-slate-900" title={ev.subject}>
                        {ev.subject || 'Sin asunto'}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[10px] text-slate-400">
                        {ev.evidence_sha256 ? (
                          <span title={ev.evidence_sha256}>
                            {ev.evidence_sha256.slice(0, 12)}...
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={isSuccess ? 'success' : ev.processing_status === 'failed' ? 'critical' : 'neutral'}>
                          {ev.processing_status}
                        </Badge>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-xs">
                        {ev.iris_case_id ? (
                          <button
                            onClick={() => onOpenCase ? onOpenCase(ev.iris_case_id) : onNavigate?.(`/cases/${ev.iris_case_id}`)}
                            className="text-blue-400 hover:underline flex items-center gap-1"
                          >
                            <span>Caso #{ev.iris_case_id}</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        ) : ev.iris_alert_id ? (
                          <button
                            onClick={() => onNavigate?.('/alerts')}
                            className="text-cyan-400 hover:underline flex items-center gap-1"
                          >
                            <span>Alerta #{ev.iris_alert_id}</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        ) : (
                          <span className="text-slate-500">—</span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setSelectedEvent(ev)}
                          icon={<Eye className="w-3.5 h-3.5" />}
                        >
                          Ver
                        </Button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedEvent && (
        <Modal
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title={`Evento de Ingesta #${selectedEvent.id}`}
          subtitle={`${selectedEvent.source_type.toUpperCase()} • ${selectedEvent.organization} • ${selectedEvent.received_at ? new Date(selectedEvent.received_at).toLocaleString() : ''}`}
          size="xl"
        >
          <div className="space-y-5 text-xs text-slate-300">
            {/* Status summary */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-surface-elevated/70 border border-border-subtle">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Estado del Procesamiento:</span>
                <Badge variant={selectedEvent.processing_status === 'failed' ? 'critical' : 'success'}>
                  {selectedEvent.processing_status}
                </Badge>
              </div>
              {selectedEvent.evidence_sha256 && (
                <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400">
                  <Lock className="w-3 h-3 text-emerald-400" />
                  <span>SHA-256: {selectedEvent.evidence_sha256}</span>
                </div>
              )}
            </div>

            {/* Error Message if present */}
            {selectedEvent.error_message && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold block mb-0.5">Error de Ingesta:</span>
                  <p>{selectedEvent.error_message}</p>
                </div>
              </div>
            )}

            {/* Subject and Content */}
            <div className="space-y-1">
              <span className="text-slate-400 font-semibold block uppercase tracking-wider text-[10px]">
                Asunto / Título:
              </span>
              <p className="font-medium text-slate-100 dark:text-white light:text-slate-900 bg-surface-root p-2 rounded border border-border-subtle">
                {selectedEvent.subject || 'Sin asunto'}
              </p>
            </div>

            {selectedEvent.original_content && (
              <div className="space-y-1">
                <span className="text-slate-400 font-semibold block uppercase tracking-wider text-[10px]">
                  Extracto de Contenido Original:
                </span>
                <pre className="p-3 rounded bg-surface-root border border-border-subtle font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                  {selectedEvent.original_content}
                </pre>
              </div>
            )}

            {/* Actions in Modal */}
            <div className="flex items-center justify-between pt-4 border-t border-border-subtle">
              <Button
                variant="secondary"
                size="sm"
                loading={reprocessing}
                onClick={() => handleReprocess(selectedEvent.id)}
                icon={<Play className="w-3.5 h-3.5 text-emerald-400" />}
              >
                Reprocesar Heurísticas & Normalización
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setSelectedEvent(null)}>
                Cerrar
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

