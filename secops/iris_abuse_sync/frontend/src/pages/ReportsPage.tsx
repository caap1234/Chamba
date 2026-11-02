import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { 
  FileText, 
  Download, 
  ExternalLink, 
  Search, 
  Eye, 
  RefreshCw, 
  Building2, 
  CheckCircle2, 
  AlertTriangle,
  X,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { api } from '../api/client';
import { OrgBadge, Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';

interface ReportsPageProps {
  onNavigate: (path: string) => void;
  onOpenCase: (caseId: number) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ onNavigate, onOpenCase }) => {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [orgFilter, setOrgFilter] = useState<'ALL' | 'NBX' | 'HP'>('ALL');
  const [previewCaseId, setPreviewCaseId] = useState<number | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const fetchCases = async () => {
    setLoading(true);
    try {
      const data = await api.listCases();
      setCases(data.cases || []);
    } catch (err: any) {
      console.error('Error fetching cases for reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const filteredCases = cases.filter(c => {
    const matchesOrg = orgFilter === 'ALL' || c.organization === orgFilter;
    const caseTitle = c.case_name || c.title || '';
    const caseDomain = c.primary_domain || c.domain || '';
    const caseTicket = c.abuse_ticket_id || c.ticket_id || '';
    const matchesSearch = !searchTerm || 
      caseTitle.toLowerCase().includes(searchTerm.toLowerCase()) ||
      caseDomain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      caseTicket.toLowerCase().includes(searchTerm.toLowerCase()) ||
      String(c.case_id).includes(searchTerm);
    return matchesOrg && matchesSearch;
  });

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, orgFilter, pageSize]);

  const totalPages = Math.ceil(filteredCases.length / pageSize) || 1;
  const paginatedCases = filteredCases.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border-main pb-4">
        <div>
          <h2 className="text-xl font-bold text-text-primary tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-indigo-500" />
            Informes Técnicos & Dictámenes SOC
          </h2>
          <p className="text-xs text-text-muted mt-0.5">
            Generación automatizada de reportes vectoriales en PDF con membrete institucional para NEUBOX y Hospedando
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={fetchCases} disabled={loading}>
            <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} />
            Actualizar Lista
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-surface-card p-3 rounded-lg border border-border-main">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            placeholder="Buscar por caso, dominio o ticket..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-surface-root border border-border-main rounded text-xs text-text-primary focus:outline-none focus:border-indigo-500 placeholder:text-text-muted"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
          <span className="text-xs text-text-muted font-medium mr-1">Organización:</span>
          <div className="flex rounded-md bg-surface-root p-0.5 border border-border-main text-xs">
            <button
              onClick={() => setOrgFilter('ALL')}
              className={`px-3 py-1 rounded font-medium transition-all ${
                orgFilter === 'ALL'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Todas
            </button>
            <button
              onClick={() => setOrgFilter('NBX')}
              className={`px-3 py-1 rounded font-medium transition-all ${
                orgFilter === 'NBX'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              NBX (Neubox)
            </button>
            <button
              onClick={() => setOrgFilter('HP')}
              className={`px-3 py-1 rounded font-medium transition-all ${
                orgFilter === 'HP'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              HP (Hospedando)
            </button>
          </div>
        </div>
      </div>

      {/* Table of cases ready for PDF reporting */}
      <div className="bg-surface-card rounded-lg border border-border-main overflow-hidden shadow-sm">
        <div className="overflow-x-auto min-w-full">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-surface-root border-b border-border-main text-text-muted font-mono uppercase text-[11px]">
                <th className="py-3 px-4 w-16">Caso</th>
                <th className="py-3 px-4 w-28">Org</th>
                <th className="py-3 px-4 min-w-[240px]">Nombre Oficial / Activo</th>
                <th className="py-3 px-4 w-32">Categoría SOC</th>
                <th className="py-3 px-4 w-28">Estado</th>
                <th className="py-3 px-4 w-48 text-right">Acciones de Informe</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-main font-sans">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-text-muted">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-indigo-500" />
                    Cargando casos disponibles para informe...
                  </td>
                </tr>
              ) : filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-text-muted">
                    No se encontraron expedientes con los criterios seleccionados.
                  </td>
                </tr>
              ) : (
                paginatedCases.map((c) => (
                  <tr key={c.case_id} className="hover:bg-surface-root/50 transition-colors">
                    <td className="py-3 px-4 font-mono font-bold text-indigo-400">
                      #{c.case_id}
                    </td>
                    <td className="py-3 px-4">
                      <OrgBadge org={c.organization} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-medium text-text-primary truncate max-w-md">
                        {c.case_name || c.title}
                      </div>
                      <div className="font-mono text-[10px] text-text-muted mt-0.5">
                        {c.primary_domain || c.domain || 'Dominio no extraído'} {(c.abuse_ticket_id || c.ticket_id) ? `| Ticket: ${c.abuse_ticket_id || c.ticket_id}` : ''}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <Badge variant="neutral">
                        {c.category_code?.toUpperCase() || 'GENERAL_ABUSE'}
                      </Badge>
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase font-mono">
                        {c.status_name || 'Abierto'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => setPreviewCaseId(c.case_id)}
                          className="px-2 py-1 text-xs font-medium text-indigo-400 bg-indigo-500/10 hover:bg-indigo-500/20 rounded border border-indigo-500/30 flex items-center gap-1 transition-colors"
                          title="Visualizar informe PDF en modal"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          Vista Previa
                        </button>
                        <a
                          href={api.getReportPdfUrl(c.case_id, true)}
                          download
                          className="px-2 py-1 text-xs font-medium text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 rounded border border-emerald-500/30 flex items-center gap-1 transition-colors"
                          title="Descargar archivo PDF formal"
                        >
                          <Download className="w-3.5 h-3.5" />
                          PDF
                        </a>
                        <button
                          onClick={() => onOpenCase(c.case_id)}
                          className="px-2 py-1 text-xs font-medium text-text-muted hover:text-text-primary bg-surface-root rounded border border-border-main transition-colors"
                          title="Abrir expediente completo"
                        >
                          Expediente
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {!loading && filteredCases.length > 0 && (
          <div className="px-4 pr-20 py-3 border-t border-border-main bg-surface-root/70 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-text-muted">
            <div className="flex items-center gap-2">
              <span>
                Mostrando <strong className="text-text-primary">{(currentPage - 1) * pageSize + 1}</strong> a{' '}
                <strong className="text-text-primary">{Math.min(currentPage * pageSize, filteredCases.length)}</strong> de{' '}
                <strong className="text-text-primary">{filteredCases.length}</strong> expedientes
              </span>
              <div className="flex items-center gap-1.5 ml-4">
                <span>Por pág:</span>
                <select
                  value={pageSize}
                  onChange={(e) => setPageSize(Number(e.target.value))}
                  className="px-2 py-0.5 rounded bg-surface-card border border-border-main text-text-primary text-xs focus:outline-none"
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
                className="p-1.5 rounded border border-border-main hover:bg-surface-card text-text-secondary disabled:opacity-30 disabled:pointer-events-none transition-colors"
                title="Página anterior"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="px-2 text-xs font-mono text-text-primary">
                Página {currentPage} de {totalPages}
              </span>
              <button
                type="button"
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="p-1.5 rounded border border-border-main hover:bg-surface-card text-text-secondary disabled:opacity-30 disabled:pointer-events-none transition-colors"
                title="Página siguiente"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* PDF Modal Preview */}
      {previewCaseId !== null && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in">
          <div className="bg-surface-card border border-border-main rounded-xl w-full max-w-5xl h-[88vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-border-main bg-surface-root">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-text-primary text-sm">
                  Informe Técnico Oficial — Caso #{previewCaseId}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <a
                  href={api.getReportPdfUrl(previewCaseId, false)}
                  target="_blank"
                  rel="noreferrer"
                  className="px-2.5 py-1 text-xs font-medium text-text-muted hover:text-text-primary bg-surface-card rounded border border-border-main flex items-center gap-1.5"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  Nueva Pestaña
                </a>
                <a
                  href={api.getReportPdfUrl(previewCaseId, true)}
                  download
                  className="px-2.5 py-1 text-xs font-medium text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 rounded border border-emerald-500/30 flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  Descargar
                </a>
                <button
                  onClick={() => setPreviewCaseId(null)}
                  className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-surface-card transition-colors ml-2"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="flex-1 bg-slate-900 p-0 relative">
              <iframe
                src={api.getReportPdfUrl(previewCaseId, false)}
                title={`Informe Caso ${previewCaseId}`}
                className="w-full h-full border-0"
              />
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};