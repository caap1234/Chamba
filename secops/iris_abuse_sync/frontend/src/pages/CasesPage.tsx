import React, { useEffect, useState } from 'react';
import {
  Search,
  ExternalLink,
  ChevronRight,
  ChevronLeft,
  FileDown,
  RefreshCw,
  FolderLock,
  Plus,
} from 'lucide-react';
import { Badge, OrgBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { api } from '../api/client';

interface CasesPageProps {
  onNavigate?: (path: string) => void;
  onOpenCase?: (caseId: number) => void;
}

export const CasesPage: React.FC<CasesPageProps> = ({ onNavigate, onOpenCase }) => {
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [orgFilter, setOrgFilter] = useState<'ALL' | 'NBX' | 'HP'>('ALL');
  const [stateFilter, setStateFilter] = useState<'all' | 'open' | 'closed'>('open');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const fetchCases = () => {
    setLoading(true);
    api
      .listCases('all')
      .then((res) => {
        setCases(res.cases || []);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const formatCategory = (catCode?: string) => {
    switch (catCode) {
      case 'abuse_phishing':
        return { label: 'PHISH', variant: 'critical' as const };
      case 'authority_req':
        return { label: 'AUTH', variant: 'high' as const };
      case 'abuse_spam':
        return { label: 'SPAM', variant: 'medium' as const };
      case 'brand_dispute':
        return { label: 'BRAND', variant: 'info' as const };
      case 'account_compromise':
        return { label: 'ACCT', variant: 'high' as const };
      case 'web_compromise':
        return { label: 'COMP', variant: 'high' as const };
      case 'abuse_malware':
        return { label: 'MALW', variant: 'critical' as const };
      case 'blacklist_rbl':
        return { label: 'RBL', variant: 'medium' as const };
      default:
        return { label: 'GENERAL', variant: 'neutral' as const };
    }
  };

  const filteredCases = cases.filter((c) => {
    if (orgFilter !== 'ALL' && c.organization !== orgFilter) return false;
    const isClosed = Boolean(c.is_closed || (c.state_name || '').toLowerCase() === 'closed' || c.state_id === 9);
    if (stateFilter === 'open' && isClosed) return false;
    if (stateFilter === 'closed' && !isClosed) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchName = (c.case_name || '').toLowerCase().includes(term);
      const matchDomain = (c.primary_domain || '').toLowerCase().includes(term);
      const matchTicket = String(c.abuse_ticket_id || '').includes(term);
      const matchServer = (c.server_name || '').toLowerCase().includes(term);
      return matchName || matchDomain || matchTicket || matchServer;
    }
    return true;
  });

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, orgFilter, stateFilter, pageSize]);

  const totalPages = Math.ceil(filteredCases.length / pageSize) || 1;
  const paginatedCases = filteredCases.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const openCount = cases.filter((c) => !c.is_closed && (c.state_name || '').toLowerCase() !== 'closed' && c.state_id !== 9).length;
  const closedCount = cases.filter((c) => c.is_closed || (c.state_name || '').toLowerCase() === 'closed' || c.state_id === 9).length;

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      {/* Page Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 dark:text-white light:text-slate-900 tracking-tight">
            Expedientes de Casos DFIR-IRIS
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-400 light:text-slate-600 mt-0.5">
            Gestión técnica de incidentes activos, bitácora forense y contención ({filteredCases.length} de {cases.length} casos sincronizados)
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={fetchCases}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          >
            Actualizar
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => onNavigate && onNavigate('/ingest')}
            icon={<Plus className="w-3.5 h-3.5" />}
          >
            Nuevo Caso
          </Button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
        <div className="flex items-center gap-3 flex-1 min-w-[300px]">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por caso, dominio, servidor o ticket..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
            />
          </div>

          {/* Org Switcher */}
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

        {/* State Filter Tabs */}
        <div className="flex items-center rounded-lg bg-surface-root border border-border-subtle p-0.5 text-xs">
          <button
            onClick={() => setStateFilter('open')}
            className={`px-3 py-1 rounded-md font-semibold text-[11px] transition-colors ${
              stateFilter === 'open'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Abiertos ({openCount})
          </button>
          <button
            onClick={() => setStateFilter('all')}
            className={`px-3 py-1 rounded-md font-semibold text-[11px] transition-colors ${
              stateFilter === 'all'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Todos ({cases.length})
          </button>
          <button
            onClick={() => setStateFilter('closed')}
            className={`px-3 py-1 rounded-md font-semibold text-[11px] transition-colors ${
              stateFilter === 'closed'
                ? 'bg-slate-700 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Cerrados ({closedCount})
          </button>
        </div>
      </div>

      {/* Cases Table */}
      <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm">
        <div className="overflow-x-auto min-w-full">
          <table className="w-full text-left text-xs whitespace-nowrap">
            <thead className="bg-surface-elevated/70 text-slate-400 uppercase font-bold text-[10px] tracking-wider border-b border-border-subtle">
              <tr>
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">Org</th>
                <th className="py-3 px-4">Nombre Oficial en IRIS</th>
                <th className="py-3 px-4">Categoría SOC</th>
                <th className="py-3 px-4">Activo / Dominio</th>
                <th className="py-3 px-4">Servidor</th>
                <th className="py-3 px-4">Ticket</th>
                <th className="py-3 px-4">Estado</th>
                <th className="py-3 px-4 text-right sticky right-0 bg-surface-elevated/90 backdrop-blur-sm z-10 w-40">
                  Acciones
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle text-slate-200">
              {loading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    Cargando casos desde DFIR-IRIS...
                  </td>
                </tr>
              ) : filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-500 italic">
                    No se encontraron casos con los filtros aplicados.
                  </td>
                </tr>
              ) : (
                paginatedCases.map((c) => {
                  const cat = formatCategory(c.category_code);
                  return (
                    <tr
                      key={c.case_id}
                      className="hover:bg-surface-elevated/40 transition-colors"
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-400">
                        #{c.case_id}
                      </td>
                      <td className="py-3.5 px-4">
                        <OrgBadge org={c.organization} />
                      </td>
                      <td className="py-3.5 px-4 font-semibold text-slate-100 dark:text-white light:text-slate-900 max-w-sm truncate" title={c.case_name}>
                        {c.case_name}
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={cat.variant}>{cat.label}</Badge>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-cyan-400">
                        {c.primary_domain || '—'}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-400">
                        {c.server_name || '—'}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-300">
                        {c.abuse_ticket_id ? `#${c.abuse_ticket_id}` : '—'}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                          {c.state_name || 'Open'}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-right sticky right-0 bg-surface-card/95 backdrop-blur-sm z-10">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => window.open(`/api/v1/cases/${c.case_id}/report.pdf`, '_blank')}
                            title="Ver Informe Técnico PDF"
                            className="p-1.5 rounded-lg text-slate-400 hover:text-blue-400 hover:bg-surface-elevated transition-colors"
                          >
                            <FileDown className="w-3.5 h-3.5" />
                          </button>
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => {
                              if (onOpenCase) onOpenCase(c.case_id);
                              else if (onNavigate) onNavigate(`/cases/${c.case_id}`);
                            }}
                            icon={<ChevronRight className="w-3.5 h-3.5" />}
                          >
                            Workspace
                          </Button>
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
        {!loading && filteredCases.length > 0 && (
          <div className="px-4 pr-20 py-3 border-t border-border-subtle bg-surface-elevated/40 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span>
                Mostrando <strong className="text-white">{(currentPage - 1) * pageSize + 1}</strong> a{' '}
                <strong className="text-white">{Math.min(currentPage * pageSize, filteredCases.length)}</strong> de{' '}
                <strong className="text-white">{filteredCases.length}</strong> casos
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
  );
};
