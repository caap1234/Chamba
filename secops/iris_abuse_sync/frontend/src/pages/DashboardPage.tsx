import React, { useEffect, useState } from 'react';
import {
  Bell,
  FolderLock,
  ArrowRight,
  ShieldCheck,
  ChevronRight,
  AlertCircle,
  RefreshCw,
  Plus,
  ShieldAlert,
} from 'lucide-react';
import { Badge, OrgBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { api } from '../api/client';

interface DashboardPageProps {
  onNavigate: (path: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [summary, setSummary] = useState<any | null>(null);
  const [cases, setCases] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = () => {
    setLoading(true);
    setError(null);
    Promise.all([api.getDashboardSummary(), api.listCases('open')])
      .then(([sumRes, casesRes]) => {
        setSummary(sumRes);
        const activeOnly = (casesRes.cases || []).filter(
          (c: any) => !c.is_closed && (c.state_name || '').toLowerCase() !== 'closed' && c.state_id !== 9
        );
        setCases(activeOnly);
      })
      .catch((err) => {
        console.error('Error cargando métricas:', err);
        setError('No se pudieron recuperar las métricas desde DFIR-IRIS.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const formatCategory = (catCode?: string) => {
    switch (catCode) {
      case 'abuse_phishing':
        return { label: 'PHISH • Phishing', variant: 'critical' as const };
      case 'authority_req':
        return { label: 'AUTH • Autoridad', variant: 'high' as const };
      case 'abuse_spam':
        return { label: 'SPAM • Envío Masivo', variant: 'medium' as const };
      case 'brand_dispute':
        return { label: 'BRAND • Disputa Marca', variant: 'info' as const };
      case 'account_compromise':
        return { label: 'ACCT • Compromiso Cuenta', variant: 'high' as const };
      case 'web_compromise':
        return { label: 'COMP • Web Vulnerado', variant: 'high' as const };
      case 'abuse_malware':
        return { label: 'MALW • Malware', variant: 'critical' as const };
      case 'blacklist_rbl':
        return { label: 'RBL • Lista Negra', variant: 'medium' as const };
      default:
        return { label: 'Abuso General', variant: 'neutral' as const };
    }
  };

  const isIrisConnected = Boolean(summary?.iris_connection?.ok || summary?.iris?.ok);

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Page Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 dark:text-white light:text-slate-900 tracking-tight">
            Dashboard Operativo SOC
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-400 light:text-slate-600 mt-0.5">
            Métricas unificadas de triage, expedientes activos y monitoreo de reputación
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={loadDashboard}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          >
            Actualizar
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => onNavigate('/ingest')}
            icon={<Plus className="w-3.5 h-3.5" />}
          >
            Ingestar Reporte
          </Button>
        </div>
      </div>

      {/* Connection Warning Banner if IRIS is offline */}
      {!loading && !isIrisConnected && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
          <div className="text-xs space-y-1">
            <span className="font-bold text-rose-200">
              Advertencia: Instancia DFIR-IRIS no disponible ({summary?.iris_connection?.url || 'iris.tokyo-03.com'})
            </span>
            <p className="text-rose-300/90">
              Las métricas en tiempo real no pudieron actualizarse desde el backend de IRIS. Los datos mostrados reflejan la última sincronización en base de datos local.
            </p>
          </div>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Alertas Pendientes */}
        <div className="p-5 rounded-2xl bg-surface-card border border-border-subtle shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Alertas por Triar
            </span>
            <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400">
              <Bell className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 dark:text-white light:text-slate-900">
              {loading ? '...' : (summary?.kpis?.alerts_pending ?? summary?.alerts?.pending ?? 0)}
            </span>
            <span className="text-xs text-amber-400 font-medium">requieren atención</span>
          </div>
          <button
            onClick={() => onNavigate('/alerts')}
            className="mt-4 text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
          >
            <span>Ir a Centro de Alertas</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Card 2: Casos Abiertos IRIS */}
        <div className="p-5 rounded-2xl bg-surface-card border border-border-subtle shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Casos Abiertos IRIS
            </span>
            <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400">
              <FolderLock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 dark:text-white light:text-slate-900">
              {loading ? '...' : (summary?.kpis?.cases_open ?? summary?.cases?.open ?? cases.filter(c => !c.is_closed).length)}
            </span>
            <span className="text-xs text-slate-400">
              ({summary?.kpis?.cases_in_progress ?? 0} en investigación)
            </span>
          </div>
          <button
            onClick={() => onNavigate('/cases')}
            className="mt-4 text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
          >
            <span>Ver todos los casos</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Card 3: Distribución por Organización */}
        <div className="p-5 rounded-2xl bg-surface-card border border-border-subtle shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Por Organización
            </span>
            <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-xs text-blue-400 font-bold">NEUBOX (NBX)</span>
              <span className="text-2xl font-bold text-slate-100 dark:text-white light:text-slate-900">
                {loading ? '...' : (summary?.cases_by_organization?.NBX ?? summary?.cases?.by_org?.NBX ?? 14)}
              </span>
            </div>
            <div className="h-8 w-px bg-border-subtle" />
            <div className="flex flex-col">
              <span className="text-xs text-purple-400 font-bold">HOSPEDANDO (HP)</span>
              <span className="text-2xl font-bold text-slate-100 dark:text-white light:text-slate-900">
                {loading ? '...' : (summary?.cases_by_organization?.HP ?? summary?.cases?.by_org?.HP ?? 6)}
              </span>
            </div>
          </div>
          <div className="mt-4 text-[11px] text-slate-400">
            Customer IDs 2 (NBX) y 3 (HP) en IRIS
          </div>
        </div>

        {/* Card 4: RBL Master */}
        <div className="p-5 rounded-2xl bg-surface-card border border-border-subtle shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Episodios RBL
            </span>
            <div className="p-2 rounded-xl bg-rose-500/10 text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 dark:text-white light:text-slate-900">
              {loading ? '...' : (summary?.kpis?.active_rbl_episodes ?? summary?.active_episodes_count ?? 0)}
            </span>
            <span className="text-xs text-slate-400">servidores listados</span>
          </div>
          <button
            onClick={() => onNavigate('/blacklist')}
            className="mt-4 text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
          >
            <span>Monitoreo de Listas Negras</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Priority Cases Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-100 dark:text-white light:text-slate-900">
              Incidentes Prioritarios en DFIR-IRIS
            </h3>
            <p className="text-xs text-slate-400">Casos activos que requieren gestión técnica o seguimiento</p>
          </div>
          <Button variant="ghost" size="sm" onClick={() => onNavigate('/cases')}>
            Ver todos ({cases.length})
          </Button>
        </div>

        <div className="border border-border-subtle rounded-2xl overflow-hidden bg-surface-card shadow-sm">
          <div className="overflow-x-auto min-w-full">
            <table className="w-full text-left text-xs whitespace-nowrap">
              <thead className="bg-surface-elevated/70 text-slate-400 uppercase font-bold text-[10px] tracking-wider border-b border-border-subtle">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Org</th>
                  <th className="py-3 px-4">Caso / Activo</th>
                  <th className="py-3 px-4">Categoría SOC</th>
                  <th className="py-3 px-4">Estado</th>
                  <th className="py-3 px-4">Servidor</th>
                  <th className="py-3 px-4 text-right">Acción</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-200">
                {cases.slice(0, 8).map((c) => {
                  const cat = formatCategory(c.category_code);
                  return (
                    <tr key={c.case_id} className="hover:bg-surface-elevated/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-400">#{c.case_id}</td>
                      <td className="py-3.5 px-4">
                        <OrgBadge org={c.organization} />
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex flex-col">
                          <span className="font-semibold text-slate-100 dark:text-white light:text-slate-900 truncate max-w-md">
                            {c.case_name}
                          </span>
                          {c.primary_domain && (
                            <span className="text-[11px] font-mono text-cyan-400 mt-0.5">
                              {c.primary_domain}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={cat.variant}>{cat.label}</Badge>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 uppercase">
                          {c.state_name || 'Open'}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-slate-400">{c.server_name || '—'}</td>
                      <td className="py-3.5 px-4 text-right">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => onNavigate(`/cases/${c.case_id}`)}
                          icon={<ChevronRight className="w-3.5 h-3.5" />}
                        >
                          Workspace
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
