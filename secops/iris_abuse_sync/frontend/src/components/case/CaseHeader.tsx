import React from 'react';
import { Save, FileDown, ShieldAlert, CheckCircle, ExternalLink, RefreshCw, Database } from 'lucide-react';
import { Button } from '../common/Button';
import { OrgBadge, Badge } from '../common/Badge';

interface CaseHeaderProps {
  caseId: number;
  caseName: string;
  organization: 'NBX' | 'HP' | string;
  stateName: string;
  stateId?: number;
  severity: string;
  saving?: boolean;
  onSave: () => void;
  onExportPdf: () => void;
  onToggleAssetSheet: () => void;
  onRefresh: () => void;
  onStateChange?: (stateId: number) => Promise<void> | void;
  stateCatalog?: Array<{ state_id: number; state_name: string; state_description?: string }>;
  isUpdatingState?: boolean;
}

export const CaseHeader: React.FC<CaseHeaderProps> = ({
  caseId,
  caseName,
  organization,
  stateName,
  stateId,
  severity,
  saving = false,
  onSave,
  onExportPdf,
  onToggleAssetSheet,
  onRefresh,
  onStateChange,
  stateCatalog = [],
  isUpdatingState = false,
}) => {
  const isClosed = stateName.toLowerCase() === 'closed';

  const severityVariant = () => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
        return 'low';
      default:
        return 'neutral';
    }
  };

  const getStateStyle = (name: string, sid?: number) => {
    const sName = (name || '').toLowerCase();
    if (sName.includes('closed') || sid === 9) {
      return 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700';
    }
    if (sName.includes('progress') || sid === 2) {
      return 'bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-700/70';
    }
    if (sName.includes('open') || sid === 3) {
      return 'bg-blue-100 text-blue-900 border-blue-300 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-700/70';
    }
    if (sName.includes('containment') || sid === 4) {
      return 'bg-orange-100 text-orange-900 border-orange-300 dark:bg-orange-950/80 dark:text-orange-300 dark:border-orange-700/70';
    }
    if (sName.includes('eradication') || sid === 5 || sName.includes('recovery') || sid === 6) {
      return 'bg-teal-100 text-teal-900 border-teal-300 dark:bg-teal-950/80 dark:text-teal-300 dark:border-teal-700/70';
    }
    if (sName.includes('post') || sid === 7) {
      return 'bg-cyan-100 text-cyan-900 border-cyan-300 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-700/70';
    }
    if (sName.includes('reporting') || sid === 8) {
      return 'bg-purple-100 text-purple-900 border-purple-300 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-700/70';
    }
    return 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-900 dark:text-slate-300 dark:border-slate-700';
  };

  return (
    <div className="px-8 py-4 bg-surface-card border-b border-border-subtle flex flex-wrap items-center justify-between gap-4">
      {/* Title & Identifiers */}
      <div className="flex items-center gap-3">
        <div className="flex flex-col">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="text-xs font-mono font-bold text-text-muted">CASO #{caseId}</span>
            <OrgBadge org={organization} />
            <Badge variant={severityVariant()}>{severity}</Badge>
            
            {/* Interactive IRIS State Dropdown / Selector */}
            {onStateChange && stateCatalog.length > 0 ? (
              <div className="relative inline-flex items-center">
                <select
                  disabled={isUpdatingState}
                  value={stateId || ''}
                  onChange={(e) => {
                    const sid = parseInt(e.target.value);
                    if (!isNaN(sid)) {
                      onStateChange(sid);
                    }
                  }}
                  className={`px-2.5 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border cursor-pointer appearance-none pr-6 focus:outline-none focus:ring-1 focus:ring-indigo-500 transition-colors ${getStateStyle(
                    stateName,
                    stateId
                  )} ${isUpdatingState ? 'opacity-50 cursor-not-allowed' : ''}`}
                  title="Cambiar estado oficial en DFIR-IRIS"
                >
                  {stateCatalog.map((st) => (
                    <option key={st.state_id} value={st.state_id} className="bg-surface-card text-text-primary text-xs normal-case">
                      {st.state_name}
                    </option>
                  ))}
                </select>
                <div className="pointer-events-none absolute right-1.5 flex items-center text-current opacity-70">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>
            ) : (
              <span
                className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${getStateStyle(
                  stateName,
                  stateId
                )}`}
              >
                {stateName}
              </span>
            )}
          </div>
          <h2 className="text-lg font-bold text-text-primary tracking-tight leading-snug">{caseName}</h2>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onToggleAssetSheet}
          icon={<Database className="w-3.5 h-3.5 text-blue-400" />}
        >
          Ficha del Activo
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          icon={<RefreshCw className="w-3.5 h-3.5 text-slate-400" />}
          title="Recargar datos de DFIR-IRIS"
        >
          Recargar
        </Button>
        <Button
          variant="secondary"
          size="sm"
          onClick={onExportPdf}
          icon={<FileDown className="w-3.5 h-3.5 text-blue-400" />}
        >
          Informe PDF
        </Button>
        <Button
          variant="primary"
          size="sm"
          loading={saving}
          onClick={onSave}
          icon={<Save className="w-3.5 h-3.5" />}
        >
          Guardar Cambios
        </Button>
      </div>
    </div>
  );
};

