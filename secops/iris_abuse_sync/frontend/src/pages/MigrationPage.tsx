import React, { useEffect, useState } from 'react';
import {
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Shield,
  Eye,
  ArrowRight,
  Database,
  Lock,
  X,
  FileCheck,
} from 'lucide-react';
import { HeaderBar } from '../components/navigation/HeaderBar';
import { Button } from '../components/common/Button';
import { Badge, OrgBadge } from '../components/common/Badge';
import { ConfirmModal } from '../components/common/ConfirmModal';
import { api } from '../api/client';
import { MigrationCaseRecord } from '../types';

interface MigrationPageProps {
  onNavigate?: (path: string) => void;
}

export const MigrationPage: React.FC<MigrationPageProps> = ({ onNavigate }) => {
  const [cases, setCases] = useState<MigrationCaseRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [selectedCase, setSelectedCase] = useState<MigrationCaseRecord | null>(null);
  const [previewData, setPreviewData] = useState<any | null>(null);

  const fetchCases = () => {
    setLoading(true);
    api
      .listMigrationCases()
      .then((res) => {
        setCases(res.cases || []);
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleOpenPreview = async (c: MigrationCaseRecord) => {
    setSelectedCase(c);
    setPreviewLoading(true);
    try {
      const res = await api.getMigrationPreview(c.case_id, true);
      setPreviewData(res);
    } catch (err: any) {
      alert(`Error generando previsualización: ${err.message}`);
    } finally {
      setPreviewLoading(false);
    }
  };

  const [confirmMigrationCaseId, setConfirmMigrationCaseId] = useState<number | null>(null);

  const handleApproveMigration = (caseId: number) => {
    setConfirmMigrationCaseId(caseId);
  };

  const handleExecuteApproveMigration = async () => {
    if (confirmMigrationCaseId === null) return;
    const cid = confirmMigrationCaseId;
    try {
      await api.approveMigration(cid, previewData?.proposed);
      setConfirmMigrationCaseId(null);
      fetchCases();
      setSelectedCase(null);
      setPreviewData(null);
    } catch (err: any) {
      alert(`Error aplicando migración: ${err.message}`);
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      <div className="flex-1 flex overflow-hidden">
        {/* Cases Table */}
        <div className="flex-1 flex flex-col p-6 md:p-8 overflow-y-auto space-y-4">
          <div className="p-4 rounded-xl bg-surface-card border border-border-subtle flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>
                <strong>Modo Seguro Activo:</strong> Se toma snapshot inmutable antes de cualquier modificación y se respetan las 3 notas originales.
              </span>
            </div>
            <Button variant="outline" size="sm" onClick={fetchCases} icon={<RefreshCw className="w-3.5 h-3.5" />}>
              Actualizar Lista
            </Button>
          </div>

          <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm">
            <div className="overflow-x-auto min-w-full">
              <table className="w-full text-left text-xs whitespace-nowrap">
              <thead className="bg-surface-elevated/70 text-slate-400 uppercase font-bold text-[10px] tracking-wider border-b border-border-subtle">
                <tr>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Org</th>
                  <th className="py-3 px-4">Caso Histórico</th>
                  <th className="py-3 px-4">Esquema</th>
                  <th className="py-3 px-4">Estado Migración</th>
                  <th className="py-3 px-4">Snapshot SHA-256</th>
                  <th className="py-3 px-4 text-right">Comparativa</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-200">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-400">
                      Escaneando casos históricos en DFIR-IRIS...
                    </td>
                  </tr>
                ) : (
                  cases.map((c) => (
                    <tr key={c.case_id} className="hover:bg-surface-elevated/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-400">#{c.case_id}</td>
                      <td className="py-3.5 px-4">
                        <OrgBadge org={c.organization} />
                      </td>
                      <td className="py-3.5 px-4 font-semibold text-white max-w-sm truncate">
                        {c.case_name}
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-400">
                        {c.schema_version}
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            c.migration_status === 'migrated'
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                              : c.migration_status === 'preview_ready'
                              ? 'bg-blue-950/80 text-blue-400 border border-blue-800/60'
                              : 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                          }`}
                        >
                          {c.migration_status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[10px] text-slate-400">
                        {c.snapshot_sha256 ? `${c.snapshot_sha256.substring(0, 12)}...` : 'Pendiente'}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => handleOpenPreview(c)}
                          icon={<Eye className="w-3.5 h-3.5" />}
                        >
                          Previsualizar
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
            </div>
          </div>
        </div>

        {/* Side-by-Side Dry-Run Comparator Drawer */}
        {selectedCase && (
          <div className="w-[620px] bg-surface-sidebar border-l border-border-subtle shadow-2xl flex flex-col animate-slide-left z-30">
            <div className="px-6 py-4 border-b border-border-subtle bg-surface-card flex items-center justify-between">
              <div>
                <span className="text-xs font-mono font-bold text-slate-400">
                  DRY-RUN COMPARATOR &bull; CASO #{selectedCase.case_id}
                </span>
                <h3 className="text-sm font-bold text-white truncate max-w-md">
                  {selectedCase.case_name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedCase(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-surface-elevated"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
              {previewLoading ? (
                <div className="py-20 text-center text-slate-400">
                  Generando snapshot SHA-256 e interpretando notas antiguas...
                </div>
              ) : previewData ? (
                <>
                  {/* Snapshot Badge */}
                  <div className="p-3.5 rounded-xl bg-surface-card border border-border-subtle text-[11px] font-mono space-y-1">
                    <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                      <FileCheck className="w-4 h-4" /> Snapshot Inmutable Respaldado
                    </div>
                    <div className="text-slate-400 truncate">
                      SHA-256: <span className="text-slate-200">{previewData.snapshot_sha256}</span>
                    </div>
                  </div>

                  {/* Side-by-Side comparison */}
                  <div className="grid grid-cols-2 gap-3">
                    {/* Left: Original v2 */}
                    <div className="p-3.5 rounded-xl bg-surface-root border border-border-subtle space-y-2">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block border-b border-border-subtle pb-1">
                        Estructura Original (v2)
                      </span>
                      <div className="text-slate-300 text-[11px] space-y-1.5">
                        <div>
                          <strong className="text-slate-400">Título:</strong> {previewData.original.case_name}
                        </div>
                        <div>
                          <strong className="text-slate-400">Notas v2:</strong> {previewData.original.notes?.length || 0} notas Markdown
                        </div>
                        <div>
                          <strong className="text-slate-400">IOCs en IRIS:</strong> {previewData.original.iocs?.length || 0}
                        </div>
                        <div>
                          <strong className="text-slate-400">Evidencias:</strong> {previewData.original.evidences?.length || 0}
                        </div>
                      </div>
                    </div>

                    {/* Right: Proposed v3.1 */}
                    <div className="p-3.5 rounded-xl bg-surface-card border border-blue-500/40 space-y-2">
                      <span className="text-[10px] uppercase font-bold text-blue-400 block border-b border-border-subtle pb-1">
                        Propuesta Normalizada (v3.1)
                      </span>
                      <div className="text-slate-200 text-[11px] space-y-1.5">
                        <div>
                          <strong className="text-slate-400">Dominio:</strong> <span className="font-mono text-cyan-300">{previewData.proposed.primary_domain || 'Por corroborar'}</span>
                        </div>
                        <div>
                          <strong className="text-slate-400">Servidor:</strong> <span className="font-mono">{previewData.proposed.server_name || 'No detectado'}</span>
                        </div>
                        <div>
                          <strong className="text-slate-400">Categoría:</strong> <Badge variant="nbx">{previewData.proposed.category_code}</Badge>
                        </div>
                        <div>
                          <strong className="text-slate-400">4 Ejes:</strong> {previewData.proposed.confirmed_incident_type}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Epistemological Separation */}
                  <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border-subtle space-y-2">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">
                      Separación Epistemológica Extraída
                    </span>
                    <div className="space-y-1.5 text-[11px]">
                      <div>
                        <strong className="text-amber-400">Reportado por Tercero:</strong>{' '}
                        <span className="text-slate-300">{previewData.proposed.epistemological_breakdown?.reported_information}</span>
                      </div>
                      <div>
                        <strong className="text-emerald-400">Hechos Confirmados:</strong>{' '}
                        <span className="text-slate-300">{previewData.proposed.epistemological_breakdown?.confirmed_facts}</span>
                      </div>
                    </div>
                  </div>

                  {/* Actions to take */}
                  <div className="pt-4 border-t border-border-subtle space-y-2">
                    <Button
                      variant="primary"
                      className="w-full py-2.5"
                      onClick={() => handleApproveMigration(selectedCase.case_id)}
                      icon={<CheckCircle2 className="w-4 h-4" />}
                    >
                      Aprobar y Sincronizar en DFIR-IRIS
                    </Button>
                    <p className="text-[10px] text-slate-500 text-center">
                      Crea la nota estructurada v3.1, actualiza atributos y preserva todas las notas v2 intactas.
                    </p>
                  </div>
                </>
              ) : null}
            </div>
          </div>
        )}
      </div>

      {/* In-app Confirmation Modal for Migration */}
      <ConfirmModal
        isOpen={confirmMigrationCaseId !== null}
        title="Confirmar Migración a DFIR-IRIS"
        message={`¿Confirmas la migración y sincronización del Caso #${confirmMigrationCaseId} hacia DFIR-IRIS? Se creará la ficha normalizada v3.1 preservando todas las notas originales.`}
        confirmLabel="Migrar Caso"
        cancelLabel="Cancelar"
        variant="primary"
        onConfirm={handleExecuteApproveMigration}
        onClose={() => setConfirmMigrationCaseId(null)}
      />
    </div>
  );
};
