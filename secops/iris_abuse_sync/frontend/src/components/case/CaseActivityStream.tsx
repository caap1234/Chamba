import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Paperclip,
  CheckCircle2,
  Copy,
  Check,
  UploadCloud,
  FileText,
  Search,
  MessageSquare,
  Sparkles,
  RefreshCw,
  Send,
  Image as ImageIcon,
  Trash2,
  Edit3,
  X,
  CheckSquare,
  Square,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../../api/client';
import { Button } from '../common/Button';
import { MarkdownEditor } from '../common/MarkdownEditor';
import { ConfirmModal } from '../common/ConfirmModal';

export interface ActivityItem {
  id: number;
  iris_case_id: number;
  playbook_execution_id?: number | null;
  step_order?: number | null;
  activity_type: 'investigacion' | 'accion' | 'evidencia' | 'comunicacion' | 'nota';
  title: string;
  content: string;
  metadata_json?: Record<string, any>;
  action_status?: string | null;
  iris_evidence_id?: number | null;
  iris_task_id?: number | null;
  iris_timeline_id?: number | null;
  sync_status: string;
  analyst_username: string;
  created_at: string;
  updated_at?: string;
}

interface CaseActivityStreamProps {
  caseId: number;
  activeExecutionId?: number | null;
  activeStepOrder?: number | null;
  onRefreshBundle?: () => void;
  onStepCompleted?: (stepOrder: number) => void;
}

export const CaseActivityStream: React.FC<CaseActivityStreamProps> = ({
  caseId,
  activeExecutionId,
  activeStepOrder,
  onRefreshBundle,
  onStepCompleted,
}) => {
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState<string>('investigacion');
  const [copiedId, setCopiedId] = useState<number | null>(null);

  // Multi-Selection State for Batch Operations
  const [selectedActivityIds, setSelectedActivityIds] = useState<number[]>([]);
  const [confirmBatchDelete, setConfirmBatchDelete] = useState(false);
  const [isDeletingBatch, setIsDeletingBatch] = useState(false);

  // Single Item Delete Confirmation State
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const [isDeletingSingle, setIsDeletingSingle] = useState(false);

  // Composer State
  const [composerType, setComposerType] = useState<'investigacion' | 'accion' | 'evidencia' | 'comunicacion'>('investigacion');
  const [composerTitle, setComposerTitle] = useState('');
  const [composerContent, setComposerContent] = useState('');
  const [composerActionStatus, setComposerActionStatus] = useState('pendiente');
  const [composerSource, setComposerSource] = useState('Bastion');
  const [composerCommChannel, setComposerCommChannel] = useState('cliente_whmcs');
  const [composerTicketRef, setComposerTicketRef] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Evidence & Clipboard State
  const [pastedImageBase64, setPastedImageBase64] = useState<string | null>(null);
  const [pastedImagePreview, setPastedImagePreview] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileDescription, setFileDescription] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropZoneRef = useRef<HTMLDivElement>(null);

  // Compiling Note state
  const [compilingNote, setCompilingNote] = useState(false);
  const [compileSuccess, setCompileSuccess] = useState<string | null>(null);

  // Inline WYSIWYG Edit Activity State
  const [editingActivityId, setEditingActivityId] = useState<number | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [editContent, setEditContent] = useState('');
  const [editActionStatus, setEditActionStatus] = useState('pendiente');
  const [savingEdit, setSavingEdit] = useState(false);

  const handleStartInlineEdit = (act: ActivityItem) => {
    setEditingActivityId(act.id);
    setEditTitle(act.title);
    setEditContent(act.content || '');
    setEditActionStatus(act.action_status || 'pendiente');
  };

  const handleCancelInlineEdit = () => {
    setEditingActivityId(null);
  };

  const handleSaveInlineEdit = async (actId: number) => {
    setSavingEdit(true);
    try {
      await api.updateCaseActivity(caseId, actId, {
        title: editTitle.trim(),
        content: editContent.trim(),
        action_status: editActionStatus,
      });

      // Optimistic in-place update
      setActivities((prev) =>
        prev.map((a) =>
          a.id === actId
            ? {
                ...a,
                title: editTitle.trim(),
                content: editContent.trim(),
                action_status: a.activity_type === 'accion' ? editActionStatus : a.action_status,
              }
            : a
        )
      );
      setEditingActivityId(null);
      await loadActivities(true);
      if (onRefreshBundle) onRefreshBundle();
    } catch (err: any) {
      alert('Error actualizando actividad: ' + (err.message || 'Error de red'));
    } finally {
      setSavingEdit(false);
    }
  };

  const loadActivities = async (silent: boolean = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await api.getCaseActivity(caseId);
      if (res.activities) {
        setActivities(res.activities);
      }
    } catch (err: any) {
      console.error('Error cargando bitácora operativa:', err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    loadActivities();
  }, [caseId]);

  // Handle global paste for screenshots
  useEffect(() => {
    const handlePaste = (e: ClipboardEvent) => {
      const items = e.clipboardData?.items;
      if (!items) return;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1) {
          const file = items[i].getAsFile();
          if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
              const b64 = event.target?.result as string;
              setPastedImageBase64(b64);
              setPastedImagePreview(b64);
              setComposerType('evidencia');
              setComposerTitle(`Captura pegada (${new Date().toLocaleTimeString()})`);
            };
            reader.readAsDataURL(file);
            e.preventDefault();
            break;
          }
        }
      }
    };

    window.addEventListener('paste', handlePaste);
    return () => window.removeEventListener('paste', handlePaste);
  }, []);

  const handleCopyText = (id: number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCreateActivity = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!composerTitle.trim()) return;

    setSubmitting(true);
    try {
      if (composerType === 'evidencia') {
        if (selectedFile || pastedImageBase64) {
          await api.uploadCaseActivityEvidence(caseId, {
            file: selectedFile || undefined,
            base64_data: pastedImageBase64 || undefined,
            title: composerTitle,
            description: fileDescription || composerContent,
            step_order: activeStepOrder || undefined,
            playbook_execution_id: activeExecutionId || undefined,
          });
          setSelectedFile(null);
          setPastedImageBase64(null);
          setPastedImagePreview(null);
          setFileDescription('');
        } else {
          alert('Selecciona un archivo o pega una captura de pantalla del portapapeles.');
          setSubmitting(false);
          return;
        }
      } else {
        const metadata: Record<string, any> = {};
        if (composerType === 'investigacion') {
          metadata.source_consulted = composerSource;
        } else if (composerType === 'comunicacion') {
          metadata.channel = composerCommChannel;
          metadata.ticket_reference = composerTicketRef;
        }

        await api.addCaseActivity(caseId, {
          activity_type: composerType,
          title: composerTitle,
          content: composerContent,
          action_status: composerType === 'accion' ? composerActionStatus : undefined,
          metadata_json: metadata,
          step_order: activeStepOrder || undefined,
          playbook_execution_id: activeExecutionId || undefined,
          sync_to_iris: true,
        });
      }

      setComposerTitle('');
      setComposerContent('');
      setComposerTicketRef('');
      await loadActivities(true);
      if (onRefreshBundle) onRefreshBundle();
      if (activeStepOrder && onStepCompleted) onStepCompleted(activeStepOrder);
    } catch (err: any) {
      alert('Error registrando en bitácora: ' + (err.message || 'Error de red'));
    } finally {
      setSubmitting(false);
    }
  };

  // Single Item Deletion via In-App ConfirmModal
  const handleExecuteSingleDelete = async () => {
    if (confirmDeleteId === null) return;
    setIsDeletingSingle(true);
    const idToDelete = confirmDeleteId;
    try {
      // Optimistic delete
      setActivities((prev) => prev.filter((a) => a.id !== idToDelete));
      setSelectedActivityIds((prev) => prev.filter((id) => id !== idToDelete));
      await api.deleteCaseActivity(caseId, idToDelete);
      setConfirmDeleteId(null);
      await loadActivities(true);
      if (onRefreshBundle) onRefreshBundle();
    } catch (err: any) {
      alert(`Error eliminando registro: ${err.message || 'Error de red'}`);
      await loadActivities(true);
    } finally {
      setIsDeletingSingle(false);
    }
  };

  // Multi-Selection Toggle
  const toggleSelectActivity = (id: number) => {
    setSelectedActivityIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedActivityIds.length === filteredActivities.length) {
      setSelectedActivityIds([]);
    } else {
      setSelectedActivityIds(filteredActivities.map((a) => a.id));
    }
  };

  // Batch Deletion via In-App ConfirmModal
  const handleExecuteBatchDelete = async () => {
    if (selectedActivityIds.length === 0) return;
    setIsDeletingBatch(true);
    const idsToDelete = [...selectedActivityIds];
    try {
      // Optimistic removal
      setActivities((prev) => prev.filter((a) => !idsToDelete.includes(a.id)));
      setSelectedActivityIds([]);
      await api.bulkDeleteCaseActivity(caseId, idsToDelete);
      setConfirmBatchDelete(false);
      await loadActivities(true);
      if (onRefreshBundle) onRefreshBundle();
    } catch (err: any) {
      alert(`Error en eliminación múltiple: ${err.message || 'Error de red'}`);
      await loadActivities(true);
    } finally {
      setIsDeletingBatch(false);
    }
  };

  const handleUpdateStatus = async (act: ActivityItem, newStatus: string) => {
    try {
      // Optimistic update
      setActivities((prev) =>
        prev.map((a) => (a.id === act.id ? { ...a, action_status: newStatus } : a))
      );
      await api.updateCaseActivity(caseId, act.id, { action_status: newStatus });
      if (onRefreshBundle) onRefreshBundle();
    } catch (err: any) {
      alert('Error actualizando estado: ' + err.message);
      await loadActivities(true);
    }
  };

  const handleCompileMarkdown = async () => {
    setCompilingNote(true);
    setCompileSuccess(null);
    try {
      await api.compileMarkdownNotesFromActivity(caseId);
      setCompileSuccess('¡Ficha Operativa compilada y sincronizada exitosamente con la Nota Oficial de IRIS!');
      if (onRefreshBundle) onRefreshBundle();
      setTimeout(() => setCompileSuccess(null), 5000);
    } catch (err: any) {
      alert('Error compilando notas: ' + err.message);
    } finally {
      setCompilingNote(false);
    }
  };

  const filteredActivities = activities.filter((a) => {
    if (filterType === 'all') return true;
    return a.activity_type === filterType;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner / Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-blue-500" />
            <h3 className="text-sm font-bold text-text-primary">Bitácora Operativa Unificada</h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 border border-blue-300 dark:border-blue-700 font-semibold">
              DFIR-IRIS Datastore Source of Truth
            </span>
          </div>
          <p className="text-xs text-text-muted mt-0.5">
            Registra comandos, hallazgos técnicos, capturas de pantalla (<kbd className="font-mono px-1 py-0.5 bg-surface-root border border-border-subtle rounded text-[10px]">Cmd+V</kbd>) y acciones sin duplicación.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Sincronización en IRIS Activa</span>
          </div>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => loadActivities(true)}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Actualizar
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={handleCompileMarkdown}
            loading={compilingNote}
            icon={<Sparkles className="w-3.5 h-3.5" />}
            title="Recompilar manualmente la ficha técnica oficial"
          >
            Forzar Recompilación
          </Button>
        </div>
      </div>

      {compileSuccess && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
          <span>{compileSuccess}</span>
        </div>
      )}

      {/* Unified Composer Box */}
      <div className="p-5 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-border-subtle pb-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-text-primary">Nueva Documentación:</span>
            <div className="flex items-center gap-1 bg-surface-root p-0.5 rounded-lg border border-border-subtle">
              <button
                type="button"
                onClick={() => setComposerType('investigacion')}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  composerType === 'investigacion'
                    ? 'bg-blue-600 text-white font-bold shadow-sm'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                🔍 Investigación / Log
              </button>
              <button
                type="button"
                onClick={() => setComposerType('accion')}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  composerType === 'accion'
                    ? 'bg-indigo-600 text-white font-bold shadow-sm'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                ⚡ Acción Operativa
              </button>
              <button
                type="button"
                onClick={() => setComposerType('evidencia')}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  composerType === 'evidencia'
                    ? 'bg-emerald-600 text-white font-bold shadow-sm'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                📎 Evidencia / Captura
              </button>
              <button
                type="button"
                onClick={() => setComposerType('comunicacion')}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  composerType === 'comunicacion'
                    ? 'bg-amber-600 text-white font-bold shadow-sm'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                💬 Comunicación / Aviso
              </button>
            </div>
          </div>

          {activeStepOrder && (
            <span className="text-[11px] font-mono text-indigo-400 bg-indigo-500/10 px-2.5 py-1 rounded border border-indigo-500/30">
              Vinculando a Paso #{activeStepOrder} de Playbook
            </span>
          )}
        </div>

        <form onSubmit={handleCreateActivity} className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <input
                type="text"
                placeholder={
                  composerType === 'investigacion'
                    ? 'Título o consulta realizada (ej. stat Adobe_Installer.html o WHOIS lottmail.com)'
                    : composerType === 'accion'
                    ? 'Título de la acción o medida de contención (ej. Suspensión cPanel / Cuarentena)'
                    : composerType === 'comunicacion'
                    ? 'Asunto o aviso (ej. 2do Aviso de Suspensión por Phishing ticket #792053)'
                    : 'Título descriptivo de la evidencia (ej. Captura cPanel Fileman / Adobe_Installer.html)'
                }
                value={composerTitle}
                onChange={(e) => setComposerTitle(e.target.value)}
                className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-blue-500"
                required
              />
            </div>

            {composerType === 'investigacion' && (
              <div>
                <select
                  value={composerSource}
                  onChange={(e) => setComposerSource(e.target.value)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-blue-500"
                >
                  <option value="Bastion">Bastion SSH</option>
                  <option value="DNS / WHOIS">DNS / WHOIS</option>
                  <option value="cPanel / DirectAdmin">cPanel / DirectAdmin</option>
                  <option value="Apache / Nginx Access Log">Apache / Nginx Access Log</option>
                  <option value="Exim / Mail Queue">Exim / Mail Queue</option>
                  <option value="ClamAV / Imunify">ClamAV / Imunify</option>
                  <option value="WHMCS">WHMCS</option>
                </select>
              </div>
            )}

            {composerType === 'accion' && (
              <div>
                <select
                  value={composerActionStatus}
                  onChange={(e) => setComposerActionStatus(e.target.value)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-blue-500 font-semibold"
                >
                  <option value="propuesta">Propuesta</option>
                  <option value="pendiente">Pendiente</option>
                  <option value="en_ejecucion">En Ejecución</option>
                  <option value="ejecutada">Ejecutada</option>
                  <option value="verificada">Verificada</option>
                  <option value="omitida">Omitida</option>
                </select>
              </div>
            )}

            {composerType === 'comunicacion' && (
              <div className="flex gap-2">
                <select
                  value={composerCommChannel}
                  onChange={(e) => setComposerCommChannel(e.target.value)}
                  className="w-1/2 text-xs px-2 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-amber-500 font-medium"
                >
                  <option value="cliente_whmcs">WHMCS (Cliente)</option>
                  <option value="cliente_zammad">Zammad (Cliente)</option>
                  <option value="email_abuse">Abuse Desk (Reportante)</option>
                  <option value="datacenter">Datacenter (Upstream)</option>
                  <option value="soc_interno">Interno SOC</option>
                </select>
                <input
                  type="text"
                  placeholder="Ticket / Ref #"
                  value={composerTicketRef}
                  onChange={(e) => setComposerTicketRef(e.target.value)}
                  className="w-1/2 text-xs px-2.5 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>
            )}
          </div>

          {composerType === 'evidencia' ? (
            <div className="space-y-3">
              {pastedImagePreview ? (
                <div className="relative p-3 rounded-lg bg-surface-root border border-emerald-500/40">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                      <ImageIcon className="w-4 h-4" />
                      Captura detectada desde el portapapeles
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setPastedImageBase64(null);
                        setPastedImagePreview(null);
                      }}
                      className="text-xs text-rose-400 hover:underline"
                    >
                      Quitar captura
                    </button>
                  </div>
                  <img
                    src={pastedImagePreview}
                    alt="Pasted preview"
                    className="max-h-56 rounded border border-border-subtle object-contain bg-black/40"
                  />
                </div>
              ) : (
                <div
                  ref={dropZoneRef}
                  onClick={() => fileInputRef.current?.click()}
                  className="p-6 border-2 border-dashed border-border-subtle hover:border-emerald-500/50 rounded-xl text-center cursor-pointer transition-all bg-surface-root/40 hover:bg-surface-root"
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setSelectedFile(e.target.files[0]);
                        if (!composerTitle) setComposerTitle(e.target.files[0].name);
                      }
                    }}
                  />
                  <UploadCloud className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                  <p className="text-xs font-semibold text-text-primary">
                    {selectedFile ? `Archivo: ${selectedFile.name} (${selectedFile.size} bytes)` : 'Arrastra un archivo aquí o haz clic para explorar'}
                  </p>
                  <p className="text-[11px] text-text-muted mt-1">
                    O presiona <kbd className="px-1 py-0.5 bg-surface-elevated rounded border border-border-subtle font-mono text-[10px]">Cmd+V</kbd> para pegar cualquier captura de pantalla directamente.
                  </p>
                </div>
              )}

              <input
                type="text"
                placeholder="Descripción adicional de la evidencia forense..."
                value={fileDescription}
                onChange={(e) => setFileDescription(e.target.value)}
                className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-blue-500"
              />
            </div>
          ) : (
            <div>
              <MarkdownEditor
                value={composerContent}
                onChange={setComposerContent}
                textareaId="bitacora-composer-md"
                minHeight="140px"
                placeholder={
                  composerType === 'investigacion'
                    ? 'Pega aquí el resultado del comando, log de servidor, salida de WHOIS o hallazgo técnico...'
                    : 'Detalles, justificación y resultado técnico de la acción ejecutada...'
                }
              />
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-text-muted">
              {composerType === 'evidencia'
                ? 'El archivo y su SHA-256 se persisten automáticamente en DFIR-IRIS Datastore.'
                : 'La información se sincroniza automáticamente con el expediente oficial.'}
            </span>

            <Button
              variant="primary"
              size="sm"
              type="submit"
              loading={submitting}
              icon={<Send className="w-3.5 h-3.5" />}
            >
              Registrar en Bitácora
            </Button>
          </div>
        </form>
      </div>

      {/* Filter Tabs & Multi-Select Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-1">
        <div className="flex items-center gap-1 overflow-x-auto text-xs font-semibold">
          <button
            onClick={() => setFilterType('investigacion')}
            className={`px-3 py-2 border-b-2 transition-colors ${
              filterType === 'investigacion'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            🔍 Investigación ({activities.filter((a) => a.activity_type === 'investigacion').length})
          </button>
          <button
            onClick={() => setFilterType('accion')}
            className={`px-3 py-2 border-b-2 transition-colors ${
              filterType === 'accion'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            ⚡ Acciones ({activities.filter((a) => a.activity_type === 'accion').length})
          </button>
          <button
            onClick={() => setFilterType('evidencia')}
            className={`px-3 py-2 border-b-2 transition-colors ${
              filterType === 'evidencia'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            📎 Evidencias ({activities.filter((a) => a.activity_type === 'evidencia').length})
          </button>
          <button
            onClick={() => setFilterType('comunicacion')}
            className={`px-3 py-2 border-b-2 transition-colors ${
              filterType === 'comunicacion'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            💬 Comunicaciones ({activities.filter((a) => a.activity_type === 'comunicacion').length})
          </button>
          <button
            onClick={() => setFilterType('all')}
            className={`px-3 py-2 border-b-2 transition-colors ${
              filterType === 'all'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            Todos ({activities.length})
          </button>
        </div>

        {/* Multi-Selection Control */}
        <div className="flex items-center gap-2">
          {filteredActivities.length > 0 && (
            <button
              type="button"
              onClick={toggleSelectAll}
              className="text-xs text-text-muted hover:text-text-primary flex items-center gap-1.5 px-2 py-1 rounded hover:bg-surface-card transition-colors"
            >
              {selectedActivityIds.length === filteredActivities.length ? (
                <CheckSquare className="w-3.5 h-3.5 text-blue-500" />
              ) : (
                <Square className="w-3.5 h-3.5" />
              )}
              <span>{selectedActivityIds.length === filteredActivities.length ? 'Deseleccionar todo' : 'Seleccionar todo'}</span>
            </button>
          )}

          {selectedActivityIds.length > 0 && (
            <Button
              variant="danger"
              size="sm"
              onClick={() => setConfirmBatchDelete(true)}
              icon={<Trash2 className="w-3.5 h-3.5" />}
            >
              Eliminar Seleccionados ({selectedActivityIds.length})
            </Button>
          )}
        </div>
      </div>

      {/* Activity Stream Entries */}
      <div className="space-y-4">
        {loading && activities.length === 0 ? (
          <div className="p-8 text-center text-xs text-text-muted">Cargando eventos de la bitácora...</div>
        ) : filteredActivities.length === 0 ? (
          <div className="p-8 text-center rounded-xl bg-surface-card border border-border-subtle text-xs text-text-muted">
            No hay registros operativos para el filtro seleccionado.
          </div>
        ) : (
          filteredActivities.map((act) => {
            const isLog = act.activity_type === 'investigacion';
            const isEvidence = act.activity_type === 'evidencia';
            const isAction = act.activity_type === 'accion';
            const meta = act.metadata_json || {};
            const isSelected = selectedActivityIds.includes(act.id);
            const isEditing = editingActivityId === act.id;

            // INLINE WYSIWYG EDIT MODE
            if (isEditing) {
              return (
                <div
                  key={act.id}
                  className="p-5 rounded-xl bg-surface-card border-2 border-blue-500/80 shadow-xl space-y-4 animate-in fade-in duration-150"
                >
                  <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
                    <span className="text-xs font-bold text-blue-400 flex items-center gap-1.5">
                      <Edit3 className="w-4 h-4" />
                      Editando Registro #{act.id} ({act.activity_type})
                    </span>
                    <button
                      type="button"
                      onClick={handleCancelInlineEdit}
                      className="text-text-muted hover:text-text-primary p-1"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div className={act.activity_type === 'accion' ? 'md:col-span-2' : 'md:col-span-3'}>
                      <label className="text-[11px] font-bold text-text-muted block mb-1">Título del Registro</label>
                      <input
                        type="text"
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                        className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-blue-500"
                        required
                      />
                    </div>
                    {act.activity_type === 'accion' && (
                      <div>
                        <label className="text-[11px] font-bold text-text-muted block mb-1">Estado de la Acción</label>
                        <select
                          value={editActionStatus}
                          onChange={(e) => setEditActionStatus(e.target.value)}
                          className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-blue-500 font-semibold"
                        >
                          <option value="propuesta">Propuesta</option>
                          <option value="pendiente">Pendiente</option>
                          <option value="en_ejecucion">En Ejecución</option>
                          <option value="ejecutada">Ejecutada</option>
                          <option value="verificada">Verificada</option>
                          <option value="omitida">Omitida</option>
                        </select>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className="text-[11px] font-bold text-text-muted block mb-1">Contenido / Hallazgo (Editor WYSIWYG)</label>
                    <MarkdownEditor
                      value={editContent}
                      onChange={setEditContent}
                      textareaId={`edit-activity-md-${act.id}`}
                      minHeight="140px"
                      placeholder="Edita el contenido directamente con formato enriquecido..."
                    />
                  </div>

                  <div className="flex items-center justify-end gap-2 pt-2 border-t border-border-subtle">
                    <Button
                      variant="secondary"
                      size="sm"
                      type="button"
                      onClick={handleCancelInlineEdit}
                    >
                      Cancelar
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      type="button"
                      loading={savingEdit}
                      onClick={() => handleSaveInlineEdit(act.id)}
                      icon={<Check className="w-3.5 h-3.5" />}
                    >
                      Guardar Cambios
                    </Button>
                  </div>
                </div>
              );
            }

            // NORMAL DISPLAY MODE
            return (
              <div
                key={act.id}
                className={`p-5 rounded-xl bg-surface-card border transition-all duration-150 space-y-3 ${
                  isSelected
                    ? 'border-indigo-500/80 bg-indigo-950/20 ring-1 ring-indigo-500/50'
                    : 'border-border-subtle hover:border-border-default'
                }`}
              >
                {/* Entry Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border-subtle pb-2.5">
                  <div className="flex items-center gap-2.5">
                    {/* Checkbox for Multi-Selection */}
                    <button
                      type="button"
                      onClick={() => toggleSelectActivity(act.id)}
                      className="text-text-muted hover:text-text-primary transition-colors cursor-pointer"
                      title={isSelected ? 'Deseleccionar' : 'Seleccionar'}
                    >
                      {isSelected ? (
                        <CheckSquare className="w-4 h-4 text-indigo-400" />
                      ) : (
                        <Square className="w-4 h-4 text-slate-500 hover:text-slate-300" />
                      )}
                    </button>

                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                        isEvidence
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : isAction
                          ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
                          : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                      }`}
                    >
                      {act.activity_type}
                    </span>

                    <h4 className="text-xs font-bold text-text-primary">{act.title}</h4>

                    {act.step_order && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-root border border-border-subtle text-text-muted">
                        Paso #{act.step_order}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-text-muted">
                    <span>{act.analyst_username}</span>
                    <span>•</span>
                    <span className="font-mono">{new Date(act.created_at).toLocaleString('es-MX')}</span>

                    {/* Status badge for actions */}
                    {isAction && act.action_status && (
                      <div className="relative group ml-1">
                        <select
                          value={act.action_status}
                          onChange={(e) => handleUpdateStatus(act, e.target.value)}
                          className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border cursor-pointer focus:outline-none ${
                            act.action_status === 'ejecutada' || act.action_status === 'verificada'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : act.action_status === 'en_ejecucion'
                              ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                              : act.action_status === 'omitida'
                              ? 'bg-slate-500/10 text-slate-400 border-slate-500/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          <option value="propuesta">Propuesta</option>
                          <option value="pendiente">Pendiente</option>
                          <option value="en_ejecucion">En Ejecución</option>
                          <option value="ejecutada">Ejecutada</option>
                          <option value="verificada">Verificada</option>
                          <option value="omitida">Omitida</option>
                        </select>
                      </div>
                    )}

                    <button
                      type="button"
                      onClick={() => handleStartInlineEdit(act)}
                      title="Editar este registro directamente"
                      className="p-1 rounded text-text-muted hover:text-blue-400 hover:bg-surface-elevated transition-colors ml-1"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>

                    <button
                      type="button"
                      onClick={() => setConfirmDeleteId(act.id)}
                      title="Eliminar este registro de la bitácora"
                      className="p-1 rounded text-text-muted hover:text-red-400 hover:bg-surface-elevated transition-colors ml-1"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Entry Content */}
                {isLog && act.content && (
                  <div className="relative group">
                    <button
                      type="button"
                      onClick={() => handleCopyText(act.id, act.content)}
                      className="absolute top-2 right-2 px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700 text-[10px] font-mono text-slate-300 flex items-center gap-1 border border-slate-600/50 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      {copiedId === act.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      {copiedId === act.id ? 'Copiado' : 'Copiar Log'}
                    </button>
                    <pre className="p-3 rounded-lg bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto whitespace-pre-wrap border border-slate-900 leading-relaxed max-h-80">
                      {act.content}
                    </pre>
                  </div>
                )}

                {isEvidence && (
                  <div className="p-3 rounded-lg bg-surface-root border border-border-subtle space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2">
                        <Paperclip className="w-4 h-4 text-emerald-500" />
                        <span className="font-semibold text-text-primary">{meta.filename || act.title}</span>
                        {meta.file_size && (
                          <span className="text-[10px] font-mono text-text-muted">({meta.file_size} bytes)</span>
                        )}
                      </div>

                      {meta.iris_file_id && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          Datastore ID: #{meta.iris_file_id}
                        </span>
                      )}
                    </div>

                    {meta.sha256 && (
                      <div className="flex items-center gap-2 text-[10px] font-mono text-text-muted bg-surface-card p-1.5 rounded border border-border-subtle overflow-x-auto">
                        <span className="text-text-primary font-bold">SHA-256:</span>
                        <span className="text-indigo-400">{meta.sha256}</span>
                        <button
                          type="button"
                          onClick={() => handleCopyText(act.id, meta.sha256)}
                          className="hover:text-text-primary ml-auto flex items-center gap-0.5"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {!isLog && !isEvidence && act.content && (
                  <p className="text-xs text-text-secondary leading-relaxed whitespace-pre-wrap">
                    {act.content}
                  </p>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Confirmation Modal: Single Item Deletion */}
      <ConfirmModal
        isOpen={confirmDeleteId !== null}
        title="Eliminar Registro de Bitácora"
        message="¿Deseas eliminar este registro de la bitácora operativa? Se actualizará la ficha técnica oficial en DFIR-IRIS automáticamente."
        confirmLabel="Eliminar Registro"
        cancelLabel="Cancelar"
        variant="danger"
        loading={isDeletingSingle}
        onConfirm={handleExecuteSingleDelete}
        onClose={() => setConfirmDeleteId(null)}
      />

      {/* Confirmation Modal: Batch Deletion */}
      <ConfirmModal
        isOpen={confirmBatchDelete}
        title="Eliminación Múltiple de Registros"
        message={`¿Deseas eliminar permanentemente los ${selectedActivityIds.length} registros seleccionados de la bitácora operativa? Los pasos de playbook vinculados se actualizarán y la ficha oficial en IRIS se sincronizará automáticamente.`}
        confirmLabel={`Eliminar (${selectedActivityIds.length})`}
        cancelLabel="Cancelar"
        variant="danger"
        loading={isDeletingBatch}
        onConfirm={handleExecuteBatchDelete}
        onClose={() => setConfirmBatchDelete(false)}
      />
    </div>
  );
};
