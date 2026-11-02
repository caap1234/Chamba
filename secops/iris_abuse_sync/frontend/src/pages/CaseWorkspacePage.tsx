import React, { useEffect, useState, useRef } from 'react';
import {
  FileText,
  Search,
  CheckCircle,
  CheckCircle2,
  Clock,
  Paperclip,
  BookOpen,
  FileDown,
  Layers,
  Sparkles,
  ExternalLink,
  RefreshCw,
  AlertCircle,
  Save,
  Trash2,
  Terminal,
  ChevronDown,
  Tag,
  Calendar,
} from 'lucide-react';
import { CaseHeader } from '../components/case/CaseHeader';
import { AssetSheetDrawer } from '../components/case/AssetSheetDrawer';
import { ActionManager } from '../components/case/ActionManager';
import { EvidenceManager } from '../components/case/EvidenceManager';
import { InvestigationTimeline } from '../components/case/InvestigationTimeline';
import { PlaybookExecutionManager } from '../components/case/PlaybookExecutionManager';
import { CaseActivityStream } from '../components/case/CaseActivityStream';
import { CaseIoCManager } from '../components/case/CaseIoCManager';
import { MarkdownEditor } from '../components/common/MarkdownEditor';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { ConfirmModal } from '../components/common/ConfirmModal';
import { api } from '../api/client';
import { CaseBundle, CaseExtension } from '../types';
import { useCopilot } from '../context/CopilotContext';

interface CaseWorkspacePageProps {
  caseId: number;
  onNavigate?: (path: string) => void;
  onBack?: () => void;
}

export const CaseWorkspacePage: React.FC<CaseWorkspacePageProps> = ({ caseId, onNavigate, onBack }) => {
  const { setActiveContext } = useCopilot();
  const [bundle, setBundle] = useState<CaseBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'resumen' | 'playbook' | 'bitacora' | 'investigacion' | 'acciones' | 'evidencias' | 'notas' | 'informe' | 'iocs' | 'timeline'>('resumen');
  const [isAssetSheetOpen, setIsAssetSheetOpen] = useState(false);
  const [showAuxiliaryTabs, setShowAuxiliaryTabs] = useState(false);
  const [showLegacyNotes, setShowLegacyNotes] = useState(false);
  const [confirmDeleteActionId, setConfirmDeleteActionId] = useState<number | null>(null);
  const [generatingTimelineAi, setGeneratingTimelineAi] = useState(false);
  const [timelineAiSuccess, setTimelineAiSuccess] = useState<string | null>(null);
  
  // Notes & Autosave Drafts
  const [currentNoteId, setCurrentNoteId] = useState<number | null>(null);
  const [currentNoteContent, setCurrentNoteContent] = useState('');
  const [drafts, setDrafts] = useState<Record<string, { content: string; updated_at: string }>>({});
  const [draftStatus, setDraftStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [draftSavedAt, setDraftSavedAt] = useState<string | null>(null);
  const [activeDraftAlert, setActiveDraftAlert] = useState<string | null>(null);
  const debounceTimerRef = useRef<any>(null);

  // PDF Viewer State
  const [pdfKey, setPdfKey] = useState(1);
  const [pdfLoading, setPdfLoading] = useState(true);

  // Case State Management
  const [stateCatalog, setStateCatalog] = useState<Array<{ state_id: number; state_name: string; state_description?: string }>>([
    { state_id: 1, state_name: 'New' },
    { state_id: 2, state_name: 'In progress' },
    { state_id: 3, state_name: 'Open' },
    { state_id: 4, state_name: 'Containment' },
    { state_id: 5, state_name: 'Eradication' },
    { state_id: 6, state_name: 'Recovery' },
    { state_id: 7, state_name: 'Post-Incident' },
    { state_id: 8, state_name: 'Reporting' },
    { state_id: 9, state_name: 'Closed' },
  ]);
  const [isUpdatingState, setIsUpdatingState] = useState(false);
  const [savingNote, setSavingNote] = useState(false);

  useEffect(() => {
    api.getCaseStatesCatalog().then(res => {
      if (res.states && res.states.length > 0) setStateCatalog(res.states);
    }).catch(err => {
      console.warn('Error loading IRIS case states catalog:', err);
    });
  }, []);

  const handleStateChange = async (newStateId: number) => {
    setIsUpdatingState(true);
    try {
      const res = await api.updateCaseState(caseId, newStateId);
      if (bundle) {
        setBundle({
          ...bundle,
          iris_case: {
            ...bundle.iris_case,
            state_id: res.state_id,
            state_name: res.state_name,
          }
        });
      }
    } catch (err: any) {
      alert('Error actualizando estado en DFIR-IRIS: ' + (err.message || 'Error de red'));
    } finally {
      setIsUpdatingState(false);
    }
  };

  const fetchCase = (silent: boolean = false) => {
    if (!silent) setLoading(true);
    api
      .getCaseBundle(caseId)
      .then((res: CaseBundle) => {
        setBundle(res);
        setActiveContext({
          type: 'case',
          id: caseId,
          title: res.iris_case.case_name,
          data: res,
        });
        if (res.iris_case.notes && res.iris_case.notes.length > 0) {
          const integratedNote = res.iris_case.notes.find(
            (n) => n.note_title.includes('04') || n.note_title.includes('Integrada')
          ) || res.iris_case.notes[0];
          setCurrentNoteId(integratedNote.note_id);
          setCurrentNoteContent(integratedNote.note_content || '');
        }
      })
      .catch((err) => {
        console.error(err);
      })
      .finally(() => {
        if (!silent) setLoading(false);
      });

    // Fetch existing auto-saved drafts
    api
      .getCaseDrafts(caseId)
      .then((res) => {
        if (res.drafts) {
          setDrafts(res.drafts);
        }
      })
      .catch((err) => console.warn('Could not load drafts:', err));
  };

  useEffect(() => {
    fetchCase();
  }, [caseId]);

  // Check if active note has an uncommitted draft
  useEffect(() => {
    if (!currentNoteId) return;
    const draftKey = `note_${currentNoteId}`;
    const draft = drafts[draftKey];
    if (draft && draft.content && draft.content !== currentNoteContent) {
      setActiveDraftAlert(draft.updated_at);
    } else {
      setActiveDraftAlert(null);
    }
  }, [currentNoteId, drafts]);

  // Handle Note Content Change with Debounced Auto-save
  const handleNoteChange = (newVal: string) => {
    setCurrentNoteContent(newVal);
    if (!currentNoteId) return;

    setDraftStatus('saving');
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    debounceTimerRef.current = setTimeout(async () => {
      try {
        const draftKey = `note_${currentNoteId}`;
        const res = await api.saveCaseDraft(caseId, draftKey, newVal);
        setDrafts((prev) => ({
          ...prev,
          [draftKey]: { content: newVal, updated_at: res.updated_at },
        }));
        setDraftStatus('saved');
        setDraftSavedAt(new Date().toLocaleTimeString());
      } catch (err) {
        console.error('Error auto-saving draft:', err);
        setDraftStatus('error');
      }
    }, 2000);
  };

  const handleRestoreDraft = () => {
    if (!currentNoteId) return;
    const draftKey = `note_${currentNoteId}`;
    const draft = drafts[draftKey];
    if (draft) {
      setCurrentNoteContent(draft.content);
      setActiveDraftAlert(null);
    }
  };

  const handleDiscardDraft = async () => {
    if (!currentNoteId) return;
    const draftKey = `note_${currentNoteId}`;
    try {
      await api.deleteCaseDraft(caseId, draftKey);
      setDrafts((prev) => {
        const copy = { ...prev };
        delete copy[draftKey];
        return copy;
      });
      setActiveDraftAlert(null);
      // Revert to original note content from bundle
      const origNote = bundle?.iris_case.notes?.find((n) => n.note_id === currentNoteId);
      if (origNote) {
        setCurrentNoteContent(origNote.note_content || '');
      }
    } catch (err: any) {
      alert('Error descartando borrador: ' + err.message);
    }
  };

  if (loading || !bundle) {
    return (
      <div className="flex-1 flex items-center justify-center p-12 text-slate-400 text-xs">
        Cargando expediente estructurado del Caso #{caseId}...
      </div>
    );
  }

  const { iris_case, extension, actions = [], investigations = [], evidences = [] } = bundle;
  const safeActions = actions || [];
  const safeInvestigations = investigations || [];
  const safeEvidences = evidences || iris_case?.evidences || [];

  const handleExtensionChange = (field: keyof CaseExtension, value: any) => {
    setBundle((prev) => {
      if (!prev) return null;
      return {
        ...prev,
        extension: {
          ...prev.extension,
          [field]: value,
        },
      };
    });
  };

  const handleSaveNote = async () => {
    if (!currentNoteId) {
      alert('No hay ninguna nota seleccionada.');
      return;
    }
    setSavingNote(true);
    try {
      await api.updateCaseNote(caseId, currentNoteId, currentNoteContent);
      await api.deleteCaseDraft(caseId, `note_${currentNoteId}`).catch(() => {});
      setDraftStatus('idle');
      setActiveDraftAlert(null);
      await fetchCase();
      alert('✓ Nota guardada y sincronizada correctamente en DFIR-IRIS.');
    } catch (err: any) {
      alert(`Error al guardar nota en IRIS: ${err.message}`);
    } finally {
      setSavingNote(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateCaseStructured(caseId, {
        state_id: bundle?.iris_case?.state_id,
        primary_domain: extension.primary_domain,
        server_name: extension.server_name,
        abuse_ticket_id: extension.abuse_ticket_id,
        holder_ticket_id: extension.holder_ticket_id,
        client_id: extension.client_id,
        service_id: extension.service_id,
        hosting_ip: extension.hosting_ip,
        reported_ip: extension.reported_ip,
        impersonated_brand: extension.impersonated_brand,
        category_code: extension.category_code,
        reported_activity: extension.reported_activity,
        confirmed_incident_type: extension.confirmed_incident_type,
        entry_vector: extension.entry_vector,
        root_cause: extension.root_cause,
        verification_state: extension.verification_state,
        severity: extension.severity,
        is_technical_compromise: extension.is_technical_compromise,
        current_note_id: currentNoteId || undefined,
        current_note_content: currentNoteContent !== undefined ? currentNoteContent : undefined,
        sync_structured_note_to_iris: false,
      });

      // Clear draft for current note if committed
      if (currentNoteId) {
        await api.deleteCaseDraft(caseId, `note_${currentNoteId}`).catch(() => {});
        setDraftStatus('idle');
        setActiveDraftAlert(null);
      }

      // Re-fetch bundle to guarantee latest state from IRIS
      await fetchCase();

      alert('✓ Cambios guardados correctamente y sincronizados con DFIR-IRIS.');
    } catch (err: any) {
      alert(`Error al guardar: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddInvestigation = async (item: any) => {
    try {
      await api.addInvestigation(caseId, item);
      await fetchCase();
    } catch (err: any) {
      alert('Error registrando investigación: ' + err.message);
    }
  };

  const handleAddAction = async (action: any) => {
    try {
      await api.addAction(caseId, action);
      await fetchCase();
    } catch (err: any) {
      alert('Error registrando acción: ' + err.message);
    }
  };

  const handleUpdateActionStatus = async (index: number, newStatus: any, resultNotes?: string) => {
    try {
      const act = actions[index];
      if (act && act.id) {
        await api.updateActionStatus(caseId, act.id, newStatus, resultNotes);
        await fetchCase();
      }
    } catch (err: any) {
      alert('Error actualizando estado de acción: ' + err.message);
    }
  };

  const handleDeleteAction = (actionId: number) => {
    setConfirmDeleteActionId(actionId);
  };

  const handleExecuteDeleteAction = async () => {
    if (confirmDeleteActionId === null) return;
    try {
      await api.deleteCaseAction(caseId, confirmDeleteActionId);
      setConfirmDeleteActionId(null);
      await fetchCase(true);
    } catch (err: any) {
      alert('Error eliminando acción: ' + err.message);
    }
  };

  const handleGenerateTimelineAi = async () => {
    setGeneratingTimelineAi(true);
    setTimelineAiSuccess(null);
    try {
      const res = await api.generateCaseTimelineAi(caseId);
      setTimelineAiSuccess(`✓ Timeline generado con IA: ${res.events_synced} eventos cronológicos sincronizados en DFIR-IRIS.`);
      await fetchCase(true);
      setTimeout(() => setTimelineAiSuccess(null), 5000);
    } catch (err: any) {
      alert('Error generando timeline con IA: ' + (err.message || 'Error de red'));
    } finally {
      setGeneratingTimelineAi(false);
    }
  };

  const handleUploadEvidence = async (file: File, description: string) => {
    try {
      await api.uploadEvidence(caseId, file, description);
      await fetchCase();
    } catch (err: any) {
      alert('Error subiendo evidencia: ' + err.message);
    }
  };

  return (
    <div className={`flex-1 flex flex-col space-y-6 w-full pb-12 transition-all duration-300 ${isAssetSheetOpen ? 'lg:pr-96 pr-80' : 'max-w-7xl mx-auto'}`}>
      {/* Case Header */}
      <CaseHeader
        caseId={caseId}
        caseName={iris_case.case_name}
        organization={extension.organization}
        stateName={iris_case.state_name || 'Abierto'}
        stateId={iris_case.state_id}
        stateCatalog={stateCatalog}
        onStateChange={handleStateChange}
        isUpdatingState={isUpdatingState}
        severity={extension.severity || 'medium'}
        onToggleAssetSheet={() => setIsAssetSheetOpen(!isAssetSheetOpen)}
        onSave={handleSave}
        onRefresh={fetchCase}
        onExportPdf={() => setActiveTab('informe')}
        saving={saving}
      />

      {/* Workspace Tabs Navigation */}
      <div className="flex items-center justify-between border-b border-border-subtle text-xs font-semibold select-none">
        <div className="flex items-center gap-1">
          {/* TAB 1: Resumen & 4 Ejes (Pestaña Principal al abrir) */}
          <button
            onClick={() => setActiveTab('resumen')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'resumen'
                ? 'border-blue-500 text-blue-500 font-bold bg-surface-elevated/40'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Resumen & 4 Ejes</span>
          </button>

          {/* TAB 2: Playbook Asistido & Bitácora */}
          <button
            onClick={() => setActiveTab('playbook')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'playbook'
                ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Playbook Asistido & Bitácora</span>
          </button>

          {/* TAB 3: Ficha Oficial IRIS */}
          <button
            onClick={() => setActiveTab('notas')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'notas'
                ? 'border-emerald-500 text-emerald-400 font-bold bg-surface-elevated/40'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Ficha Oficial IRIS</span>
          </button>

          {/* TAB 4: Informe PDF v3.1 */}
          <button
            onClick={() => setActiveTab('informe')}
            className={`flex items-center gap-2 px-4 py-3 border-b-2 transition-colors ${
              activeTab === 'informe'
                ? 'border-blue-500 text-blue-400 bg-surface-elevated/40'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Informe PDF v3.1</span>
          </button>
        </div>

        {/* Mini Submenú Desplegable: Vistas Auxiliares */}
        <div className="relative mr-2">
          <button
            type="button"
            onClick={() => setShowAuxiliaryTabs(!showAuxiliaryTabs)}
            className={`text-xs font-medium px-3 py-1.5 rounded-lg border transition-all flex items-center gap-1.5 ${
              ['investigacion', 'acciones', 'evidencias', 'iocs', 'timeline'].includes(activeTab)
                ? 'bg-blue-600/10 border-blue-500/40 text-blue-400 font-semibold'
                : 'bg-surface-card border-border-subtle text-text-muted hover:text-text-primary'
            }`}
          >
            <span>
              {activeTab === 'investigacion'
                ? 'Vista: Investigación'
                : activeTab === 'acciones'
                ? 'Vista: Acciones'
                : activeTab === 'evidencias'
                ? 'Vista: Evidencias'
                : activeTab === 'iocs'
                ? 'Vista: Indicadores (IoCs)'
                : activeTab === 'timeline'
                ? 'Vista: Timeline IRIS'
                : 'Vistas Auxiliares'}
            </span>
            <ChevronDown className={`w-3.5 h-3.5 transition-transform ${showAuxiliaryTabs ? 'rotate-180' : ''}`} />
          </button>

          {showAuxiliaryTabs && (
            <div className="absolute right-0 mt-1.5 w-60 rounded-xl bg-surface-card border border-border-subtle shadow-xl py-1.5 z-30 animate-fade-in text-xs space-y-0.5">
              <button
                type="button"
                onClick={() => {
                  setActiveTab('investigacion');
                  setShowAuxiliaryTabs(false);
                }}
                className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors ${
                  activeTab === 'investigacion'
                    ? 'bg-blue-600/10 text-blue-400 font-bold'
                    : 'text-text-secondary hover:bg-surface-elevated hover:text-text-primary'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Search className="w-3.5 h-3.5 text-blue-400" />
                  <span>Investigación</span>
                </div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface-root text-text-muted">
                  {safeInvestigations.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setActiveTab('acciones');
                  setShowAuxiliaryTabs(false);
                }}
                className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors ${
                  activeTab === 'acciones'
                    ? 'bg-blue-600/10 text-blue-400 font-bold'
                    : 'text-text-secondary hover:bg-surface-elevated hover:text-text-primary'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Clock className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Acciones de Contención</span>
                </div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface-root text-text-muted">
                  {safeActions.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setActiveTab('evidencias');
                  setShowAuxiliaryTabs(false);
                }}
                className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors ${
                  activeTab === 'evidencias'
                    ? 'bg-blue-600/10 text-blue-400 font-bold'
                    : 'text-text-secondary hover:bg-surface-elevated hover:text-text-primary'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Paperclip className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Bóveda de Evidencias</span>
                </div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface-root text-text-muted">
                  {safeEvidences.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setActiveTab('iocs');
                  setShowAuxiliaryTabs(false);
                }}
                className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors ${
                  activeTab === 'iocs'
                    ? 'bg-blue-600/10 text-blue-400 font-bold'
                    : 'text-text-secondary hover:bg-surface-elevated hover:text-text-primary'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Tag className="w-3.5 h-3.5 text-purple-400" />
                  <span>Indicadores (IoCs)</span>
                </div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface-root text-text-muted">
                  {bundle.iris_case?.iocs?.length || 0}
                </span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setActiveTab('timeline');
                  setShowAuxiliaryTabs(false);
                }}
                className={`w-full text-left px-3.5 py-2 flex items-center justify-between transition-colors ${
                  activeTab === 'timeline'
                    ? 'bg-blue-600/10 text-blue-400 font-bold'
                    : 'text-text-secondary hover:bg-surface-elevated hover:text-text-primary'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Timeline Forense IRIS</span>
                </div>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-surface-root text-text-muted">
                  {bundle.iris_case?.timeline?.length || 0}
                </span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Tab Panels */}
      <div className="flex-1">
        {/* TAB 1: Resumen & 4 Ejes */}
        {activeTab === 'resumen' && (
          <div className={`grid gap-6 ${isAssetSheetOpen ? 'grid-cols-1 2xl:grid-cols-2' : 'grid-cols-1 lg:grid-cols-2'}`}>
            <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-4 min-w-0">
              <h3 className="text-sm font-bold text-text-primary border-b border-border-subtle pb-3">
                Identificación del Incidente
              </h3>
              <div className="space-y-3 text-xs">
                <div className="flex justify-between py-1 border-b border-border-subtle/50">
                  <span className="text-text-muted">Activo / Dominio:</span>
                  <span className="font-mono text-cyan-600 dark:text-cyan-400 font-semibold">{extension.primary_domain || '—'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border-subtle/50">
                  <span className="text-text-muted">Servidor Hosting:</span>
                  <span className="font-mono text-text-primary">{extension.server_name || '—'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border-subtle/50">
                  <span className="text-text-muted">Ticket de Abuso:</span>
                  <span className="font-mono text-text-primary">#{extension.abuse_ticket_id || '—'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border-subtle/50">
                  <span className="text-text-muted">ID de Cliente / Servicio:</span>
                  <span className="font-mono text-text-secondary">
                    Cliente #{extension.client_id || '—'} &bull; Serv #{extension.service_id || '—'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-border-subtle/50">
                  <span className="text-text-muted">IP Reportada:</span>
                  <span className="font-mono text-text-secondary">{extension.reported_ip || '—'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">Compromiso Técnico:</span>
                  <Badge variant={extension.is_technical_compromise ? 'critical' : 'low'}>
                    {extension.is_technical_compromise ? 'Confirmado' : 'No detectado'}
                  </Badge>
                </div>
              </div>
            </div>

            {/* Clasificación en 4 Ejes */}
            <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-4 min-w-0">
              <h3 className="text-sm font-bold text-text-primary border-b border-border-subtle pb-3">
                Taxonomía SOC (4 Ejes Independientes)
              </h3>
              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-text-muted block mb-1">Categoría SOC:</span>
                  <Badge variant="nbx">{extension.category_code}</Badge>
                </div>
                <div>
                  <span className="text-text-muted block mb-1">Eje 1 &bull; Actividad Reportada:</span>
                  <span className="font-medium text-text-secondary">{extension.reported_activity}</span>
                </div>
                <div>
                  <span className="text-text-muted block mb-1">Eje 2 &bull; Incidente Confirmado:</span>
                  <span className="font-medium text-text-secondary">{extension.confirmed_incident_type}</span>
                </div>
                <div>
                  <span className="text-text-muted block mb-1">Eje 3 &bull; Vector de Entrada:</span>
                  <span className="font-medium text-text-secondary">{extension.entry_vector || 'unknown'}</span>
                </div>
                <div>
                  <span className="text-text-muted block mb-1">Eje 4 &bull; Causa Raíz:</span>
                  <span className="font-medium text-text-secondary">{extension.root_cause || 'unknown'}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Playbook Asistido */}
        {activeTab === 'playbook' && (
          <PlaybookExecutionManager
            caseId={caseId}
            categoryCode={extension.category_code}
            activeExecutions={bundle.playbook_executions}
            onRefresh={() => fetchCase(true)}
          />
        )}

        {/* TAB: Bitácora Unificada */}
        {activeTab === 'bitacora' && (
          <CaseActivityStream
            caseId={caseId}
            onRefreshBundle={() => fetchCase(true)}
          />
        )}

        {/* TAB 3: Investigación */}
        {activeTab === 'investigacion' && (
          <InvestigationTimeline
            investigations={safeInvestigations}
            onAddInvestigation={handleAddInvestigation}
          />
        )}

        {/* TAB 3: Acciones de Contención */}
        {activeTab === 'acciones' && (
          <ActionManager
            actions={safeActions}
            onAddAction={handleAddAction}
            onUpdateStatus={handleUpdateActionStatus}
            onDeleteAction={handleDeleteAction}
          />
        )}

        {/* TAB 4: Evidencias */}
        {activeTab === 'evidencias' && (
          <EvidenceManager
            evidences={safeEvidences}
            onUpload={handleUploadEvidence}
          />
        )}

        {/* TAB: Indicadores (IoCs) */}
        {activeTab === 'iocs' && (
          <CaseIoCManager
            caseId={caseId}
            onRefresh={() => fetchCase(true)}
          />
        )}

        {/* TAB: Timeline Forense IRIS */}
        {activeTab === 'timeline' && (
          <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-3">
              <div>
                <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                  <Calendar className="w-4 h-4 text-cyan-400" />
                  Línea de Tiempo Oficial de DFIR-IRIS (Timeline)
                </h3>
                <p className="text-xs text-text-muted mt-0.5">
                  Hitos cronológicos del incidente registrados y visibles en el grafo y reporte oficial de IRIS.
                </p>
              </div>

              <Button
                variant="primary"
                size="sm"
                onClick={handleGenerateTimelineAi}
                loading={generatingTimelineAi}
                icon={<Sparkles className="w-3.5 h-3.5" />}
              >
                Generar Timeline con IA
              </Button>
            </div>

            {timelineAiSuccess && (
              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                <span>{timelineAiSuccess}</span>
              </div>
            )}

            <div className="space-y-3">
              {(bundle.iris_case?.timeline || []).length === 0 ? (
                <div className="p-8 text-center text-xs text-text-muted">
                  No hay eventos registrados en la línea de tiempo de IRIS. Pulsa <b>"Generar Timeline con IA"</b> para extraerlos cronológicamente de la bitácora.
                </div>
              ) : (
                (bundle.iris_case?.timeline || []).map((ev: any, idx: number) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-surface-root border border-border-subtle flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-surface-card border border-border-subtle shrink-0 mt-0.5">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                    </div>
                    <div className="flex-1">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <h4 className="text-xs font-bold text-text-primary">{ev.event_title}</h4>
                        <span className="text-[10px] font-mono text-text-muted">
                          {ev.event_date ? new Date(ev.event_date).toLocaleString('es-MX') : 'Fecha no especificada'}
                        </span>
                      </div>
                      <p className="text-xs text-text-secondary mt-1 whitespace-pre-wrap">{ev.event_content}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* TAB 5: Notas Markdown con Autoguardado */}
        {activeTab === 'notas' && (
          <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100 dark:text-white light:text-slate-900">
                  Notas de Documentación DFIR-IRIS
                </h3>
                <p className="text-xs text-slate-400">
                  Sincronización bidireccional con notas oficiales de DFIR-IRIS y autoguardado local de borradores
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {/* Note Selector */}
                <div className="flex flex-wrap items-center gap-1.5 bg-surface-root p-1 rounded-lg border border-border-subtle">
                  {(() => {
                    const allNotes = iris_case.notes || [];
                    const isIntegrated = (title: string) => /04|ficha|integrada|normalizada/i.test(title);
                    const primaryNotes = allNotes.filter(n => isIntegrated(n.note_title));
                    const legacyNotes = allNotes.filter(n => !isIntegrated(n.note_title));

                    return (
                      <>
                        {(primaryNotes.length > 0 ? primaryNotes : allNotes).map((n) => (
                          <button
                            key={n.note_id}
                            onClick={() => {
                              setCurrentNoteId(n.note_id);
                              setCurrentNoteContent(n.note_content || '');
                            }}
                            className={`px-3 py-1 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                              currentNoteId === n.note_id
                                ? 'bg-blue-600 text-white'
                                : 'text-slate-400 hover:text-white'
                            }`}
                          >
                            <FileText className="w-3.5 h-3.5" />
                            {n.note_title}
                          </button>
                        ))}

                        {legacyNotes.length > 0 && primaryNotes.length > 0 && (
                          <div className="flex items-center gap-1 pl-2 border-l border-border-subtle">
                            <span className="text-[10px] text-text-muted font-mono uppercase px-1">Histórico:</span>
                            {legacyNotes.map((n) => (
                              <button
                                key={n.note_id}
                                onClick={() => {
                                  setCurrentNoteId(n.note_id);
                                  setCurrentNoteContent(n.note_content || '');
                                }}
                                title={n.note_title}
                                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                                  currentNoteId === n.note_id
                                    ? 'bg-surface-elevated text-text-primary border border-border-subtle font-semibold'
                                    : 'text-text-muted hover:text-text-primary'
                                }`}
                              >
                                {n.note_title.replace(/^\d+\s*/, '')}
                              </button>
                            ))}
                          </div>
                        )}
                      </>
                    );
                  })()}
                </div>

                <Button
                  size="sm"
                  variant="primary"
                  onClick={handleSaveNote}
                  loading={savingNote}
                  icon={<Save className="w-3.5 h-3.5" />}
                >
                  Guardar Nota en IRIS
                </Button>
              </div>
            </div>

            {/* Autosave Draft Notice Banner if local draft differs */}
            {activeDraftAlert && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
                  <span>
                    Existe un borrador autoguardado no publicado en IRIS ({new Date(activeDraftAlert).toLocaleTimeString()}).
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="outline" onClick={handleRestoreDraft}>
                    Restaurar Borrador
                  </Button>
                  <Button size="sm" variant="ghost" onClick={handleDiscardDraft} icon={<Trash2 className="w-3.5 h-3.5" />}>
                    Descartar
                  </Button>
                </div>
              </div>
            )}

            {/* Autosave Status Indicator */}
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-mono text-[11px]">
                {draftStatus === 'saving' && 'Guardando borrador automático...'}
                {draftStatus === 'saved' && `✓ Borrador guardado automáticamente (${draftSavedAt || ''})`}
                {draftStatus === 'error' && '⚠ Error guardando borrador'}
                {draftStatus === 'idle' && 'Borrador al día'}
              </span>
              <span className="text-[11px] text-slate-500">
                Los borradores se guardan en BD aislada y solo se publican en IRIS al pulsar Guardar Cambios.
              </span>
            </div>

            <MarkdownEditor
              value={currentNoteContent}
              onChange={handleNoteChange}
              placeholder="Escribe detalles técnicos, cabeceras o logs..."
            />
          </div>
        )}

        {/* TAB 6: Informe PDF con Visor Integrado Funcional */}
        {activeTab === 'informe' && (
          <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100 dark:text-white light:text-slate-900">
                  Informe Técnico de Incidente (15 Secciones)
                </h3>
                <p className="text-xs text-slate-400">
                  Renderizado vectorial institucional con formato ejecutivo y notas Markdown renderizadas
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setPdfLoading(true);
                    setPdfKey((prev) => prev + 1);
                  }}
                  icon={<RefreshCw className={`w-3.5 h-3.5 ${pdfLoading ? 'animate-spin' : ''}`} />}
                >
                  Recargar Visor
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => window.open(`/api/v1/cases/${caseId}/report.pdf`, '_blank')}
                  icon={<ExternalLink className="w-3.5 h-3.5" />}
                >
                  Abrir en Pestaña
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => window.open(`/api/v1/cases/${caseId}/report.pdf?download=1`, '_blank')}
                  icon={<FileDown className="w-3.5 h-3.5" />}
                >
                  Descargar PDF
                </Button>
              </div>
            </div>

            {/* Embedded Inline PDF Viewer */}
            <div className="border border-border-subtle rounded-xl overflow-hidden bg-slate-950 h-[720px] relative flex flex-col items-center justify-center">
              {pdfLoading && (
                <div className="absolute inset-0 bg-surface-root/80 backdrop-blur-sm flex flex-col items-center justify-center gap-2 z-10 text-slate-400 text-xs">
                  <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  <span>Cargando informe vectorial del Caso #{caseId}...</span>
                </div>
              )}
              <iframe
                key={pdfKey}
                src={`/api/v1/cases/${caseId}/report.pdf`}
                className="w-full h-full border-0"
                title={`Informe Caso #${caseId}`}
                onLoad={() => setPdfLoading(false)}
              />
            </div>
          </div>
        )}
      </div>

      {/* Asset Sheet Drawer */}
      <AssetSheetDrawer
        isOpen={isAssetSheetOpen}
        onClose={() => setIsAssetSheetOpen(false)}
        extension={extension}
        adminLinks={bundle.admin_links}
        onChange={handleExtensionChange}
      />

      {/* Confirmation Modal: Delete Case Action */}
      <ConfirmModal
        isOpen={confirmDeleteActionId !== null}
        title="Eliminar Acción de Contención"
        message="¿Confirmas que deseas eliminar esta acción operativa del expediente? La bitácora y la ficha técnica se actualizarán en consecuencia."
        confirmLabel="Eliminar Acción"
        cancelLabel="Cancelar"
        variant="danger"
        onConfirm={handleExecuteDeleteAction}
        onClose={() => setConfirmDeleteActionId(null)}
      />
    </div>
  );
};
