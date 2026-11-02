import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { 
  BookOpen, 
  CheckCircle2, 
  Clock, 
  AlertCircle, 
  Play, 
  Pause, 
  RotateCcw, 
  ShieldCheck, 
  ChevronRight, 
  Plus, 
  Check, 
  Ban, 
  Sparkles,
  Link as LinkIcon,
  X,
  FileText,
  Terminal,
  Paperclip,
  Share2,
  Unlink,
  Search,
} from 'lucide-react';
import { api } from '../../api/client';
import { PlaybookExecutionRecord, PlaybookStepState } from '../../types';
import { Badge } from '../common/Badge';
import { Button } from '../common/Button';
import { CaseActivityStream, ActivityItem } from './CaseActivityStream';

interface PlaybookExecutionManagerProps {
  caseId: number;
  categoryCode: string;
  activeExecutions?: PlaybookExecutionRecord[];
  onRefresh: () => void;
}

export const PlaybookExecutionManager: React.FC<PlaybookExecutionManagerProps> = ({
  caseId,
  categoryCode,
  activeExecutions = [],
  onRefresh,
}) => {
  const [suggestedPlaybooks, setSuggestedPlaybooks] = useState<any[]>([]);
  const [loadingSuggestions, setLoadingSuggestions] = useState(false);
  const [selectedPlaybookCode, setSelectedPlaybookCode] = useState<string>('');
  const [starting, setStarting] = useState(false);
  const [updatingStep, setUpdatingStep] = useState<number | null>(null);
  const [selectedStepOrder, setSelectedStepOrder] = useState<number | null>(null);

  // Dynamic Custom Step Modal
  const [showCustomStepModal, setShowCustomStepModal] = useState(false);
  const [customStepTitle, setCustomStepTitle] = useState('');
  const [customStepDesc, setCustomStepDesc] = useState('');
  const [customStepType, setCustomStepType] = useState('custom_step');
  const [savingCustomStep, setSavingCustomStep] = useState(false);

  // Omit Step Modal
  const [omittingStepOrder, setOmittingStepOrder] = useState<number | null>(null);
  const [omissionReason, setOmissionReason] = useState('');
  const [savingOmission, setSavingOmission] = useState(false);

  // Link Activity Modal
  const [linkingStepOrder, setLinkingStepOrder] = useState<number | null>(null);
  const [caseActivities, setCaseActivities] = useState<ActivityItem[]>([]);
  const [selectedActivityIdsToLink, setSelectedActivityIdsToLink] = useState<number[]>([]);
  const [loadingActivities, setLoadingActivities] = useState(false);
  const [savingLink, setSavingLink] = useState(false);
  const [linkFilter, setLinkFilter] = useState<string>('all');
  const [linkSearch, setLinkSearch] = useState<string>('');

  // Unlink Modal Filters
  const [unlinkFilter, setUnlinkFilter] = useState<string>('all');
  const [unlinkSearch, setUnlinkSearch] = useState<string>('');

  // Active execution
  const activeExecution = activeExecutions.find((e) => e.status === 'in_progress') || activeExecutions[0] || null;

  const loadSuggestions = async () => {
    setLoadingSuggestions(true);
    try {
      const res = await api.getSuggestedPlaybooks(caseId);
      const pbs = res.playbooks || [];
      setSuggestedPlaybooks(pbs);
      if (pbs.length > 0 && !selectedPlaybookCode) {
        const primary = pbs.find((p: any) => p.is_suggested) || pbs[0];
        setSelectedPlaybookCode(primary.code);
      }
    } catch (err: any) {
      console.error('Error fetching suggested playbooks:', err);
    } finally {
      setLoadingSuggestions(false);
    }
  };

  useEffect(() => {
    loadSuggestions();
  }, [caseId, categoryCode]);

  useEffect(() => {
    if (activeExecution && activeExecution.steps_state.length > 0) {
      const firstPending = activeExecution.steps_state.find(
        (s) => s.status === 'en_progreso' || s.status === 'pendiente'
      );
      if (firstPending && selectedStepOrder === null) {
        setSelectedStepOrder(firstPending.order);
      }
    }
  }, [activeExecution]);

  const handleStartPlaybook = async () => {
    if (!selectedPlaybookCode) return;
    setStarting(true);
    try {
      await api.startCasePlaybook(caseId, selectedPlaybookCode);
      await onRefresh();
    } catch (err: any) {
      alert('Error iniciando ejecución de Playbook: ' + err.message);
    } finally {
      setStarting(false);
    }
  };

  const handleUpdateStepStatus = async (stepOrder: number, newStatus: string, createAction = false) => {
    if (!activeExecution) return;
    setUpdatingStep(stepOrder);
    try {
      await api.updatePlaybookStep(caseId, activeExecution.id, stepOrder, {
        status: newStatus,
        create_case_action: createAction,
      });
      await onRefresh();
    } catch (err: any) {
      alert('Error actualizando paso del Playbook: ' + err.message);
    } finally {
      setUpdatingStep(null);
    }
  };

  const handleExecutionStatus = async (newStatus: string) => {
    if (!activeExecution) return;
    try {
      await api.updatePlaybookExecutionStatus(caseId, activeExecution.id, newStatus);
      await onRefresh();
    } catch (err: any) {
      alert('Error cambiando estado de la ejecución: ' + err.message);
    }
  };

  const handleAddCustomStep = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeExecution || !customStepTitle.trim()) return;

    setSavingCustomStep(true);
    try {
      await api.addCustomPlaybookStep(caseId, activeExecution.id, {
        title: customStepTitle,
        description: customStepDesc,
        suggested_action_type: customStepType,
      });
      setShowCustomStepModal(false);
      setCustomStepTitle('');
      setCustomStepDesc('');
      await onRefresh();
    } catch (err: any) {
      alert('Error agregando paso personalizado: ' + err.message);
    } finally {
      setSavingCustomStep(false);
    }
  };

  const handleConfirmOmission = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeExecution || omittingStepOrder === null || !omissionReason.trim()) return;

    setSavingOmission(true);
    try {
      await api.omitPlaybookStep(caseId, activeExecution.id, omittingStepOrder, omissionReason);
      setOmittingStepOrder(null);
      setOmissionReason('');
      await onRefresh();
    } catch (err: any) {
      alert('Error omitiendo paso: ' + err.message);
    } finally {
      setSavingOmission(false);
    }
  };

  const loadCaseActivities = async () => {
    try {
      const res = await api.getCaseActivity(caseId);
      if (res.activities) {
        setCaseActivities(res.activities);
      }
    } catch (err) {
      console.error('Error cargando actividades:', err);
    }
  };

  useEffect(() => {
    loadCaseActivities();
  }, [caseId, activeExecution?.id]);

  const openLinkModal = async (stepOrder: number) => {
    setLinkingStepOrder(stepOrder);
    setSelectedActivityIdsToLink([]);
    setLinkFilter('all');
    setLinkSearch('');
    setLoadingActivities(true);
    try {
      const res = await api.getCaseActivity(caseId);
      setCaseActivities(res.activities || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingActivities(false);
    }
  };

  const handleToggleSelectActivity = (activityId: number) => {
    setSelectedActivityIdsToLink((prev) =>
      prev.includes(activityId) ? prev.filter((id) => id !== activityId) : [...prev, activityId]
    );
  };

  const handleConfirmLinkMultiple = async () => {
    if (!activeExecution || linkingStepOrder === null || selectedActivityIdsToLink.length === 0) return;
    setSavingLink(true);
    try {
      for (const actId of selectedActivityIdsToLink) {
        await api.linkActivityToPlaybookStep(caseId, activeExecution.id, linkingStepOrder, actId);
      }
      setLinkingStepOrder(null);
      setSelectedActivityIdsToLink([]);
      await onRefresh();
      await loadCaseActivities();
    } catch (err: any) {
      alert('Error vinculando actividades seleccionadas: ' + err.message);
    } finally {
      setSavingLink(false);
    }
  };

  const [unlinkingStepOrder, setUnlinkingStepOrder] = useState<number | null>(null);
  const [stepLinkedActivities, setStepLinkedActivities] = useState<ActivityItem[]>([]);
  const [selectedActivityIdsToUnlink, setSelectedActivityIdsToUnlink] = useState<number[]>([]);

  const handleUnlink = async (stepOrder: number) => {
    if (!activeExecution) return;
    setUpdatingStep(stepOrder);
    try {
      const res = await api.getCaseActivity(caseId, {
        playbook_execution_id: activeExecution.id,
        step_order: stepOrder,
      });
      const acts: ActivityItem[] = res.activities || [];
      if (acts.length > 1) {
        setStepLinkedActivities(acts);
        setSelectedActivityIdsToUnlink([]);
        setUnlinkFilter('all');
        setUnlinkSearch('');
        setUnlinkingStepOrder(stepOrder);
      } else {
        await api.unlinkActivityFromPlaybookStep(caseId, activeExecution.id, stepOrder);
        await onRefresh();
      }
    } catch (err: any) {
      alert('Error desvinculando paso: ' + err.message);
    } finally {
      setUpdatingStep(null);
    }
  };

  const handleToggleSelectUnlinkActivity = (activityId: number) => {
    setSelectedActivityIdsToUnlink((prev) =>
      prev.includes(activityId) ? prev.filter((id) => id !== activityId) : [...prev, activityId]
    );
  };

  const handleConfirmUnlinkMultiple = async () => {
    if (!activeExecution || unlinkingStepOrder === null || selectedActivityIdsToUnlink.length === 0) return;
    setSavingLink(true);
    try {
      for (const actId of selectedActivityIdsToUnlink) {
        await api.unlinkActivityFromPlaybookStep(caseId, activeExecution.id, unlinkingStepOrder, actId);
      }
      setUnlinkingStepOrder(null);
      setSelectedActivityIdsToUnlink([]);
      await onRefresh();
    } catch (err: any) {
      alert('Error desvinculando actividades seleccionadas: ' + err.message);
    } finally {
      setSavingLink(false);
    }
  };

  const handleConfirmUnlinkAll = async () => {
    if (!activeExecution || unlinkingStepOrder === null) return;
    setSavingLink(true);
    try {
      await api.unlinkActivityFromPlaybookStep(caseId, activeExecution.id, unlinkingStepOrder);
      setUnlinkingStepOrder(null);
      setSelectedActivityIdsToUnlink([]);
      await onRefresh();
    } catch (err: any) {
      alert('Error desvinculando actividades: ' + err.message);
    } finally {
      setSavingLink(false);
    }
  };

  // Compute progress
  const steps = activeExecution?.steps_state || [];
  const completedSteps = steps.filter((s) => s.status === 'completado').length;
  const progressPercent = steps.length > 0 ? Math.round((completedSteps / steps.length) * 100) : 0;

  const filteredLinkActivities = caseActivities.filter((act) => {
    if (linkFilter !== 'all' && act.activity_type !== linkFilter) return false;
    if (linkSearch.trim()) {
      const q = linkSearch.toLowerCase();
      const matchTitle = act.title.toLowerCase().includes(q);
      const matchContent = (act.content || '').toLowerCase().includes(q);
      return matchTitle || matchContent;
    }
    return true;
  });

  const filteredUnlinkActivities = stepLinkedActivities.filter((act) => {
    if (unlinkFilter !== 'all' && act.activity_type !== unlinkFilter) return false;
    if (unlinkSearch.trim()) {
      const q = unlinkSearch.toLowerCase();
      const matchTitle = act.title.toLowerCase().includes(q);
      const matchContent = (act.content || '').toLowerCase().includes(q);
      return matchTitle || matchContent;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Playbook Header & Overview */}
      <div className="p-5 rounded-xl bg-surface-card border border-border-subtle shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-text-primary flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-indigo-500" />
            Asistente Dinámico de Playbooks SOC
          </h3>
          <p className="text-xs text-text-muted mt-0.5">
            Procedimiento interactivo para contención, investigación técnica y remediación de incidentes ({categoryCode}).
          </p>
        </div>

        {activeExecution ? (
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowCustomStepModal(true)}
              icon={<Plus className="w-3.5 h-3.5" />}
            >
              Agregar Paso Operativo
            </Button>

            {activeExecution.status === 'in_progress' ? (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleExecutionStatus('suspended')}
                icon={<Pause className="w-3.5 h-3.5" />}
              >
                Pausar
              </Button>
            ) : (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => handleExecutionStatus('in_progress')}
                icon={<Play className="w-3.5 h-3.5" />}
              >
                Reanudar
              </Button>
            )}

            {activeExecution.status !== 'completed' && (
              <Button
                variant="primary"
                size="sm"
                onClick={() => handleExecutionStatus('completed')}
                icon={<CheckCircle2 className="w-3.5 h-3.5" />}
              >
                Completar Playbook
              </Button>
            )}
          </div>
        ) : null}
      </div>

      {/* Suggested Playbooks Selector (When no active execution) */}
      {!activeExecution && (
        <div className="p-5 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-border-subtle pb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-500" />
              <h4 className="text-sm font-semibold text-text-primary">
                Procedimientos Recomendados para este Caso
              </h4>
            </div>
            <span className="text-xs text-text-muted">Selección supervisada por analista</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {suggestedPlaybooks.map((pb) => {
              const isSelected = selectedPlaybookCode === pb.code;
              return (
                <div
                  key={pb.code}
                  onClick={() => setSelectedPlaybookCode(pb.code)}
                  className={`p-4 rounded-lg border text-left cursor-pointer transition-all ${
                    isSelected
                      ? 'border-indigo-500 bg-indigo-50/20 dark:bg-indigo-950/30 ring-1 ring-indigo-500'
                      : 'border-border-subtle bg-surface-elevated/40 hover:bg-surface-hover'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-card border border-border-subtle text-text-muted">
                      {pb.code}
                    </span>
                    {pb.is_suggested && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-100 text-indigo-700 dark:bg-indigo-950/80 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-700/60">
                        Sugerido
                      </span>
                    )}
                  </div>
                  <h5 className="text-xs font-bold text-text-primary line-clamp-1">{pb.name}</h5>
                  <p className="text-[11px] text-text-muted mt-1 line-clamp-2">{pb.description}</p>
                  <div className="mt-3 text-[10px] font-mono text-text-secondary flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    <span>{pb.steps_count} pasos operativos</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-3 border-t border-border-subtle flex justify-end">
            <Button
              variant="primary"
              size="md"
              loading={starting}
              disabled={!selectedPlaybookCode}
              onClick={handleStartPlaybook}
              icon={<Play className="w-4 h-4" />}
            >
              Iniciar Ejecución Supervisada
            </Button>
          </div>
        </div>
      )}

      {/* Active Playbook Dual Workspace */}
      {activeExecution && (
        <div className="space-y-6">
          {/* Progress Banner */}
          <div className="p-5 rounded-xl bg-surface-card border border-border-subtle shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-700/60 font-semibold">
                  {activeExecution.playbook_code} (v{activeExecution.playbook_version})
                </span>
                <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                  activeExecution.status === 'completed'
                    ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300'
                    : activeExecution.status === 'suspended'
                    ? 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/80 dark:text-amber-300'
                    : 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/80 dark:text-blue-300'
                }`}>
                  {activeExecution.status === 'completed' ? 'Completado' : activeExecution.status === 'suspended' ? 'En Pausa' : 'En Ejecución'}
                </span>
              </div>
              <h4 className="text-sm font-bold text-text-primary mt-1.5">{activeExecution.playbook_name}</h4>
            </div>

            <div className="w-full md:w-64 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-text-secondary">Progreso</span>
                <span className="font-mono font-bold text-indigo-400">{progressPercent}%</span>
              </div>
              <div className="w-full h-2 rounded-full bg-surface-root border border-border-subtle overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
              <span className="text-[10px] text-text-muted block text-right font-mono">
                {completedSteps} de {steps.length} pasos completados
              </span>
            </div>
          </div>

          {/* Procedures Timeline */}
          <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <h4 className="text-xs font-bold text-text-primary flex items-center gap-2">
                <span>Procedimiento Operativo Paso a Paso</span>
                <span className="text-[11px] font-normal text-text-muted">
                  (Haz clic en un paso para seleccionarlo y documentar directamente en la bitácora)
                </span>
              </h4>

              <Button
                variant="secondary"
                size="sm"
                onClick={() => setShowCustomStepModal(true)}
                icon={<Plus className="w-3.5 h-3.5" />}
              >
                Paso Ad-hoc
              </Button>
            </div>

            <div className="space-y-3">
              {steps.map((s) => {
                const isSelected = selectedStepOrder === s.order;
                const isUpdating = updatingStep === s.order;

                return (
                  <div
                    key={s.order}
                    onClick={() => setSelectedStepOrder(s.order)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      isSelected
                        ? 'border-indigo-500 bg-indigo-500/5 ring-1 ring-indigo-500'
                        : s.status === 'completado'
                        ? 'bg-emerald-500/5 border-emerald-500/20'
                        : s.status === 'en_progreso'
                        ? 'bg-blue-500/5 border-blue-500/30'
                        : s.status === 'omitido'
                        ? 'bg-slate-500/5 border-slate-500/20 opacity-70'
                        : 'bg-surface-elevated/40 border-border-subtle hover:border-border-default'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                      <div className="flex items-start gap-3 flex-1">
                        <div
                          className={`w-7 h-7 rounded-full flex items-center justify-center font-mono text-xs font-bold shrink-0 mt-0.5 ${
                            s.status === 'completado'
                              ? 'bg-emerald-600 text-white'
                              : s.status === 'en_progreso'
                              ? 'bg-blue-600 text-white animate-pulse'
                              : s.status === 'omitido'
                              ? 'bg-slate-600 text-white'
                              : 'bg-surface-card border border-border-subtle text-text-muted'
                          }`}
                        >
                          {s.status === 'completado' ? <Check className="w-4 h-4" /> : s.order}
                        </div>

                        <div className="space-y-1 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <h5 className="text-xs font-bold text-text-primary">{s.title}</h5>

                            {s.is_custom && (
                              <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-300 dark:border-purple-700">
                                Personalizado
                              </span>
                            )}

                            {s.mandatory && (
                              <span className="text-[9px] uppercase font-bold px-1.5 py-0.2 rounded bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-700">
                                Obligatorio
                              </span>
                            )}

                            <span
                              className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${
                                s.status === 'completado'
                                  ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300'
                                  : s.status === 'en_progreso'
                                  ? 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/80 dark:text-blue-300'
                                  : s.status === 'omitido'
                                  ? 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300'
                                  : 'bg-surface-root text-text-muted border-border-subtle'
                              }`}
                            >
                              {s.status}
                            </span>
                          </div>

                          <p className="text-xs text-text-secondary leading-relaxed">{s.description}</p>

                          {/* Lista concisa con solo el título de los elementos vinculados */}
                          {(() => {
                            const linkedForStep = caseActivities.filter(
                              (a) => a.playbook_execution_id === activeExecution?.id && a.step_order === s.order
                            );
                            if (linkedForStep.length > 0) {
                              return (
                                <div className="mt-2 space-y-1">
                                  <span className="text-[10px] font-mono uppercase text-text-muted font-bold block">
                                    Elementos vinculados ({linkedForStep.length}):
                                  </span>
                                  <div className="flex flex-col gap-1">
                                    {linkedForStep.map((act) => (
                                      <div
                                        key={act.id}
                                        className="flex items-center gap-2 text-xs font-medium text-text-secondary bg-surface-root/80 px-2.5 py-1.5 rounded-lg border border-border-subtle"
                                      >
                                        <span className="text-[10px] font-bold uppercase font-mono px-1.5 py-0.2 rounded bg-surface-card border border-border-subtle text-text-muted shrink-0">
                                          {act.activity_type}
                                        </span>
                                        <span className="truncate text-text-primary font-medium">{act.title}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              );
                            }
                            if (s.observations) {
                              return (
                                <p className="text-[11px] text-text-muted font-mono bg-surface-root/80 p-2 rounded border border-border-subtle/50 mt-1">
                                  💬 {s.observations}
                                </p>
                              );
                            }
                            return null;
                          })()}
                        </div>
                      </div>

                      {/* Fast Action Controls */}
                      <div className="flex items-center gap-1.5 shrink-0" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => handleUpdateStepStatus(s.order, 'en_progreso')}
                          disabled={isUpdating || s.status === 'en_progreso'}
                          className="px-2.5 py-1 text-xs font-medium rounded border border-border-subtle bg-surface-card hover:bg-surface-hover text-text-primary disabled:opacity-40 transition-colors"
                        >
                          En Curso
                        </button>

                        <button
                          type="button"
                          onClick={() => handleUpdateStepStatus(s.order, 'completado', true)}
                          disabled={isUpdating || s.status === 'completado'}
                          className="px-2.5 py-1 text-xs font-semibold rounded border border-emerald-500/40 bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm disabled:opacity-40 transition-colors flex items-center gap-1"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Completar
                        </button>

                        <button
                          type="button"
                          onClick={() => openLinkModal(s.order)}
                          className="px-2.5 py-1 text-xs font-medium rounded border border-border-subtle bg-surface-card hover:bg-surface-hover text-indigo-400 flex items-center gap-1"
                          title="Vincular con un hallazgo o evidencia ya existente en la bitácora"
                        >
                          <LinkIcon className="w-3 h-3" />
                          Vincular
                        </button>

                        {(s.linked_activity_id || s.status === 'completado') && (
                          <button
                            type="button"
                            onClick={() => handleUnlink(s.order)}
                            disabled={isUpdating}
                            className="px-2 py-1 text-xs font-medium rounded border border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 flex items-center gap-1 transition-colors"
                            title="Desvincular actividad o restaurar paso a pendiente"
                          >
                            <Unlink className="w-3 h-3" />
                            Desvincular
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() => {
                            setOmittingStepOrder(s.order);
                            setOmissionReason('');
                          }}
                          disabled={isUpdating || s.status === 'omitido'}
                          className="px-2 py-1 text-xs font-medium rounded border border-border-subtle bg-surface-card hover:bg-surface-hover text-text-muted disabled:opacity-40 transition-colors"
                          title="Omitir este paso con justificación obligatoria"
                        >
                          Omitir
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Integrated Bitácora Stream for the Active Step & Incident */}
          <div className="border-t border-border-subtle pt-6">
            <CaseActivityStream
              caseId={caseId}
              activeExecutionId={activeExecution.id}
              activeStepOrder={selectedStepOrder}
              onRefreshBundle={onRefresh}
              onStepCompleted={(order) => {
                // If current step is completed, move to next step
                const nextStep = steps.find((s) => s.order > order && s.status === 'pendiente');
                if (nextStep) setSelectedStepOrder(nextStep.order);
              }}
            />
          </div>
        </div>
      )}

      {/* Modal: Custom Ad-hoc Step */}
      {showCustomStepModal && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-border-subtle rounded-2xl p-6 w-full max-w-lg shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <Plus className="w-4 h-4 text-indigo-500" />
                Agregar Paso Operativo Personalizado
              </h3>
              <button onClick={() => setShowCustomStepModal(false)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddCustomStep} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-text-secondary block mb-1">Título del Paso</label>
                <input
                  type="text"
                  placeholder="ej. Verificar redirección en Cloudflare o Regla iptables"
                  value={customStepTitle}
                  onChange={(e) => setCustomStepTitle(e.target.value)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-text-secondary block mb-1">Descripción / Procedimiento</label>
                <textarea
                  rows={3}
                  placeholder="Instrucciones u objetivo específico de este paso ad-hoc..."
                  value={customStepDesc}
                  onChange={(e) => setCustomStepDesc(e.target.value)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500 resize-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
                <Button variant="secondary" size="sm" type="button" onClick={() => setShowCustomStepModal(false)}>
                  Cancelar
                </Button>
                <Button variant="primary" size="sm" type="submit" loading={savingCustomStep}>
                  Agregar Paso
                </Button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* Modal: Omission Reason */}
      {omittingStepOrder !== null && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-border-subtle rounded-2xl p-6 w-full max-w-md shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <Ban className="w-4 h-4 text-amber-500" />
                Justificar Omisión de Paso #{omittingStepOrder}
              </h3>
              <button onClick={() => setOmittingStepOrder(null)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleConfirmOmission} className="space-y-4">
              <p className="text-xs text-text-muted">
                Para mantener la trazabilidad forense, indica por qué este procedimiento no aplica o no fue ejecutado en este incidente:
              </p>

              <div>
                <textarea
                  rows={3}
                  placeholder="ej. Dominio alojado en proveedor externo (GoDaddy/Cloudflare), no se dispone de acceso a cPanel..."
                  value={omissionReason}
                  onChange={(e) => setOmissionReason(e.target.value)}
                  className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-amber-500 resize-none"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
                <Button variant="secondary" size="sm" type="button" onClick={() => setOmittingStepOrder(null)}>
                  Cancelar
                </Button>
                <Button variant="primary" size="sm" type="submit" loading={savingOmission}>
                  Confirmar Omisión
                </Button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}

      {/* Modal: Link Existing Activity */}
      {linkingStepOrder !== null && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-border-subtle rounded-2xl p-6 w-full max-w-xl shadow-xl space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3 shrink-0">
              <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <LinkIcon className="w-4 h-4 text-indigo-500" />
                Vincular Actividad Existente a Paso #{linkingStepOrder}
              </h3>
              <button onClick={() => setLinkingStepOrder(null)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-text-muted shrink-0">
              Selecciona un hallazgo, log o evidencia ya documentado para cumplir este paso sin duplicar acciones:
            </p>

            {/* Buscador y Pestañas de Filtro */}
            <div className="space-y-2 shrink-0">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
                <input
                  type="text"
                  placeholder="Buscar por título o contenido..."
                  value={linkSearch}
                  onChange={(e) => setLinkSearch(e.target.value)}
                  className="w-full text-xs pl-8 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
                <button
                  type="button"
                  onClick={() => setLinkFilter('all')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    linkFilter === 'all'
                      ? 'bg-indigo-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Todos ({caseActivities.length})
                </button>
                <button
                  type="button"
                  onClick={() => setLinkFilter('investigacion')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    linkFilter === 'investigacion'
                      ? 'bg-blue-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Investigación ({caseActivities.filter((a) => a.activity_type === 'investigacion').length})
                </button>
                <button
                  type="button"
                  onClick={() => setLinkFilter('accion')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    linkFilter === 'accion'
                      ? 'bg-indigo-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Acciones ({caseActivities.filter((a) => a.activity_type === 'accion').length})
                </button>
                <button
                  type="button"
                  onClick={() => setLinkFilter('evidencia')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    linkFilter === 'evidencia'
                      ? 'bg-emerald-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Evidencias ({caseActivities.filter((a) => a.activity_type === 'evidencia').length})
                </button>
                <button
                  type="button"
                  onClick={() => setLinkFilter('comunicacion')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    linkFilter === 'comunicacion'
                      ? 'bg-amber-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Comunicaciones ({caseActivities.filter((a) => a.activity_type === 'comunicacion').length})
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {loadingActivities ? (
                <div className="p-8 text-center text-xs text-text-muted">Cargando actividades del caso...</div>
              ) : filteredLinkActivities.length === 0 ? (
                <div className="p-6 text-center text-xs text-text-muted rounded-xl bg-surface-root border border-border-subtle">
                  No hay actividades que coincidan con el filtro seleccionado.
                </div>
              ) : (
                filteredLinkActivities.map((act) => {
                  const isSelected = selectedActivityIdsToLink.includes(act.id);
                  return (
                    <div
                      key={act.id}
                      onClick={() => handleToggleSelectActivity(act.id)}
                      className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center justify-between gap-3 relative select-none ${
                        isSelected
                          ? 'border-emerald-500 bg-emerald-500/10 ring-1 ring-emerald-500 shadow-sm'
                          : 'border-border-subtle bg-surface-root hover:border-slate-500'
                      }`}
                    >
                      <div className="space-y-1 flex-1 pr-2">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold uppercase px-1.5 py-0.2 rounded bg-surface-card border border-border-subtle text-text-muted">
                            {act.activity_type}
                          </span>
                          <h5 className={`text-xs font-semibold ${isSelected ? 'text-emerald-400 font-bold' : 'text-text-primary'}`}>
                            {act.title}
                          </h5>
                        </div>
                        <p className="text-[11px] text-text-muted line-clamp-1">{act.content || 'Sin contenido de texto'}</p>
                      </div>

                      {/* Palomita verde en la esquina cuando está seleccionado */}
                      <div className={`w-5 h-5 rounded-full flex items-center justify-center border transition-all shrink-0 ${
                        isSelected
                          ? 'bg-emerald-600 border-emerald-500 text-white'
                          : 'border-border-subtle bg-surface-card text-transparent'
                      }`}>
                        <Check className="w-3.5 h-3.5" />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border-subtle shrink-0">
              <span className="text-xs text-text-muted">
                {selectedActivityIdsToLink.length > 0
                  ? `${selectedActivityIdsToLink.length} seleccionado(s)`
                  : 'Selecciona una o varias actividades'}
              </span>

              <div className="flex items-center gap-2">
                <Button variant="secondary" size="sm" type="button" onClick={() => setLinkingStepOrder(null)}>
                  Cancelar
                </Button>

                <Button
                  variant="primary"
                  size="sm"
                  loading={savingLink}
                  disabled={selectedActivityIdsToLink.length === 0}
                  onClick={handleConfirmLinkMultiple}
                  icon={<LinkIcon className="w-3.5 h-3.5" />}
                >
                  Vincular Seleccionados {selectedActivityIdsToLink.length > 0 ? `(${selectedActivityIdsToLink.length})` : ''}
                </Button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Modal Desvincular con Selección Múltiple */}
      {unlinkingStepOrder !== null && createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-surface-card border border-border-subtle rounded-2xl p-6 w-full max-w-lg shadow-xl space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3 shrink-0">
              <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                <Unlink className="w-4 h-4 text-amber-500" />
                Desvincular Actividades del Paso #{unlinkingStepOrder}
              </h3>
              <button onClick={() => setUnlinkingStepOrder(null)} className="text-text-muted hover:text-text-primary">
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-text-muted shrink-0">
              Selecciona una o varias actividades para desvincularlas de este paso, o utiliza el botón inferior para desvincular todas:
            </p>

            {/* Buscador y Pestañas de Filtro para Desvincular */}
            <div className="space-y-2 shrink-0">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
                <input
                  type="text"
                  placeholder="Buscar entre actividades vinculadas..."
                  value={unlinkSearch}
                  onChange={(e) => setUnlinkSearch(e.target.value)}
                  className="w-full text-xs pl-8 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
                <button
                  type="button"
                  onClick={() => setUnlinkFilter('all')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    unlinkFilter === 'all'
                      ? 'bg-amber-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Todos ({stepLinkedActivities.length})
                </button>
                <button
                  type="button"
                  onClick={() => setUnlinkFilter('investigacion')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    unlinkFilter === 'investigacion'
                      ? 'bg-blue-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Investigación ({stepLinkedActivities.filter((a) => a.activity_type === 'investigacion').length})
                </button>
                <button
                  type="button"
                  onClick={() => setUnlinkFilter('accion')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    unlinkFilter === 'accion'
                      ? 'bg-indigo-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Acciones ({stepLinkedActivities.filter((a) => a.activity_type === 'accion').length})
                </button>
                <button
                  type="button"
                  onClick={() => setUnlinkFilter('evidencia')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    unlinkFilter === 'evidencia'
                      ? 'bg-emerald-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Evidencias ({stepLinkedActivities.filter((a) => a.activity_type === 'evidencia').length})
                </button>
                <button
                  type="button"
                  onClick={() => setUnlinkFilter('comunicacion')}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                    unlinkFilter === 'comunicacion'
                      ? 'bg-amber-600 text-white font-bold shadow-sm'
                      : 'bg-surface-root text-text-muted hover:text-text-primary border border-border-subtle'
                  }`}
                >
                  Comunicaciones ({stepLinkedActivities.filter((a) => a.activity_type === 'comunicacion').length})
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {filteredUnlinkActivities.length === 0 ? (
                <div className="p-6 text-center text-xs text-text-muted rounded-xl bg-surface-root border border-border-subtle">
                  No hay actividades vinculadas que coincidan con el filtro.
                </div>
              ) : (
                filteredUnlinkActivities.map((act) => {
                  const isSelected = selectedActivityIdsToUnlink.includes(act.id);
                  return (
                    <div
                      key={act.id}
                      onClick={() => handleToggleSelectUnlinkActivity(act.id)}
                      className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center justify-between gap-3 relative select-none ${
                        isSelected
                          ? 'border-amber-500 bg-amber-500/10 ring-1 ring-amber-500 shadow-sm'
                          : 'border-border-subtle bg-surface-root hover:border-slate-500'
                      }`}
                    >
                      <div className="space-y-1 flex-1 pr-2 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-surface-card border border-border-subtle text-amber-400 font-mono shrink-0">
                            {act.activity_type}
                          </span>
                          <h5 className={`text-xs font-semibold truncate ${isSelected ? 'text-amber-400 font-bold' : 'text-text-primary'}`} title={act.title}>
                            {act.title}
                          </h5>
                        </div>
                        <p className="text-[11px] text-text-muted truncate">
                          {act.content || 'Sin contenido de texto'}
                        </p>
                      </div>

                      {/* Palomita en la esquina cuando está seleccionado para desvincular */}
                      <div className={`w-5 h-5 rounded-full flex items-center justify-center border transition-all shrink-0 ${
                        isSelected
                          ? 'bg-amber-600 border-amber-500 text-white'
                          : 'border-border-subtle bg-surface-card text-transparent'
                      }`}>
                        <Check className="w-3.5 h-3.5" />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border-subtle shrink-0">
              <Button
                variant="danger"
                size="sm"
                loading={savingLink}
                onClick={handleConfirmUnlinkAll}
              >
                Desvincular Todas ({stepLinkedActivities.length})
              </Button>

              <div className="flex items-center gap-2">
                <Button variant="secondary" size="sm" type="button" onClick={() => setUnlinkingStepOrder(null)}>
                  Cancelar
                </Button>

                <Button
                  variant="danger"
                  size="sm"
                  loading={savingLink}
                  disabled={selectedActivityIdsToUnlink.length === 0}
                  onClick={handleConfirmUnlinkMultiple}
                  icon={<Unlink className="w-3.5 h-3.5" />}
                  className="bg-amber-600 hover:bg-amber-500 text-white border-amber-500"
                >
                  Desvincular Seleccionadas {selectedActivityIdsToUnlink.length > 0 ? `(${selectedActivityIdsToUnlink.length})` : ''}
                </Button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};
