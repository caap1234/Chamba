import React, { useState } from 'react';
import { X, Send, Sparkles, Bot, User, CheckCircle2, AlertCircle, Trash2, ArrowRight, Minus, Copy, Check, FileText } from 'lucide-react';
import { useCopilot } from '../../context/CopilotContext';
import { Button } from '../common/Button';
import { renderMarkdownToHtml } from '../common/MarkdownEditor';
import { api } from '../../api/client';
import { ConfirmModal } from '../common/ConfirmModal';

interface FloatingCopilotDrawerProps {
  onApplyChanges?: (changes: Record<string, any>) => void;
}

export const FloatingCopilotDrawer: React.FC<FloatingCopilotDrawerProps> = ({ onApplyChanges }) => {
  const { isOpen, setIsOpen, activeContext, messages, sendMessage, clearMessages, isThinking } = useCopilot();
  const [inputText, setInputText] = useState('');
  const [showCloseConfirm, setShowCloseConfirm] = useState(false);
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null);
  const [applyingCorrection, setApplyingCorrection] = useState(false);
  const [pendingCorrectionText, setPendingCorrectionText] = useState<string | null>(null);
  const [correctionSuccessMsg, setCorrectionSuccessMsg] = useState<string | null>(null);

  const handleCopyMessage = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedMsgId(id);
    setTimeout(() => setCopiedMsgId(null), 2000);
  };

  const handleApplyNoteDirectly = (correctedText: string) => {
    if (!activeContext.id) return;
    setPendingCorrectionText(correctedText);
  };

  const handleConfirmApplyNote = async () => {
    if (!pendingCorrectionText || !activeContext.id) return;
    const caseId = Number(activeContext.id);
    if (!caseId) return;

    setApplyingCorrection(true);
    try {
      const bundle = await api.getCaseBundle(caseId);
      const notes = bundle.iris_case?.notes || [];
      const targetNote = notes.find((n: any) => n.note_title?.includes('04') || n.note_title?.includes('Integrada')) || notes[0];
      if (!targetNote) {
        alert('No se encontró una nota técnica en el caso para actualizar.');
        return;
      }
      let cleanText = pendingCorrectionText;
      const fenceMatch = pendingCorrectionText.match(/```(?:markdown)?\n([\s\S]*?)```/);
      if (fenceMatch) {
        cleanText = fenceMatch[1];
      }
      await api.updateCaseNote(caseId, targetNote.note_id, cleanText);
      setPendingCorrectionText(null);
      setCorrectionSuccessMsg(`✓ Nota técnica #${targetNote.note_id} actualizada en IRIS.`);
      setTimeout(() => setCorrectionSuccessMsg(null), 4000);
    } catch (err: any) {
      alert(`Error aplicando nota: ${err.message}`);
    } finally {
      setApplyingCorrection(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || isThinking) return;
    sendMessage(inputText.trim());
    setInputText('');
  };

  const handleShortcut = (prompt: string) => {
    sendMessage(prompt);
  };

  const handleCloseClick = () => {
    if (messages.length > 1) {
      setShowCloseConfirm(true);
    } else {
      setIsOpen(false);
    }
  };

  const handleConfirmClose = () => {
    clearMessages();
    setShowCloseConfirm(false);
    setIsOpen(false);
  };

  const handleCancelClose = () => {
    setShowCloseConfirm(false);
  };

  return (
    <>
      {/* Botón Circular Flotante (FAB) en la esquina inferior derecha para no obstruir paginación */}
      {!isOpen && (
        <button
          type="button"
          onClick={() => setIsOpen(true)}
          className="fixed bottom-5 right-5 z-40 w-12 h-12 rounded-full bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white shadow-2xl border border-cyan-400/50 hover:scale-110 active:scale-95 transition-all flex items-center justify-center group ring-4 ring-cyan-500/10 cursor-pointer"
          title={activeContext.id ? `Copiloto SOC (Gemini AI) - Caso #${activeContext.id}` : 'Copiloto SOC (Gemini AI)'}
        >
          <div className="relative flex items-center justify-center">
            <Sparkles className="w-5 h-5 text-cyan-200 group-hover:rotate-12 transition-transform" />
            {activeContext.id ? (
              <span className="absolute -top-3.5 -right-3.5 px-1.5 py-0.5 rounded-full bg-slate-950 border border-cyan-400 text-[9px] font-mono font-bold text-cyan-200 shadow-sm leading-none">
                #{activeContext.id}
              </span>
            ) : (
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-slate-900" />
            )}
          </div>
        </button>
      )}

      {/* Ventana de Chat Flotante en la esquina inferior derecha */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 w-96 sm:w-[440px] h-[600px] max-h-[85vh] bg-[#0E1726]/95 backdrop-blur-xl border border-cyan-500/30 rounded-2xl shadow-2xl z-50 flex flex-col overflow-hidden animate-slide-up">
          {/* Header */}
          <div className="px-4 py-3 border-b border-border-subtle bg-surface-card flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-cyan-950/80 border border-cyan-700/60 text-cyan-300">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                  Copiloto SOC
                  <span className="text-[9px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700/50">
                    Gemini AI
                  </span>
                </h3>
                <p className="text-[10px] text-slate-400">Asistencia técnica contextual para el analista</p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              {/* Botón Minimizar: guarda la conversación para continuar después */}
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                title="Minimizar (conserva la conversación para continuar después)"
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-surface-elevated transition-colors"
              >
                <Minus className="w-4 h-4" />
              </button>

              {/* Botón Limpiar conversación */}
              <button
                type="button"
                onClick={clearMessages}
                title="Limpiar conversación actual"
                className="p-1.5 rounded-lg text-slate-400 hover:text-amber-300 hover:bg-surface-elevated transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>

              {/* Botón Cerrar y finalizar */}
              <button
                type="button"
                onClick={handleCloseClick}
                title="Cerrar conversación"
                className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-surface-elevated transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Context Banner */}
          <div className="px-4 py-2 bg-surface-elevated/70 border-b border-border-subtle flex items-center justify-between text-xs shrink-0">
            <div className="flex items-center gap-2 overflow-hidden">
              <span className="text-slate-400 text-[11px]">Contexto:</span>
              {activeContext.id ? (
                <span className="font-semibold text-cyan-300 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/80 truncate text-[11px]">
                  {activeContext.type === 'case' ? 'Caso' : 'Alerta'} #{activeContext.id} &bull; {activeContext.title || 'Activo'}
                </span>
              ) : (
                <span className="text-slate-400 italic text-[11px]">General (sin caso activo)</span>
              )}
            </div>
          </div>

          {/* Aviso Estético Dentro del Chat para Confirmar Cierre */}
          {showCloseConfirm && (
            <div className="m-3 p-3 rounded-xl bg-surface-card border border-amber-500/50 shadow-xl text-xs shrink-0 animate-in fade-in slide-in-from-top-2">
              <div className="flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="font-semibold text-slate-100 text-xs">¿Deseas finalizar y cerrar la conversación?</p>
                  <p className="text-[11px] text-slate-400 mt-1 leading-snug">
                    Se borrará el historial de este chat. Si prefieres conservarlo para después, haz clic en el botón Minimizar (<Minus className="w-3 h-3 inline" />).
                  </p>
                  <div className="flex items-center gap-2 mt-3">
                    <button
                      type="button"
                      onClick={handleConfirmClose}
                      className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-[11px] transition-colors shadow-sm"
                    >
                      Finalizar y Cerrar
                    </button>
                    <button
                      type="button"
                      onClick={handleCancelClose}
                      className="px-3 py-1.5 rounded-lg bg-surface-elevated hover:bg-surface-hover text-slate-300 text-[11px] border border-border-subtle transition-colors"
                    >
                      Cancelar
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Quick Prompts */}
          <div className="p-2.5 bg-surface-card/40 border-b border-border-subtle flex flex-wrap gap-1.5 text-[10px] shrink-0">
            <button
              type="button"
              onClick={() => handleShortcut('Resume los hechos confirmados y el vector de este incidente')}
              className="px-2 py-1 rounded bg-surface-elevated hover:bg-surface-hover text-slate-300 border border-border-subtle transition-colors"
            >
              Resumir caso
            </button>
            <button
              type="button"
              onClick={() => handleShortcut('Corrige la redacción, gramática y orden de las notas del caso')}
              className="px-2 py-1 rounded bg-surface-elevated hover:bg-surface-hover text-slate-300 border border-border-subtle transition-colors"
            >
              Corregir ortografía
            </button>
            <button
              type="button"
              onClick={() => handleShortcut('Propón acciones de contención y notificación según los procedimientos SOC')}
              className="px-2 py-1 rounded bg-surface-elevated hover:bg-surface-hover text-slate-300 border border-border-subtle transition-colors"
            >
              Proponer acciones
            </button>
          </div>

          {/* Messages Scroll Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex flex-col ${
                  msg.sender === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div className="flex items-center justify-between w-full mb-1 px-1 text-[10px] text-slate-400">
                  <div className="flex items-center gap-1.5">
                    {msg.sender === 'assistant' ? (
                      <>
                        <Bot className="w-3 h-3 text-cyan-400" />
                        <span className="font-semibold text-slate-300">Gemini</span>
                      </>
                    ) : msg.sender === 'user' ? (
                      <>
                        <span className="font-semibold text-slate-300">Analista</span>
                        <User className="w-3 h-3 text-blue-400" />
                      </>
                    ) : (
                      <AlertCircle className="w-3 h-3 text-amber-400" />
                    )}
                    <span>{msg.timestamp}</span>
                  </div>

                  {msg.sender === 'assistant' && (
                    <button
                      type="button"
                      onClick={() => handleCopyMessage(msg.id, msg.text)}
                      title="Copiar texto de la respuesta"
                      className="text-[10px] text-slate-400 hover:text-cyan-300 flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      {copiedMsgId === msg.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedMsgId === msg.id ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  )}
                </div>

                <div
                  className={`max-w-[92%] rounded-xl p-3 text-xs leading-relaxed shadow-sm ${
                    msg.sender === 'user'
                      ? 'bg-blue-600 text-white font-medium rounded-tr-none'
                      : msg.sender === 'assistant'
                      ? 'bg-surface-card text-slate-200 border border-border-subtle rounded-tl-none overflow-x-auto'
                      : 'bg-red-950/60 text-red-300 border border-red-800/60'
                  }`}
                >
                  {msg.sender === 'assistant' ? (
                    <div
                      className="text-slate-200 text-xs leading-relaxed"
                      dangerouslySetInnerHTML={renderMarkdownToHtml(msg.text)}
                    />
                  ) : (
                    <div className="whitespace-pre-wrap">{msg.text}</div>
                  )}

                  {/* Botón para aplicar texto corregido a Nota Técnica de IRIS */}
                  {msg.sender === 'assistant' && activeContext.id && activeContext.type === 'case' && (
                    <div className="mt-3 pt-2 border-t border-border-subtle flex items-center justify-end">
                      <button
                        type="button"
                        disabled={applyingCorrection}
                        onClick={() => handleApplyNoteDirectly(msg.text)}
                        className="px-2.5 py-1 rounded bg-indigo-600/80 hover:bg-indigo-600 active:bg-indigo-700 text-white font-medium text-[10px] flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm disabled:opacity-40"
                        title="Reemplaza la nota técnica oficial en IRIS con esta corrección"
                      >
                        <FileText className="w-3 h-3 text-cyan-300" />
                        <span>{applyingCorrection ? 'Aplicando...' : 'Aplicar a Nota Oficial IRIS'}</span>
                      </button>
                    </div>
                  )}

                  {/* Proposed Changes Preview */}
                  {msg.proposedChanges && onApplyChanges && (
                    <div className="mt-3 pt-2.5 border-t border-border-subtle">
                      <div className="text-[11px] font-bold text-cyan-300 mb-1 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Cambios sugeridos listos para aplicar:
                      </div>
                      <pre className="text-[10px] font-mono bg-surface-root p-2 rounded text-slate-300 overflow-x-auto mb-2">
                        {JSON.stringify(msg.proposedChanges, null, 2)}
                      </pre>
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => onApplyChanges(msg.proposedChanges!)}
                        icon={<ArrowRight className="w-3.5 h-3.5" />}
                      >
                        Aplicar al caso
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            ))}

            {isThinking && (
              <div className="flex items-center gap-2 p-3 rounded-xl bg-surface-card border border-border-subtle text-xs text-slate-400">
                <Sparkles className="w-4 h-4 text-cyan-400 animate-spin" />
                <span>Gemini está analizando el caso...</span>
              </div>
            )}
          </div>

          {correctionSuccessMsg && (
            <div className="p-2 mx-3 mb-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs text-center">
              {correctionSuccessMsg}
            </div>
          )}

          {/* Input Form */}
          <form onSubmit={handleSubmit} className="p-3 border-t border-border-subtle bg-surface-card shrink-0">
            <div className="relative flex items-center">
              <input
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Pregunta a Gemini o pide redactar/analizar..."
                className="w-full pl-3 pr-10 py-2 rounded-lg bg-surface-root border border-border-subtle text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/80 focus:border-cyan-500"
                disabled={isThinking}
              />
              <button
                type="submit"
                disabled={!inputText.trim() || isThinking}
                className="absolute right-1.5 p-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 transition-colors cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
            <p className="mt-1.5 text-[9px] text-slate-400 text-center">
              Las sugerencias técnicas deben ser validadas por el analista SOC.
            </p>
          </form>
        </div>
      )}

      {/* Confirmación in-app para aplicar corrección de nota oficial */}
      <ConfirmModal
        isOpen={pendingCorrectionText !== null}
        title="Reemplazar Nota Técnica Oficial en IRIS"
        message="¿Confirmas que deseas sobrescribir el contenido de la ficha/nota técnica oficial en DFIR-IRIS con esta versión corregida por la IA?"
        confirmLabel="Reemplazar Nota en IRIS"
        cancelLabel="Cancelar"
        variant="warning"
        loading={applyingCorrection}
        onConfirm={handleConfirmApplyNote}
        onClose={() => setPendingCorrectionText(null)}
      />
    </>
  );
};
