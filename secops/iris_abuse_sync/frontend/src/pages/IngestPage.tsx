import React, { useState } from 'react';
import {
  Inbox,
  FileText,
  UploadCloud,
  CheckCircle2,
  Sparkles,
  ArrowRight,
  ShieldAlert,
  Layers,
  FileUp,
  AlertCircle,
  Copy,
} from 'lucide-react';
import { HeaderBar } from '../components/navigation/HeaderBar';
import { Button } from '../components/common/Button';
import { Badge, OrgBadge } from '../components/common/Badge';
import { api } from '../api/client';
import { IngestResponse, Organization } from '../types';

interface IngestPageProps {
  onNavigate?: (path: string) => void;
  onOpenCase?: (caseId: number) => void;
}

export const IngestPage: React.FC<IngestPageProps> = ({ onNavigate, onOpenCase }) => {
  const [currentStep, setCurrentStep] = useState<1 | 2 | 3 | 4>(1);
  const [ingestMode, setIngestMode] = useState<'upload' | 'text'>('upload');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState('');
  const [subject, setSubject] = useState('');
  const [organization, setOrganization] = useState<Organization>('NBX');
  const [useGemini, setUseGemini] = useState(true);
  const [loading, setLoading] = useState(false);
  const [ingestResult, setIngestResult] = useState<IngestResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleProcess = async () => {
    setError(null);
    setLoading(true);
    try {
      let res: IngestResponse;
      if (ingestMode === 'upload' && selectedFile) {
        res = await api.ingestUpload(selectedFile, organization, false, useGemini);
      } else {
        res = await api.ingestText(rawText, subject || 'Reporte Manual de Abuso', organization, false, useGemini);
      }
      setIngestResult(res);
      setCurrentStep(2);
    } catch (err: any) {
      setError(err.message || 'Error procesando la ingesta');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmCreateAlert = async () => {
    if (!ingestResult) return;
    setLoading(true);
    try {
      let res: IngestResponse;
      if (ingestMode === 'upload' && selectedFile) {
        res = await api.ingestUpload(selectedFile, organization, true, useGemini);
      } else {
        res = await api.ingestText(rawText, subject || 'Reporte Manual de Abuso', organization, true, useGemini);
      }
      setCurrentStep(4);
      setIngestResult(res);
    } catch (err: any) {
      alert(`Error al crear alerta en IRIS: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSample = async (sampleKey: string) => {
    setLoading(true);
    try {
      const res = await api.loadSampleTicket(sampleKey);
      setIngestResult(res);
      setCurrentStep(2);
    } catch (err: any) {
      alert(`Error cargando muestra: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto w-full pb-12">
      {/* Header Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 dark:text-white light:text-slate-900 tracking-tight">
            Ingesta Multi-Canal de Reportes
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-400 light:text-slate-600 mt-0.5">
            Flujo guiado de recepción, desfangado de IOCs, análisis heurístico y generación de alertas
          </p>
        </div>
        {onNavigate && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onNavigate('/ingest-history')}
            icon={<FileText className="w-3.5 h-3.5" />}
          >
            Ver Historial de Ingesta
          </Button>
        )}
      </div>

      <div className="space-y-6">
        {/* Step Indicator Bar */}
        <div className="grid grid-cols-4 gap-2 border-b border-border-subtle pb-5 text-xs font-semibold">
          {[
            { step: 1, label: '1. Origen del Reporte' },
            { step: 2, label: '2. Normalización & Extracción' },
            { step: 3, label: '3. Clasificación 4 Ejes' },
            { step: 4, label: '4. Alerta en DFIR-IRIS' },
          ].map((item) => (
            <div
              key={item.step}
              className={`flex items-center gap-2 pb-2 border-b-2 transition-all ${
                currentStep >= item.step
                  ? 'border-blue-500 text-blue-400 font-bold'
                  : 'border-transparent text-slate-500'
              }`}
            >
              <span
                className={`w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold ${
                  currentStep >= item.step
                    ? 'bg-blue-600 text-white'
                    : 'bg-surface-card text-slate-500 border border-border-subtle'
                }`}
              >
                {item.step}
              </span>
              <span className="hidden sm:inline truncate">{item.label}</span>
            </div>
          ))}
        </div>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/60 border border-red-800/80 text-red-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {/* STEP 1: Select Source */}
        {currentStep === 1 && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white">Selecciona el Modo de Ingesta</h3>
                  <p className="text-xs text-slate-400">Sube un archivo de denuncia o pega el texto directamente</p>
                </div>

                {/* Organization selector */}
                <div className="flex items-center gap-2 bg-surface-root p-1 rounded-lg border border-border-subtle text-xs">
                  <span className="text-[11px] text-slate-400 px-2 font-semibold">Organización:</span>
                  {(['NBX', 'HP'] as const).map((org) => (
                    <button
                      key={org}
                      type="button"
                      onClick={() => setOrganization(org)}
                      className={`px-3 py-1 rounded text-xs font-bold transition-colors ${
                        organization === org
                          ? org === 'NBX' ? 'bg-blue-600 text-white' : 'bg-purple-600 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {org === 'NBX' ? 'NEUBOX (ID 2)' : 'HOSPEDANDO (ID 3)'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Mode Switcher */}
              <div className="flex items-center gap-2 border-b border-border-subtle pb-3">
                <button
                  type="button"
                  onClick={() => setIngestMode('upload')}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 ${
                    ingestMode === 'upload'
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <FileUp className="w-4 h-4" />
                  <span>Subir Archivo (.pdf, .eml, .txt)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setIngestMode('text')}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 ${
                    ingestMode === 'text'
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <Copy className="w-4 h-4" />
                  <span>Pegar Texto de Correo o Ticket</span>
                </button>
              </div>

              {/* Upload Input */}
              {ingestMode === 'upload' ? (
                <div className="border-2 border-dashed border-border-subtle rounded-xl p-8 text-center bg-surface-root/50 hover:border-slate-500 transition-colors">
                  <UploadCloud className="w-10 h-10 text-blue-400 mx-auto mb-3" />
                  <p className="text-xs font-semibold text-slate-200">
                    {selectedFile ? selectedFile.name : 'Arrastra tu archivo aquí o haz clic para explorar'}
                  </p>
                  <p className="text-[11px] text-slate-500 mt-1">Soporta tickets PDF de Zammad, correos .EML y registros .TXT</p>
                  <input
                    type="file"
                    id="file-ingest"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setSelectedFile(e.target.files[0]);
                      }
                    }}
                  />
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="mt-4"
                    onClick={() => document.getElementById('file-ingest')?.click()}
                  >
                    Examinar Archivos
                  </Button>
                </div>
              ) : (
                <div className="space-y-3">
                  <div>
                    <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                      Asunto o Título del Reporte
                    </label>
                    <input
                      type="text"
                      value={subject}
                      onChange={(e) => setSubject(e.target.value)}
                      placeholder="ej. [Abuse #791092] Phishing URL detected in helpdesk"
                      className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                      Cuerpo del Mensaje / Cabeceras
                    </label>
                    <textarea
                      rows={8}
                      value={rawText}
                      onChange={(e) => setRawText(e.target.value)}
                      placeholder="Pega el contenido completo del correo, denuncia o bloque de Bastion..."
                      className="w-full p-3 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs font-mono focus:ring-1 focus:ring-blue-500 focus:outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Gemini toggle */}
              <div className="flex items-center justify-between p-3.5 rounded-xl bg-surface-elevated/40 border border-border-subtle">
                <div className="flex items-center gap-2 text-xs">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span className="font-semibold text-slate-200">Enriquecer con Google Gemini AI</span>
                </div>
                <input
                  type="checkbox"
                  checked={useGemini}
                  onChange={(e) => setUseGemini(e.target.checked)}
                  className="rounded bg-surface-root border-border-subtle text-cyan-500 focus:ring-0"
                />
              </div>

              {/* Samples test shortcuts */}
              <div className="pt-3 border-t border-border-subtle flex flex-wrap items-center gap-2">
                <span className="text-[10px] uppercase font-bold text-slate-500">Muestras Reales:</span>
                {['791092', '791233', '791255', '791328', '791842'].map((key) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleLoadSample(key)}
                    className="px-2 py-0.5 rounded bg-surface-elevated hover:bg-surface-hover text-slate-300 text-[11px] font-mono border border-border-subtle"
                  >
                    Ticket #{key}
                  </button>
                ))}
              </div>

              <div className="flex justify-end pt-3">
                <Button
                  variant="primary"
                  loading={loading}
                  disabled={ingestMode === 'upload' ? !selectedFile : !rawText.trim()}
                  onClick={handleProcess}
                  icon={<ArrowRight className="w-4 h-4" />}
                >
                  Normalizar y Analizar
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* STEP 2 & 3: Extraction & Classification Preview */}
        {currentStep >= 2 && currentStep <= 3 && ingestResult && (
          <div className="space-y-6">
            <div className="p-6 rounded-2xl bg-surface-card border border-border-subtle shadow-sm space-y-5">
              <div className="flex items-center justify-between border-b border-border-subtle pb-3">
                <div>
                  <h3 className="text-sm font-bold text-white">Extracción Forense & Indicadores</h3>
                  <p className="text-xs text-slate-400">
                    Paquete SHA-256: <code className="text-cyan-300 font-mono">{ingestResult.evidence_package?.primary_sha256?.substring(0, 16)}...</code>
                  </p>
                </div>
                <OrgBadge org={ingestResult.organization} />
              </div>

              {/* Extracted Parameters Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-surface-root border border-border-subtle">
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Ticket Abuso</span>
                  <span className="font-mono font-bold text-white text-sm">{ingestResult.normalized.abuse_ticket_id || '—'}</span>
                </div>
                <div className="p-3 rounded-xl bg-surface-root border border-border-subtle">
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Dominio Principal</span>
                  <span className="font-mono font-bold text-cyan-300 text-sm truncate block">{ingestResult.normalized.primary_domain || '—'}</span>
                </div>
                <div className="p-3 rounded-xl bg-surface-root border border-border-subtle">
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Servidor</span>
                  <span className="font-mono text-slate-200">{ingestResult.normalized.server_name || 'No detectado'}</span>
                </div>
                <div className="p-3 rounded-xl bg-surface-root border border-border-subtle">
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Categoría Heurística</span>
                  <span className="font-semibold text-slate-200">{ingestResult.heuristics.category_name}</span>
                </div>
              </div>

              {/* 4-Axis Classification Card */}
              <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border-subtle space-y-3">
                <span className="text-xs font-bold text-white block">Clasificación de 4 Ejes Independientes</span>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                  <div>
                    <span className="text-[10px] text-slate-400 block">Eje 1: Actividad Reportada</span>
                    <span className="font-mono text-slate-200">{ingestResult.heuristics.reported_activity}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block">Eje 2: Incidente Confirmado</span>
                    <span className="font-mono text-slate-200">{ingestResult.heuristics.confirmed_incident_type}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block">Eje 3: Vector de Entrada</span>
                    <span className="font-mono text-slate-200">{ingestResult.heuristics.entry_vector}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block">Eje 4: Causa Raíz</span>
                    <span className="font-mono text-slate-200">{ingestResult.heuristics.root_cause}</span>
                  </div>
                </div>
              </div>

              {/* Gemini Insight Callout if available */}
              {ingestResult.gemini?.ai_used && (
                <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/60 space-y-2">
                  <div className="flex items-center gap-2 text-cyan-300 font-bold text-xs">
                    <Sparkles className="w-4 h-4" />
                    <span>Conclusiones Sugeridas por Google Gemini</span>
                  </div>
                  <p className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
                    {ingestResult.gemini.analysis?.conclusion || ingestResult.gemini.analysis?.summary}
                  </p>
                </div>
              )}

              {/* Navigation and confirm */}
              <div className="flex items-center justify-between pt-4 border-t border-border-subtle">
                <Button variant="ghost" size="sm" onClick={() => setCurrentStep(1)}>
                  Volver / Modificar
                </Button>
                <Button
                  variant="primary"
                  loading={loading}
                  onClick={handleConfirmCreateAlert}
                  icon={<CheckCircle2 className="w-4 h-4" />}
                >
                  Confirmar y Crear Alerta en IRIS
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* STEP 4: Success confirmation */}
        {currentStep === 4 && ingestResult && (
          <div className="p-8 rounded-2xl bg-surface-card border border-border-subtle shadow-sm text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-emerald-950/80 border border-emerald-700/60 text-emerald-400 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white">¡Alerta Creada Exitosamente en DFIR-IRIS!</h3>
            <p className="text-xs text-slate-300 max-w-md mx-auto">
              La alerta ha sido registrada con el paquete de evidencia forense SHA-256 e indicadores correlacionados.
            </p>
            {ingestResult.iris_alert_id && (
              <div className="p-3 rounded-lg bg-surface-root border border-border-subtle inline-block font-mono text-xs text-cyan-300">
                Alerta ID: #{ingestResult.iris_alert_id} &bull; {ingestResult.alert_title}
              </div>
            )}
            <div className="flex justify-center gap-3 pt-4">
              <Button variant="secondary" onClick={() => setCurrentStep(1)}>
                Ingestar Otro Reporte
              </Button>
              <Button variant="primary" onClick={() => onNavigate ? onNavigate('/alerts') : undefined}>
                Ir al Centro de Alertas
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
