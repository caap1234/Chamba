import React, { useState } from 'react';
import { Plus, Search, Terminal, CheckCircle2, AlertTriangle, FileText, Calendar } from 'lucide-react';
import { InvestigationItem } from '../../types';
import { Button } from '../common/Button';
import { Modal } from '../common/Modal';

interface InvestigationTimelineProps {
  investigations: InvestigationItem[];
  onAddInvestigation: (item: {
    source_consulted: string;
    commands_or_queries?: string;
    results_observed: string;
    fact_type: 'reported_claim' | 'confirmed_fact' | 'technical_indicator' | 'hypothesis';
  }) => void;
}

export const InvestigationTimeline: React.FC<InvestigationTimelineProps> = ({
  investigations,
  onAddInvestigation,
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [source, setSource] = useState('Análisis Bastion / DNS');
  const [commands, setCommands] = useState('');
  const [results, setResults] = useState('');
  const [factType, setFactType] = useState<'reported_claim' | 'confirmed_fact' | 'technical_indicator' | 'hypothesis'>('confirmed_fact');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!source.trim() || !results.trim()) return;
    onAddInvestigation({
      source_consulted: source.trim(),
      commands_or_queries: commands.trim() || undefined,
      results_observed: results.trim(),
      fact_type: factType,
    });
    setCommands('');
    setResults('');
    setIsModalOpen(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white">Cronología de Investigaciones y Hallazgos</h3>
          <p className="text-xs text-slate-400">
            Registro secuencial de fuentes consultadas, consultas ejecutadas y hechos verificados
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setIsModalOpen(true)}
          icon={<Plus className="w-3.5 h-3.5" />}
        >
          Agregar Entrada
        </Button>
      </div>

      <div className="space-y-3">
        {investigations.length === 0 ? (
          <div className="p-8 text-center bg-surface-card border border-border-subtle rounded-xl text-slate-500 text-xs italic">
            No se han registrado investigaciones estructuradas aún.
          </div>
        ) : (
          investigations.map((inv, idx) => (
            <div
              key={inv.id || idx}
              className="p-4 rounded-xl bg-surface-card border border-border-subtle space-y-2 shadow-sm hover:border-slate-600 transition-colors"
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="p-1 rounded bg-blue-950/60 text-blue-400 border border-blue-800/60 font-mono text-[10px] font-bold">
                    #{idx + 1}
                  </span>
                  <span className="font-bold text-white">{inv.source_consulted}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${
                      inv.fact_type === 'confirmed_fact'
                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                        : inv.fact_type === 'technical_indicator'
                        ? 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60'
                        : 'bg-amber-950/80 text-amber-300 border-amber-700/60'
                    }`}
                  >
                    {inv.fact_type === 'confirmed_fact'
                      ? 'Hecho Confirmado'
                      : inv.fact_type === 'technical_indicator'
                      ? 'Indicador Técnico'
                      : 'Alegación Reportada'}
                  </span>
                  {inv.executed_at && (
                    <span className="text-[10px] text-slate-500">
                      {new Date(inv.executed_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                    </span>
                  )}
                </div>
              </div>

              {inv.commands_or_queries && (
                <div className="bg-surface-root rounded-lg p-2.5 font-mono text-[11px] text-cyan-300 border border-border-subtle overflow-x-auto">
                  <span className="text-slate-500 select-none">$ </span>
                  {inv.commands_or_queries}
                </div>
              )}

              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                {inv.results_observed}
              </p>
            </div>
          ))
        )}
      </div>

      {/* Modal Nueva Entrada */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Registrar Actividad de Investigación"
        subtitle="Documenta comandos, consultas Bastion/DNS y resultados observados"
      >
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                Fuente Consultada *
              </label>
              <input
                type="text"
                required
                value={source}
                onChange={(e) => setSource(e.target.value)}
                placeholder="ej. Bastion SSH, WHOIS, cPanel API"
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                Naturaleza de la Información
              </label>
              <select
                value={factType}
                onChange={(e) => setFactType(e.target.value as any)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              >
                <option value="confirmed_fact">Hecho Confirmado (Verificado por SOC)</option>
                <option value="technical_indicator">Indicador Técnico (IP/Dominio/Hash)</option>
                <option value="reported_claim">Alegación de Tercero (No corroborado)</option>
                <option value="hypothesis">Hipótesis / En Investigación</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
              Comando o Consulta Ejecutada
            </label>
            <input
              type="text"
              value={commands}
              onChange={(e) => setCommands(e.target.value)}
              placeholder="ej. dig +short @8.8.8.8 domain.com / grep -i 'spam' /var/log/exim_mainlog"
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
              Resultado Observado *
            </label>
            <textarea
              rows={4}
              required
              value={results}
              onChange={(e) => setResults(e.target.value)}
              placeholder="Detalla lo que se identificó, códigos HTTP, cuentas involucradas o hallazgos..."
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none resize-none"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
            <Button variant="ghost" size="sm" type="button" onClick={() => setIsModalOpen(false)}>
              Cancelar
            </Button>
            <Button variant="primary" size="sm" type="submit">
              Guardar Entrada
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

