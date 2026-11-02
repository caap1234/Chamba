import React, { useState } from 'react';
import { Plus, Check, Clock, AlertOctagon, XCircle, ShieldCheck, PlayCircle, MinusCircle, Trash2 } from 'lucide-react';
import { CaseAction, ActionStatus } from '../../types';
import { ActionStatusBadge } from '../common/Badge';
import { Button } from '../common/Button';
import { Modal } from '../common/Modal';

interface ActionManagerProps {
  actions: CaseAction[];
  onAddAction: (action: { title: string; action_type: string; status: ActionStatus; result_notes?: string }) => void;
  onUpdateStatus: (index: number, newStatus: ActionStatus, resultNotes?: string) => void;
  onDeleteAction?: (actionId: number) => void;
}

export const ActionManager: React.FC<ActionManagerProps> = ({
  actions,
  onAddAction,
  onUpdateStatus,
  onDeleteAction,
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newType, setNewType] = useState('notificacion_cliente');
  const [newStatus, setNewStatus] = useState<ActionStatus>('propuesta');
  const [newNotes, setNewNotes] = useState('');

  const statusOptions: { value: ActionStatus; label: string }[] = [
    { value: 'propuesta', label: 'Propuesta' },
    { value: 'autorizada', label: 'Autorizada' },
    { value: 'pendiente', label: 'Pendiente' },
    { value: 'en_ejecucion', label: 'En Ejecución' },
    { value: 'ejecutada', label: 'Ejecutada' },
    { value: 'verificada', label: 'Verificada' },
    { value: 'cancelada', label: 'Cancelada' },
    { value: 'no_aplicable', label: 'No Aplicable' },
  ];

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    onAddAction({
      title: newTitle.trim(),
      action_type: newType,
      status: newStatus,
      result_notes: newNotes.trim() || undefined,
    });
    setNewTitle('');
    setNewNotes('');
    setNewStatus('propuesta');
    setIsModalOpen(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white">Acciones Estructuradas del Incidente</h3>
          <p className="text-xs text-slate-400">
            Seguimiento riguroso bajo los 8 estados de ciclo de vida SOC
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setIsModalOpen(true)}
          icon={<Plus className="w-3.5 h-3.5" />}
        >
          Agregar Acción
        </Button>
      </div>

      <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm">
        <table className="w-full text-left text-xs">
          <thead className="bg-surface-elevated/70 text-slate-400 uppercase font-bold text-[10px] tracking-wider border-b border-border-subtle">
            <tr>
              <th className="py-3 px-4">Acción / Tarea</th>
              <th className="py-3 px-4">Tipo</th>
              <th className="py-3 px-4">Estado (8 Estados)</th>
              <th className="py-3 px-4">Resultado / Resolución</th>
              <th className="py-3 px-4 text-right">Actualizar</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle text-slate-200">
            {actions.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-8 text-center text-slate-500 italic">
                  No hay acciones asignadas a este incidente.
                </td>
              </tr>
            ) : (
              actions.map((act, idx) => (
                <tr key={act.id || idx} className="hover:bg-surface-elevated/40 transition-colors">
                  <td className="py-3 px-4 font-semibold text-white">
                    {act.title}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                    {act.action_type}
                  </td>
                  <td className="py-3 px-4">
                    <ActionStatusBadge status={act.status} />
                  </td>
                  <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                    {act.result_notes || '—'}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <select
                        value={act.status}
                        onChange={(e) => onUpdateStatus(idx, e.target.value as ActionStatus, act.result_notes)}
                        className="px-2 py-1 rounded bg-surface-root border border-border-subtle text-slate-300 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
                      >
                        {statusOptions.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>

                      {onDeleteAction && act.id && (
                        <button
                          type="button"
                          onClick={() => onDeleteAction(act.id!)}
                          title="Eliminar acción"
                          className="p-1 rounded text-text-muted hover:text-red-400 hover:bg-surface-elevated transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Modal Nueva Acción */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Registrar Acción Estructurada"
        subtitle="Agrega una acción técnica o administrativa para este caso"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          <div>
            <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
              Título de la Acción *
            </label>
            <input
              type="text"
              required
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="ej. Notificación al cliente / Suspensión de cuenta"
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                Tipo de Acción
              </label>
              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              >
                <option value="notificacion_cliente">Notificación a Cliente</option>
                <option value="suspension_servicio">Suspensión de Servicio</option>
                <option value="cambio_credenciales">Cambio de Credenciales</option>
                <option value="limpieza_malware">Limpieza / Desinfección</option>
                <option value="bloqueo_ip_firewall">Bloqueo IP / Firewall</option>
                <option value="solicitud_delist_rbl">Solicitud Delisting RBL</option>
                <option value="respuesta_autoridad">Respuesta a Autoridad</option>
                <option value="orientacion_wipo">Orientación WIPO (Marca)</option>
                <option value="verificacion_bastion">Verificación Bastion/DNS</option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                Estado Inicial
              </label>
              <select
                value={newStatus}
                onChange={(e) => setNewStatus(e.target.value as ActionStatus)}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              >
                {statusOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
              Notas de Resultado o Motivo
            </label>
            <textarea
              rows={3}
              value={newNotes}
              onChange={(e) => setNewNotes(e.target.value)}
              placeholder="Detalles de la ejecución, ticket o comando ejecutado..."
              className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none resize-none"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
            <Button variant="ghost" size="sm" type="button" onClick={() => setIsModalOpen(false)}>
              Cancelar
            </Button>
            <Button variant="primary" size="sm" type="submit">
              Guardar Acción
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

