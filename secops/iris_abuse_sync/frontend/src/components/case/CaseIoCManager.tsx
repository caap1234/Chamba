import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Plus,
  Trash2,
  RefreshCw,
  ExternalLink,
  Copy,
  Check,
  Tag,
  Globe,
  Server,
  Hash,
  Link as LinkIcon,
  Mail,
  AlertCircle,
} from 'lucide-react';
import { api } from '../../api/client';
import { Button } from '../common/Button';
import { Badge } from '../common/Badge';
import { ConfirmModal } from '../common/ConfirmModal';

interface IoCItem {
  ioc_id: number;
  ioc_value: string;
  ioc_type: string;
  ioc_description?: string;
  ioc_tags?: string;
  ioc_tlp_id?: number;
  date_added?: string;
}

interface CaseIoCManagerProps {
  caseId: number;
  onRefresh?: () => void;
}

export const CaseIoCManager: React.FC<CaseIoCManagerProps> = ({ caseId, onRefresh }) => {
  const [iocs, setIocs] = useState<IoCItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  // Form State
  const [showAddForm, setShowAddForm] = useState(false);
  const [iocValue, setIocValue] = useState('');
  const [iocType, setIocType] = useState('domain');
  const [iocDescription, setIocDescription] = useState('');
  const [iocTags, setIocTags] = useState('abuse,soc');
  const [submitting, setSubmitting] = useState(false);

  // Delete State
  const [deleteIocId, setDeleteIocId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState(false);

  const loadIocs = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await api.getCaseIocs(caseId);
      if (res.iocs) {
        setIocs(res.iocs);
      }
    } catch (err: any) {
      console.error('Error cargando IoCs desde IRIS:', err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    loadIocs();
  }, [caseId]);

  const handleCopy = (id: number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!iocValue.trim()) return;

    setSubmitting(true);
    try {
      await api.addCaseIoc(caseId, {
        ioc_value: iocValue.trim(),
        ioc_type: iocType,
        ioc_description: iocDescription.trim() || `Indicador ${iocType} registrado desde consola SOC`,
        ioc_tags: iocTags.trim(),
      });
      setIocValue('');
      setIocDescription('');
      setShowAddForm(false);
      await loadIocs(true);
      if (onRefresh) onRefresh();
    } catch (err: any) {
      alert('Error registrando IoC en DFIR-IRIS: ' + (err.message || 'Error de red'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteIoc = async () => {
    if (deleteIocId === null) return;
    setDeleting(true);
    const idToDelete = deleteIocId;
    try {
      // Optimistic delete
      setIocs((prev) => prev.filter((i) => i.ioc_id !== idToDelete));
      await api.deleteCaseIoc(caseId, idToDelete);
      setDeleteIocId(null);
      await loadIocs(true);
      if (onRefresh) onRefresh();
    } catch (err: any) {
      alert('Error eliminando IoC en DFIR-IRIS: ' + (err.message || 'Error de red'));
      await loadIocs(true);
    } finally {
      setDeleting(false);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'domain':
        return <Globe className="w-3.5 h-3.5 text-blue-400" />;
      case 'ip':
      case 'ip-dst':
      case 'ip-src':
        return <Server className="w-3.5 h-3.5 text-cyan-400" />;
      case 'url':
        return <LinkIcon className="w-3.5 h-3.5 text-indigo-400" />;
      case 'md5':
      case 'sha256':
      case 'sha1':
        return <Hash className="w-3.5 h-3.5 text-emerald-400" />;
      case 'email':
      case 'email-src':
        return <Mail className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-surface-card border border-border-subtle shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-indigo-500" />
            <h3 className="text-sm font-bold text-text-primary">Indicadores de Compromiso (IoCs)</h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 font-semibold">
              DFIR-IRIS IOC Module
            </span>
          </div>
          <p className="text-xs text-text-muted mt-0.5">
            Dominios maliciosos, direcciones IP de comando y control (C2), URLs y hashes forenses sincronizados directamente con DFIR-IRIS.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => loadIocs(true)}
            icon={<RefreshCw className="w-3.5 h-3.5" />}
          >
            Actualizar
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowAddForm(!showAddForm)}
            icon={<Plus className="w-3.5 h-3.5" />}
          >
            {showAddForm ? 'Cerrar Formulario' : 'Nuevo IoC'}
          </Button>
        </div>
      </div>

      {/* Add IoC Form */}
      {showAddForm && (
        <form onSubmit={handleAddIoc} className="p-4 rounded-xl bg-surface-card border-2 border-indigo-500/60 shadow-lg space-y-3 animate-in fade-in duration-150">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="text-xs font-bold text-indigo-400 flex items-center gap-1.5">
              <Plus className="w-4 h-4" /> Registrar Nuevo Indicador de Compromiso en DFIR-IRIS
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="text-[11px] font-bold text-text-muted block mb-1">Valor del Indicador *</label>
              <input
                type="text"
                placeholder="ej. lottmail.com, 65.99.205.177, https://phish-site.com/login"
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                className="w-full text-xs font-mono px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500"
                required
              />
            </div>

            <div>
              <label className="text-[11px] font-bold text-text-muted block mb-1">Tipo de IoC</label>
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500 font-semibold"
              >
                <option value="domain">Dominio (FQDN)</option>
                <option value="ip">Dirección IP (v4/v6)</option>
                <option value="url">URL Completa</option>
                <option value="sha256">Hash SHA-256</option>
                <option value="md5">Hash MD5</option>
                <option value="email">Dirección de Correo</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-bold text-text-muted block mb-1">Descripción / Rol Forense</label>
              <input
                type="text"
                placeholder="ej. Dominio alojando formulario falso de Microsoft Office"
                value={iocDescription}
                onChange={(e) => setIocDescription(e.target.value)}
                className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="text-[11px] font-bold text-text-muted block mb-1">Etiquetas (separadas por coma)</label>
              <input
                type="text"
                placeholder="abuse,soc,phishing"
                value={iocTags}
                onChange={(e) => setIocTags(e.target.value)}
                className="w-full text-xs px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-border-subtle">
            <Button variant="secondary" size="sm" type="button" onClick={() => setShowAddForm(false)}>
              Cancelar
            </Button>
            <Button variant="primary" size="sm" type="submit" loading={submitting}>
              Guardar en DFIR-IRIS
            </Button>
          </div>
        </form>
      )}

      {/* IoCs List */}
      <div className="space-y-2">
        {loading && iocs.length === 0 ? (
          <div className="p-8 text-center text-xs text-text-muted">Cargando indicadores desde DFIR-IRIS...</div>
        ) : iocs.length === 0 ? (
          <div className="p-8 text-center rounded-xl bg-surface-card border border-border-subtle text-xs text-text-muted">
            No se han registrado IoCs en este caso. Haz clic en "Nuevo IoC" para agregar el primero.
          </div>
        ) : (
          iocs.map((ioc) => (
            <div
              key={ioc.ioc_id}
              className="p-3.5 rounded-xl bg-surface-card border border-border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-border-default transition-all"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-surface-root border border-border-subtle">
                  {getTypeIcon(ioc.ioc_type)}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-text-primary">{ioc.ioc_value}</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(ioc.ioc_id, ioc.ioc_value)}
                      className="text-text-muted hover:text-text-primary"
                      title="Copiar indicador"
                    >
                      {copiedId === ioc.ioc_id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-root border border-border-subtle text-text-muted uppercase">
                      {ioc.ioc_type}
                    </span>
                  </div>

                  {ioc.ioc_description && (
                    <p className="text-[11px] text-text-secondary mt-0.5">{ioc.ioc_description}</p>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-3 self-end sm:self-center">
                {ioc.ioc_tags && (
                  <div className="flex items-center gap-1">
                    {ioc.ioc_tags.split(',').map((t, i) => (
                      <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-root text-text-muted border border-border-subtle">
                        #{t.trim()}
                      </span>
                    ))}
                  </div>
                )}

                <button
                  type="button"
                  onClick={() => setDeleteIocId(ioc.ioc_id)}
                  title="Eliminar este indicador de DFIR-IRIS"
                  className="p-1 rounded text-text-muted hover:text-red-400 hover:bg-surface-elevated transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Confirmation Modal: Delete IoC */}
      <ConfirmModal
        isOpen={deleteIocId !== null}
        title="Eliminar Indicador de Compromiso (IoC)"
        message="¿Confirmas que deseas eliminar este IoC del caso oficial en DFIR-IRIS? Esta acción retirará el indicador del caso."
        confirmLabel="Eliminar IoC"
        cancelLabel="Cancelar"
        variant="danger"
        loading={deleting}
        onConfirm={handleDeleteIoc}
        onClose={() => setDeleteIocId(null)}
      />
    </div>
  );
};

