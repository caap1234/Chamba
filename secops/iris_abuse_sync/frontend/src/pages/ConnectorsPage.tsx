import React, { useState, useEffect } from 'react';
import { 
  Network, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  Play, 
  Settings2, 
  Clock, 
  ShieldCheck, 
  AlertCircle,
  Eye,
  EyeOff,
  Server,
  Mail,
  Lock,
  MessageSquare,
  Sparkles,
  Database,
  Plus
} from 'lucide-react';
import { api } from '../api/client';
import { Badge, OrgBadge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Modal } from '../components/common/Modal';

interface ConnectorsPageProps {
  onNavigate?: (path: string) => void;
}

export const ConnectorsPage: React.FC<ConnectorsPageProps> = ({ onNavigate }) => {
  const [connectors, setConnectors] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [testingId, setTestingId] = useState<number | null>(null);
  const [testResult, setTestResult] = useState<Record<number, { success: boolean; message: string }>>({});
  
  // Edit modal
  const [editingConnector, setEditingConnector] = useState<any | null>(null);
  const [editForm, setEditForm] = useState<Record<string, any>>({});
  const [secretInput, setSecretInput] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [saving, setSaving] = useState(false);

  const fetchConnectors = async () => {
    setLoading(true);
    try {
      const data = await api.getConnectors();
      setConnectors(data.connectors || []);
    } catch (err: any) {
      console.error('Error fetching connectors:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConnectors();
  }, []);

  const handleTest = async (id: number) => {
    setTestingId(id);
    try {
      const res = await api.testConnector(id);
      const isSuccess = Boolean(res.ok || res.success);
      setTestResult(prev => ({
        ...prev,
        [id]: { success: isSuccess, message: res.message || (isSuccess ? 'Conexión exitosa' : 'Fallo de conexión') }
      }));
    } catch (err: any) {
      setTestResult(prev => ({
        ...prev,
        [id]: { success: false, message: err.message || 'Error comunicando con el conector' }
      }));
    } finally {
      setTestingId(null);
    }
  };

  const handleEdit = (conn: any) => {
    setEditingConnector(conn);
    setEditForm({
      name: conn.name,
      is_enabled: conn.is_enabled,
      organization: conn.organization || 'ALL',
      poll_interval_seconds: conn.poll_interval_seconds || 300,
      settings_json: { ...(conn.settings_json || {}) },
    });
    setSecretInput('');
    setShowSecret(false);
  };

  const handleSaveEdit = async () => {
    if (!editingConnector) return;
    setSaving(true);
    try {
      const payload: any = {
        name: editForm.name,
        is_enabled: editForm.is_enabled,
        organization: editForm.organization,
        poll_interval_seconds: editForm.poll_interval_seconds,
        settings_json: editForm.settings_json,
      };
      if (secretInput.trim()) {
        payload.secret_value = secretInput.trim();
      }

      await api.updateConnector(editingConnector.id, payload);
      setEditingConnector(null);
      await fetchConnectors();
      alert('✓ Configuración del conector guardada con éxito.');
    } catch (err: any) {
      alert('Error guardando conector: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  const getConnectorIcon = (type: string) => {
    switch (type) {
      case 'zammad':
        return <Server className="w-5 h-5 text-blue-400" />;
      case 'whmcs':
        return <Database className="w-5 h-5 text-indigo-400" />;
      case 'imap':
        return <Mail className="w-5 h-5 text-emerald-400" />;
      case 'slack':
        return <MessageSquare className="w-5 h-5 text-purple-400" />;
      case 'blacklist_master':
        return <ShieldCheck className="w-5 h-5 text-rose-400" />;
      case 'gemini':
        return <Sparkles className="w-5 h-5 text-cyan-400" />;
      default:
        return <Network className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 dark:text-white light:text-slate-900 tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-indigo-400" />
            Conectores de Ingesta & Canales SOC
          </h2>
          <p className="text-xs text-slate-400 dark:text-slate-400 light:text-slate-600 mt-0.5">
            Gestión de fuentes automatizadas: Zammad, WHMCS, IMAP, Slack, Blacklist Master y Google Gemini
          </p>
        </div>
        <Button 
          variant="secondary" 
          size="sm"
          icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />}
          onClick={fetchConnectors}
        >
          Actualizar Estado
        </Button>
      </div>

      {/* Grid of Connectors */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {connectors.map(c => {
          const test = testResult[c.id];
          return (
            <div 
              key={c.id} 
              className="bg-surface-card border border-border-subtle rounded-2xl p-5 flex flex-col justify-between hover:border-border-light transition shadow-sm"
            >
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-surface-elevated border border-border-subtle flex items-center justify-center shrink-0">
                      {getConnectorIcon(c.connector_type)}
                    </div>
                    <div>
                      <h3 className="font-semibold text-slate-100 dark:text-white light:text-slate-900 text-sm leading-tight">
                        {c.name}
                      </h3>
                      <span className="text-[11px] text-slate-400 font-mono">{c.connector_type}</span>
                    </div>
                  </div>
                  <Badge variant={c.is_enabled ? 'success' : 'neutral'}>
                    {c.is_enabled ? 'Activo' : 'Inactivo'}
                  </Badge>
                </div>

                <div className="space-y-2 text-xs py-3 border-y border-border-subtle/80 my-3">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-500" /> Intervalo Polling:
                    </span>
                    <span className="font-mono text-slate-200">{c.poll_interval_seconds}s</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400 flex items-center gap-1.5">
                      <ShieldCheck className="w-3.5 h-3.5 text-slate-500" /> Organización:
                    </span>
                    <span className="font-mono text-slate-200">
                      <OrgBadge org={c.organization || 'ALL'} />
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Última Sincronización:</span>
                    <span className="font-mono text-slate-300">
                      {c.last_sync_at ? new Date(c.last_sync_at).toLocaleTimeString() : 'Pendiente'}
                    </span>
                  </div>
                </div>

                {/* Status or test message */}
                {test && (
                  <div className={`p-2.5 rounded-lg text-xs flex items-center gap-2 mb-3 ${
                    test.success ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-300 border border-rose-500/20'
                  }`}>
                    {test.success ? <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" /> : <XCircle className="w-4 h-4 shrink-0 text-rose-400" />}
                    <span className="truncate">{test.message}</span>
                  </div>
                )}
                {c.last_error && !test && (
                  <div className="p-2.5 rounded-lg text-xs flex items-center gap-2 mb-3 bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    <AlertCircle className="w-4 h-4 shrink-0 text-amber-400" />
                    <span className="truncate">{c.last_error}</span>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 pt-2 border-t border-border-subtle/80">
                <Button 
                  size="sm" 
                  variant="secondary" 
                  className="flex-1"
                  loading={testingId === c.id}
                  icon={<Play className="w-3.5 h-3.5 text-emerald-400" />}
                  onClick={() => handleTest(c.id)}
                >
                  Probar Enlace
                </Button>
                {c.connector_type === 'gemini' ? (
                  <Button 
                    size="sm" 
                    variant="ghost"
                    icon={<Sparkles className="w-3.5 h-3.5 text-cyan-400" />}
                    onClick={() => {
                      if (onNavigate) onNavigate('/settings?tab=gemini');
                      else {
                        window.history.pushState({}, '', '/settings?tab=gemini');
                        window.dispatchEvent(new PopStateEvent('popstate'));
                      }
                    }}
                  >
                    Ajustes LLM
                  </Button>
                ) : (
                  <Button 
                    size="sm" 
                    variant="ghost"
                    icon={<Settings2 className="w-3.5 h-3.5" />}
                    onClick={() => handleEdit(c)}
                  >
                    Configurar
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Dedicated Edit Modal per Connector Type */}
      {editingConnector && (
        <Modal 
          isOpen={!!editingConnector} 
          onClose={() => setEditingConnector(null)}
          title={`Configuración: ${editingConnector.name}`}
          subtitle={`Tipo de integración: ${editingConnector.connector_type.toUpperCase()}`}
          size="lg"
        >
          <div className="space-y-4 text-xs text-slate-300">
            {/* General parameters */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block font-semibold text-slate-400 mb-1">Nombre Descriptivo</label>
                <input 
                  type="text" 
                  className="w-full bg-surface-root border border-border-subtle rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500"
                  value={editForm.name || ''}
                  onChange={e => setEditForm({ ...editForm, name: e.target.value })}
                />
              </div>

              <div>
                <label className="block font-semibold text-slate-400 mb-1">Intervalo de Polling (segundos)</label>
                <input 
                  type="number" 
                  className="w-full bg-surface-root border border-border-subtle rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                  value={editForm.poll_interval_seconds || 300}
                  onChange={e => setEditForm({ ...editForm, poll_interval_seconds: parseInt(e.target.value) || 60 })}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block font-semibold text-slate-400 mb-1">Organización Asignada</label>
                <select
                  value={editForm.organization || 'ALL'}
                  onChange={e => setEditForm({ ...editForm, organization: e.target.value })}
                  className="w-full bg-surface-root border border-border-subtle rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="ALL">ALL (Ambas organizaciones)</option>
                  <option value="NBX">NBX (Neubox)</option>
                  <option value="HP">HP (Hospedando)</option>
                </select>
              </div>

              <div className="flex items-center gap-2 pt-6">
                <input 
                  type="checkbox" 
                  id="conn-enabled"
                  checked={Boolean(editForm.is_enabled)}
                  onChange={e => setEditForm({ ...editForm, is_enabled: e.target.checked })}
                  className="rounded border-slate-700 text-blue-600 focus:ring-0 bg-surface-root"
                />
                <label htmlFor="conn-enabled" className="text-slate-200 font-semibold cursor-pointer">
                  Habilitar conector en segundo plano
                </label>
              </div>
            </div>

            {/* Specialized Form depending on connector type */}
            <div className="pt-2 border-t border-border-subtle space-y-3">
              <span className="font-bold text-[11px] uppercase tracking-wider text-slate-400 block">
                Parámetros Específicos del Canal
              </span>

              {/* ZAMMAD */}
              {editingConnector.connector_type === 'zammad' && (
                <div className="space-y-3 bg-surface-root p-3 rounded-xl border border-border-subtle">
                  <div>
                    <label className="block text-slate-400 mb-1">URL Base de Zammad Helpdesk</label>
                    <input 
                      type="text"
                      value={editForm.settings_json?.base_url || 'https://helpdesk.neubox.com'}
                      onChange={e => setEditForm({
                        ...editForm,
                        settings_json: { ...editForm.settings_json, base_url: e.target.value }
                      })}
                      className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-400 mb-1">Nombre del Grupo</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.group_name || 'Soporte 2do Nivel'}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, group_name: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Filtro de Consulta (Query)</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.query_filter || 'group_id:14'}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, query_filter: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* WHMCS */}
              {editingConnector.connector_type === 'whmcs' && (
                <div className="space-y-3 bg-surface-root p-3 rounded-xl border border-border-subtle">
                  <div>
                    <label className="block text-slate-400 mb-1">Endpoint API WHMCS</label>
                    <input 
                      type="text"
                      value={editForm.settings_json?.base_url || 'https://clientes.neubox.com/includes/api.php'}
                      onChange={e => setEditForm({
                        ...editForm,
                        settings_json: { ...editForm.settings_json, base_url: e.target.value }
                      })}
                      className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-400 mb-1">Identificador API (API Identifier)</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.api_identifier || ''}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, api_identifier: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Departamento</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.department || 'Abuse / Seguridad'}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, department: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 text-slate-200"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* IMAP */}
              {editingConnector.connector_type === 'imap' && (
                <div className="space-y-3 bg-surface-root p-3 rounded-xl border border-border-subtle">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="col-span-2">
                      <label className="block text-slate-400 mb-1">Servidor IMAP (Host)</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.host || 'mail.neubox.com'}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, host: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Puerto (TLS)</label>
                      <input 
                        type="number"
                        value={editForm.settings_json?.port || 993}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, port: parseInt(e.target.value) || 993 }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-400 mb-1">Buzón de Correo (Usuario)</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.user || 'abuse@neubox.com'}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, user: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Carpeta Origen</label>
                      <input 
                        type="text"
                        value={editForm.settings_json?.folder || 'INBOX'}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, folder: e.target.value }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* SLACK */}
              {editingConnector.connector_type === 'slack' && (
                <div className="space-y-3 bg-surface-root p-3 rounded-xl border border-border-subtle">
                  <div>
                    <label className="block text-slate-400 mb-1">Canales Monitoreados (Separados por coma)</label>
                    <input 
                      type="text"
                      value={editForm.settings_json?.allowed_channels || '#soc-abuse, #alertas-seguridad'}
                      onChange={e => setEditForm({
                        ...editForm,
                        settings_json: { ...editForm.settings_json, allowed_channels: e.target.value }
                      })}
                      className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                    />
                  </div>
                  <p className="text-[11px] text-slate-500">
                    Endpoint receptor de webhook: <code className="text-cyan-400">/api/v1/ingest/webhooks/slack</code> (Valida HMAC SHA-256 con el Signing Secret).
                  </p>
                </div>
              )}

              {/* BLACKLIST MASTER */}
              {editingConnector.connector_type === 'blacklist_master' && (
                <div className="space-y-3 bg-surface-root p-3 rounded-xl border border-border-subtle">
                  <div>
                    <label className="block text-slate-400 mb-1">URL de API o Feed de Listas Negras</label>
                    <input 
                      type="text"
                      value={editForm.settings_json?.feed_url || 'https://monitor.neubox.com/rbl/api/status'}
                      onChange={e => setEditForm({
                        ...editForm,
                        settings_json: { ...editForm.settings_json, feed_url: e.target.value }
                      })}
                      className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-400 mb-1">Ventana de Deduplicación (Horas)</label>
                      <input 
                        type="number"
                        value={editForm.settings_json?.dedup_hours || 48}
                        onChange={e => setEditForm({
                          ...editForm,
                          settings_json: { ...editForm.settings_json, dedup_hours: parseInt(e.target.value) || 24 }
                        })}
                        className="w-full bg-surface-card border border-border-subtle rounded px-3 py-1.5 font-mono text-slate-200"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Secret Token / Password Input (Masked) */}
              <div className="pt-2">
                <div className="flex items-center justify-between mb-1">
                  <label className="text-slate-400 font-semibold flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-slate-400" />
                    <span>Clave Secreta / Token de Acceso (Bóveda Cifrada)</span>
                  </label>
                  <button 
                    type="button"
                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                    onClick={() => setShowSecret(!showSecret)}
                  >
                    {showSecret ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    {showSecret ? 'Ocultar' : 'Mostrar'}
                  </button>
                </div>
                <input 
                  type={showSecret ? 'text' : 'password'}
                  placeholder="Dejar en blanco para mantener la clave actual o escribir nueva para sustituir..."
                  value={secretInput}
                  onChange={e => setSecretInput(e.target.value)}
                  className="w-full bg-surface-root border border-border-subtle rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                />
                <span className="text-[10px] text-slate-500 mt-1 block">
                  Por seguridad, las claves nunca se muestran en texto plano. Si ingresas un valor, se cifrará con Fernet y clave maestra.
                </span>
              </div>
            </div>

            {/* Modal Actions */}
            <div className="flex justify-end gap-3 pt-4 border-t border-border-subtle">
              <Button variant="ghost" size="sm" onClick={() => setEditingConnector(null)}>
                Cancelar
              </Button>
              <Button variant="primary" size="sm" loading={saving} onClick={handleSaveEdit}>
                Guardar Conector
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
