import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Users,
  Sparkles,
  FileText,
  CheckCircle2,
  XCircle,
  Key,
  History,
  RefreshCw,
  Search,
  BookOpen,
  Edit2,
  Plus,
  Save,
  Check,
  AlertTriangle,
  Trash2,
  ArrowUp,
  ArrowDown,
  Database,
} from 'lucide-react';
import { api } from '../api/client';
import { Badge } from '../components/common/Badge';
import { Button } from '../components/common/Button';
import { Modal } from '../components/common/Modal';
import { RetentionCapacityManager } from '../components/case/RetentionCapacityManager';

export const AdminPage: React.FC<{ defaultTab?: 'users' | 'gemini' | 'audit' | 'playbooks' | 'retention' }> = ({ defaultTab = 'users' }) => {
  const getInitialTab = (): 'users' | 'gemini' | 'audit' | 'playbooks' | 'retention' => {
    const params = new URLSearchParams(window.location.search);
    const tabParam = params.get('tab');
    if (tabParam && ['users', 'gemini', 'audit', 'playbooks', 'retention'].includes(tabParam)) {
      return tabParam as any;
    }
    return defaultTab;
  };

  const [activeTab, setActiveTab] = useState<'users' | 'gemini' | 'audit' | 'playbooks' | 'retention'>(getInitialTab);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (defaultTab && !window.location.search.includes('tab=')) {
      setActiveTab(defaultTab);
    }
  }, [defaultTab]);

  const switchTab = (tab: 'users' | 'gemini' | 'audit' | 'playbooks' | 'retention') => {
    setActiveTab(tab);
    const newUrl = `${window.location.pathname}?tab=${tab}`;
    window.history.replaceState({}, '', newUrl);
  };

  // Users state
  const [users, setUsers] = useState<any[]>([]);
  // Gemini state
  const [geminiConfig, setGeminiConfig] = useState<any>({});
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [availableModels, setAvailableModels] = useState<any[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [geminiSaving, setGeminiSaving] = useState(false);
  const [geminiTesting, setGeminiTesting] = useState(false);
  const [geminiTestResult, setGeminiTestResult] = useState<{ ok: boolean; message: string; raw_detail?: string } | null>(null);

  // Audit state
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [auditSearch, setAuditSearch] = useState('');

  // Playbooks state
  const [playbooks, setPlaybooks] = useState<any[]>([]);
  const [categories, setCategories] = useState<any[]>([]);
  const [editingPlaybook, setEditingPlaybook] = useState<any | null>(null);
  const [isCreatingPlaybook, setIsCreatingPlaybook] = useState(false);
  const [playbookForm, setPlaybookForm] = useState<any>({});
  const [savingPlaybook, setSavingPlaybook] = useState(false);

  // User Management state
  const [editingUser, setEditingUser] = useState<any | null>(null);
  const [isCreatingUser, setIsCreatingUser] = useState(false);
  const [userForm, setUserForm] = useState<any>({
    username: '',
    email: '',
    full_name: '',
    password: '',
    role: 'analyst',
    allowed_orgs: ['NBX', 'HP'],
    is_active: true,
  });
  const [userSaving, setUserSaving] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'users') {
        const u = await api.getUsers();
        setUsers(u.users || []);
      } else if (activeTab === 'gemini') {
        const g = await api.getGeminiConfig();
        setGeminiConfig(g.gemini || {});
        // Fetch dynamic model list from backend
        setLoadingModels(true);
        try {
          const m = await api.getGeminiModels();
          if (m.models) {
            setAvailableModels(m.models);
          }
        } catch (e) {
          console.warn('Error fetching dynamic gemini models:', e);
        } finally {
          setLoadingModels(false);
        }
      } else if (activeTab === 'audit') {
        const a = await api.getAuditLogs();
        setAuditLogs(a.logs || []);
      } else if (activeTab === 'playbooks') {
        const c = await api.getAdminCatalogs();
        setPlaybooks(c.playbooks || []);
        setCategories(c.categories || []);
      }
    } catch (err: any) {
      console.error('Error loading admin data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeTab]);

  const handleSaveGemini = async () => {
    setGeminiSaving(true);
    try {
      const payload: any = {
        model: geminiConfig.model || 'gemini-3.5-flash',
        temperature: parseFloat(geminiConfig.temperature) || 0.2,
        max_output_tokens: parseInt(geminiConfig.max_output_tokens) || 4096,
        timeout_seconds: parseInt(geminiConfig.timeout_seconds) || 30,
        is_enabled: geminiConfig.is_enabled ?? true,
      };
      if (apiKeyInput.trim()) {
        payload.api_key = apiKeyInput.trim();
      }
      const res = await api.updateGeminiConfig(payload);
      setGeminiConfig(res.gemini);
      setApiKeyInput('');
      alert('✓ Configuración de Gemini & LLM actualizada exitosamente.');
    } catch (err: any) {
      alert('Error guardando configuración de Gemini: ' + err.message);
    } finally {
      setGeminiSaving(false);
    }
  };

  const handleTestGemini = async () => {
    setGeminiTesting(true);
    setGeminiTestResult(null);
    try {
      const res = await api.testGemini();
      if (res.ok || res.status === 'connected') {
        const preview = res.response_preview ? `\nRespuesta: "${res.response_preview}"` : '';
        setGeminiTestResult({
          ok: true,
          message: `Inferencia exitosa con modelo ${res.model || geminiConfig.model}.${preview}`,
        });
      } else {
        setGeminiTestResult({
          ok: false,
          message: res.message || res.error || 'Fallo de inferencia con Gemini API.',
          raw_detail: res.raw_detail,
        });
      }
    } catch (err: any) {
      setGeminiTestResult({ ok: false, message: err.message || 'Error de comunicación con Gemini API.' });
    } finally {
      setGeminiTesting(false);
    }
  };

  const handleOpenCreateUser = () => {
    setUserError(null);
    setUserForm({
      username: '',
      email: '',
      full_name: '',
      password: '',
      role: 'analyst',
      allowed_orgs: ['NBX', 'HP'],
      is_active: true,
    });
    setIsCreatingUser(true);
  };

  const handleOpenEditUser = (u: any) => {
    setUserError(null);
    setEditingUser(u);
    setUserForm({
      username: u.username,
      email: u.email || '',
      full_name: u.full_name || '',
      password: '',
      role: u.role || 'analyst',
      allowed_orgs: u.allowed_orgs || ['NBX', 'HP'],
      is_active: u.is_active ?? true,
    });
  };

  const handleSaveUser = async () => {
    setUserError(null);
    setUserSaving(true);
    try {
      if (isCreatingUser) {
        if (!userForm.username.trim() || !userForm.email.trim() || !userForm.password.trim()) {
          setUserError('El nombre de usuario, correo y contraseña son obligatorios.');
          setUserSaving(false);
          return;
        }
        await api.createUser(userForm);
        setIsCreatingUser(false);
      } else if (editingUser) {
        const payload: any = {
          email: userForm.email.trim(),
          full_name: userForm.full_name.trim(),
          role: userForm.role,
          allowed_orgs: userForm.allowed_orgs,
          is_active: userForm.is_active,
        };
        if (userForm.password && userForm.password.trim()) {
          payload.password = userForm.password.trim();
        }
        await api.updateUser(editingUser.id, payload);
        setEditingUser(null);
      }
      const u = await api.getUsers();
      setUsers(u.users || []);
    } catch (err: any) {
      setUserError(err.message || 'Error al guardar usuario');
    } finally {
      setUserSaving(false);
    }
  };

  const handleOpenPlaybookModal = (pb: any) => {
    setEditingPlaybook(pb);
    setPlaybookForm({
      code: pb.code,
      name: pb.name,
      category_code: pb.category_code,
      description: pb.description || '',
      is_active: pb.is_active ?? true,
      steps_json: pb.steps || [],
    });
  };

  const handleOpenCreatePlaybookModal = () => {
    setIsCreatingPlaybook(true);
    setPlaybookForm({
      code: '',
      name: '',
      category_code: categories[0]?.code || 'abuse_phishing',
      description: '',
      version: '1.0',
      is_active: true,
      steps_json: [
        {
          order: 1,
          title: 'Verificar resolución DNS y alojamiento en NEUBOX/Hospedando (Bastion / WHOIS)',
          description: 'Consultar servidores autoritativos y confirmar si el activo o IP pertenece a nuestra infraestructura.',
          mandatory: true,
          suggested_action_type: 'verificacion_dns_bastion',
        },
        {
          order: 2,
          title: 'Preservar captura, código fuente y hashes SHA-256 de evidencia',
          description: 'Descargar o capturar el recurso reportado antes de aplicar contención para bitácora forense.',
          mandatory: true,
          suggested_action_type: 'preservacion_evidencia',
        },
        {
          order: 3,
          title: 'Suspender servicio o aislar directorio malicioso',
          description: 'Aplicar contención técnica supervisada respetando las directrices de la organización.',
          mandatory: true,
          suggested_action_type: 'suspension_servicio',
        },
        {
          order: 4,
          title: 'Notificar al titular del servicio mediante ticket oficial',
          description: 'Emitir comunicación formal al cliente especificando hallazgos y requisitos de remediación.',
          mandatory: true,
          suggested_action_type: 'notificacion_cliente',
        },
      ],
    });
  };

  const handleAddStep = () => {
    const steps = [...(playbookForm.steps_json || [])];
    steps.push({
      order: steps.length + 1,
      title: '',
      description: '',
      mandatory: true,
      suggested_action_type: 'playbook_step',
    });
    setPlaybookForm({ ...playbookForm, steps_json: steps });
  };

  const handleRemoveStep = (idx: number) => {
    const steps = [...(playbookForm.steps_json || [])];
    steps.splice(idx, 1);
    const reordered = steps.map((s, i) => ({ ...s, order: i + 1 }));
    setPlaybookForm({ ...playbookForm, steps_json: reordered });
  };

  const handleMoveStep = (idx: number, direction: 'up' | 'down') => {
    const steps = [...(playbookForm.steps_json || [])];
    const targetIdx = direction === 'up' ? idx - 1 : idx + 1;
    if (targetIdx < 0 || targetIdx >= steps.length) return;
    const temp = steps[idx];
    steps[idx] = steps[targetIdx];
    steps[targetIdx] = temp;
    const reordered = steps.map((s, i) => ({ ...s, order: i + 1 }));
    setPlaybookForm({ ...playbookForm, steps_json: reordered });
  };

  const handleSavePlaybook = async () => {
    if (!playbookForm.code || !playbookForm.name) return;
    setSavingPlaybook(true);
    try {
      await api.updatePlaybookTemplate(playbookForm.code, playbookForm);
      setEditingPlaybook(null);
      loadData();
      alert('✓ Playbook actualizado exitosamente.');
    } catch (err: any) {
      alert('Error actualizando playbook: ' + err.message);
    } finally {
      setSavingPlaybook(false);
    }
  };

  const handleSaveNewPlaybook = async () => {
    if (!playbookForm.code || !playbookForm.name || !playbookForm.category_code) {
      alert('Por favor completa código, nombre y categoría del procedimiento.');
      return;
    }
    setSavingPlaybook(true);
    try {
      await api.createPlaybookTemplate(playbookForm);
      setIsCreatingPlaybook(false);
      loadData();
      alert('✓ Nuevo Playbook creado y publicado exitosamente en el catálogo SOC.');
    } catch (err: any) {
      alert('Error creando playbook: ' + err.message);
    } finally {
      setSavingPlaybook(false);
    }
  };

  const filteredLogs = auditLogs.filter(l => {
    if (!auditSearch) return true;
    const q = auditSearch.toLowerCase();
    return (
      (l.action && l.action.toLowerCase().includes(q)) ||
      (l.username && l.username.toLowerCase().includes(q)) ||
      (l.module && l.module.toLowerCase().includes(q)) ||
      (l.ip_address && l.ip_address.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border-subtle pb-4">
        <div>
          <h1 className="text-xl font-bold text-text-primary flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-indigo-500" />
            Configuración SOC & Gobernanza Centralizada
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Administración unificada de identidades RBAC, modelos de IA generativa, catálogos normativos y trazabilidad
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          icon={<RefreshCw className={`w-3.5 h-3.5 mr-1 ${loading ? 'animate-spin' : ''}`} />}
          onClick={loadData}
        >
          Recargar
        </Button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border-subtle gap-2 overflow-x-auto text-xs font-semibold select-none">
        <button
          onClick={() => switchTab('users')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all ${activeTab === 'users'
            ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
            : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
        >
          <Users className="w-4 h-4" />
          <span>Usuarios & Roles</span>
        </button>

        <button
          onClick={() => switchTab('gemini')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all ${activeTab === 'gemini'
            ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
            : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
        >
          <Sparkles className="w-4 h-4" />
          <span>Gemini & LLM</span>
        </button>

        <button
          onClick={() => switchTab('audit')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all ${activeTab === 'audit'
            ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
            : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
        >
          <History className="w-4 h-4" />
          <span>Auditoría & Logs</span>
        </button>

        <button
          onClick={() => switchTab('playbooks')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all ${activeTab === 'playbooks'
            ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
            : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
        >
          <BookOpen className="w-4 h-4" />
          <span>Playbooks & Taxonomía</span>
        </button>

        <button
          onClick={() => switchTab('retention')}
          className={`flex items-center gap-2 px-4 py-2.5 border-b-2 transition-all ${activeTab === 'retention'
            ? 'border-indigo-500 text-indigo-500 font-bold bg-surface-elevated/40'
            : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
        >
          <Database className="w-4 h-4" />
          <span>Retención & Datastore</span>
        </button>
      </div>

      {/* TAB CONTENT */}
      <div>
        {/* USERS TAB */}
        {activeTab === 'users' && (
          <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-text-primary">Directorio de Usuarios y Control de Acceso (RBAC)</h3>
                <p className="text-xs text-text-muted">Roles permitidos: admin, supervisor, analyst, readonly</p>
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={handleOpenCreateUser}
                icon={<Plus className="w-3.5 h-3.5" />}
              >
                Nuevo Usuario
              </Button>
            </div>

            <div className="border border-border-subtle rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-surface-elevated/80 text-text-muted uppercase text-[10px] font-mono border-b border-border-subtle">
                  <tr>
                    <th className="px-4 py-3">Usuario</th>
                    <th className="px-4 py-3">Nombre Completo</th>
                    <th className="px-4 py-3">Correo</th>
                    <th className="px-4 py-3">Rol</th>
                    <th className="px-4 py-3">Organizaciones</th>
                    <th className="px-4 py-3">Estado</th>
                    <th className="px-4 py-3 text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle font-sans">
                  {users.map(u => (
                    <tr key={u.id} className="hover:bg-surface-elevated/30">
                      <td className="px-4 py-3 font-semibold text-text-primary font-mono">{u.username}</td>
                      <td className="px-4 py-3 text-text-primary">{u.full_name || '—'}</td>
                      <td className="px-4 py-3 text-text-muted font-mono">{u.email || '—'}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-100 text-indigo-800 dark:bg-indigo-950/80 dark:text-indigo-300 border border-indigo-300 dark:border-indigo-700/60 uppercase">
                          {u.role}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          {(u.allowed_orgs || []).map((o: string) => (
                            <span key={o} className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-surface-root border border-border-subtle text-text-primary">
                              {o}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          u.is_active
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300'
                            : 'bg-red-100 text-red-800 border border-red-300 dark:bg-red-950 dark:text-red-300'
                        }`}>
                          {u.is_active ? 'Activo' : 'Inactivo'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleOpenEditUser(u)}
                          icon={<Edit2 className="w-3.5 h-3.5" />}
                        >
                          Editar
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* MODAL CREAR / EDITAR USUARIO */}
            {(isCreatingUser || editingUser) && (
              <Modal
                isOpen={true}
                onClose={() => {
                  setIsCreatingUser(false);
                  setEditingUser(null);
                }}
                title={isCreatingUser ? 'Crear Nuevo Usuario SOC' : `Editar Usuario: ${editingUser?.username}`}
                size="md"
              >
                <div className="space-y-4 text-xs">
                  {userError && (
                    <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>{userError}</span>
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                        Nombre de Usuario
                      </label>
                      <input
                        type="text"
                        disabled={!isCreatingUser}
                        value={userForm.username}
                        onChange={e => setUserForm({ ...userForm, username: e.target.value })}
                        placeholder="ej. analista_soc"
                        className={`w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500 ${
                          !isCreatingUser ? 'opacity-60 cursor-not-allowed' : ''
                        }`}
                      />
                    </div>

                    <div>
                      <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                        Nombre Completo
                      </label>
                      <input
                        type="text"
                        value={userForm.full_name}
                        onChange={e => setUserForm({ ...userForm, full_name: e.target.value })}
                        placeholder="ej. Christian Aceves"
                        className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                      Correo Electrónico
                    </label>
                    <input
                      type="email"
                      value={userForm.email}
                      onChange={e => setUserForm({ ...userForm, email: e.target.value })}
                      placeholder="usuario@neubox.net"
                      className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                      {isCreatingUser ? 'Contraseña Inicial (mínimo 8 caracteres)' : 'Nueva Contraseña (dejar en blanco para conservar la actual)'}
                    </label>
                    <input
                      type="password"
                      value={userForm.password}
                      onChange={e => setUserForm({ ...userForm, password: e.target.value })}
                      placeholder={isCreatingUser ? '••••••••' : 'Solo si deseas cambiar la contraseña...'}
                      className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                        Rol Operativo
                      </label>
                      <select
                        value={userForm.role}
                        onChange={e => setUserForm({ ...userForm, role: e.target.value })}
                        className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                      >
                        <option value="analyst">Analyst (Operativo SOC)</option>
                        <option value="supervisor">Supervisor (Aprobación y triage)</option>
                        <option value="admin">Admin (Acceso total)</option>
                        <option value="readonly">Read-Only (Solo lectura)</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                        Estado de la Cuenta
                      </label>
                      <select
                        value={userForm.is_active ? 'true' : 'false'}
                        onChange={e => setUserForm({ ...userForm, is_active: e.target.value === 'true' })}
                        className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                      >
                        <option value="true">Activo (Permite login)</option>
                        <option value="false">Inactivo (Bloqueado)</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                      Organizaciones Permitidas
                    </label>
                    <div className="flex gap-4 pt-1">
                      {['NBX', 'HP'].map(org => {
                        const checked = (userForm.allowed_orgs || []).includes(org);
                        return (
                          <label key={org} className="flex items-center gap-2 cursor-pointer select-none">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={e => {
                                const current = userForm.allowed_orgs || [];
                                if (e.target.checked) {
                                  setUserForm({ ...userForm, allowed_orgs: [...current, org] });
                                } else {
                                  setUserForm({ ...userForm, allowed_orgs: current.filter((o: string) => o !== org) });
                                }
                              }}
                              className="rounded border-border-subtle text-indigo-500 focus:ring-0"
                            />
                            <span className="text-xs font-mono font-bold text-text-primary">
                              {org === 'NBX' ? 'NEUBOX (NBX)' : 'Hospedando (HP)'}
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  </div>

                  <div className="flex justify-end gap-2 pt-4 border-t border-border-subtle">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setIsCreatingUser(false);
                        setEditingUser(null);
                      }}
                    >
                      Cancelar
                    </Button>
                    <Button
                      variant="primary"
                      size="sm"
                      loading={userSaving}
                      onClick={handleSaveUser}
                      icon={<Save className="w-3.5 h-3.5" />}
                    >
                      {isCreatingUser ? 'Crear Usuario' : 'Guardar Cambios'}
                    </Button>
                  </div>
                </div>
              </Modal>
            )}
          </div>
        )}

        {/* GEMINI & LLM TAB (CENTRALIZED) */}
        {activeTab === 'gemini' && (
          <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border-subtle pb-4">
              <div>
                <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  Consola de Gobierno Gemini AI & Copiloto SOC
                </h3>
                <p className="text-xs text-text-muted mt-0.5">
                  Ubicación centralizada para credenciales cifradas (Fernet), límites de tokens y afinación de inferencia
                </p>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  loading={geminiTesting}
                  onClick={handleTestGemini}
                  icon={<Sparkles className="w-3.5 h-3.5 text-cyan-400" />}
                >
                  Probar Inferencia en Vivo
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  loading={geminiSaving}
                  onClick={handleSaveGemini}
                  icon={<Save className="w-3.5 h-3.5" />}
                >
                  Guardar Configuración
                </Button>
              </div>
            </div>

            {geminiTestResult && (
              <div className={`p-4 rounded-xl border flex items-center gap-3 text-xs ${geminiTestResult.ok
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-red-500/10 border-red-500/30 text-red-400'
                }`}>
                {geminiTestResult.ok ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <XCircle className="w-4 h-4 shrink-0" />}
                <span>{geminiTestResult.message}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
              {/* API Key */}
              <div className="space-y-2">
                <label className="block font-bold uppercase text-[11px] text-text-muted">
                  Google Gemini API Key
                </label>
                <input
                  type="password"
                  placeholder={geminiConfig.key_hint ? `Clave activa (${geminiConfig.key_hint}) — Escribe para cambiar` : 'AIzaSy...'}
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
                <span className="text-[10px] text-text-muted block">
                  Almacenada con cifrado Fernet AES-128 en el baúl seguro. Nunca se expone en texto plano.
                </span>
              </div>

              {/* Model Select */}
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <label className="block font-bold uppercase text-[11px] text-text-muted">
                    Modelo de Inferencia Principal
                  </label>
                  {loadingModels && <span className="text-[10px] text-indigo-500 animate-pulse font-medium">Consultando catálogo API...</span>}
                </div>
                <select
                  value={geminiConfig.model || 'gemini-3.5-flash'}
                  onChange={(e) => setGeminiConfig({ ...geminiConfig, model: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500 font-medium"
                >
                  {availableModels.length > 0 ? (
                    availableModels.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.display_name} {m.recommended ? '⭐ (Recomendado / Activo)' : ''}
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="gemini-3.5-flash">Gemini 3.5 Flash ⭐ (Recomendado — Alta velocidad y precisión SOC)</option>
                      <option value="gemini-3.1-flash-lite">Gemini 3.1 Flash-Lite (Triaje masivo de reportes)</option>
                      <option value="gemini-3.8-flash">Gemini 3.8 Flash (Interactions API)</option>
                      <option value="gemini-3.1-pro-preview">Gemini 3.1 Pro Preview (Análisis forense profundo)</option>
                    </>
                  )}
                </select>
                <span className="text-[10px] text-text-muted block">
                  Modelos verificados directamente contra Google Gemini API para tu API Key.
                </span>
              </div>

              {/* Temperature */}
              <div className="space-y-2">
                <div className="flex justify-between">
                  <label className="font-bold uppercase text-[11px] text-text-muted">
                    Temperatura de Muestreo: {geminiConfig.temperature ?? 0.2}
                  </label>
                  <span className="text-[10px] text-text-muted font-mono">0.0 (Determinista) - 1.0 (Creativo)</span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={geminiConfig.temperature ?? 0.2}
                  onChange={(e) => setGeminiConfig({ ...geminiConfig, temperature: parseFloat(e.target.value) })}
                  className="w-full accent-indigo-500"
                />
              </div>

              {/* Max Output Tokens */}
              <div className="space-y-2">
                <label className="block font-bold uppercase text-[11px] text-text-muted">
                  Límite Máximo de Tokens (Max Output)
                </label>
                <input
                  type="number"
                  value={geminiConfig.max_output_tokens ?? 8192}
                  onChange={(e) => setGeminiConfig({ ...geminiConfig, max_output_tokens: parseInt(e.target.value, 10) })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Timeout */}
              <div className="space-y-2">
                <label className="block font-bold uppercase text-[11px] text-text-muted">
                  Timeout de Respuesta (Segundos)
                </label>
                <input
                  type="number"
                  value={geminiConfig.timeout_seconds ?? 30}
                  onChange={(e) => setGeminiConfig({ ...geminiConfig, timeout_seconds: parseInt(e.target.value, 10) })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Enabled Switch */}
              <div className="space-y-2 flex items-center justify-between pt-4">
                <div>
                  <span className="font-bold text-text-primary block text-xs">Habilitar IA Asistencial</span>
                  <span className="text-[10px] text-text-muted">Permite normalización heurística y copiloto en chat</span>
                </div>
                <input
                  type="checkbox"
                  checked={geminiConfig.is_enabled ?? true}
                  onChange={(e) => setGeminiConfig({ ...geminiConfig, is_enabled: e.target.checked })}
                  className="w-4 h-4 rounded text-indigo-600 focus:ring-0 cursor-pointer"
                />
              </div>
            </div>
          </div>
        )}

        {/* AUDIT LOGS TAB */}
        {activeTab === 'audit' && (
          <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-text-primary">Registro de Auditoría & Trazabilidad SOC</h3>
                <p className="text-xs text-text-muted">Eventos inmutables de autenticación, cambios de expediente y operaciones sensibles</p>
              </div>

              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  type="text"
                  placeholder="Filtrar por acción o usuario..."
                  value={auditSearch}
                  onChange={(e) => setAuditSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-xs text-text-primary focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="border border-border-subtle rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-surface-elevated/80 text-text-muted uppercase text-[10px] font-mono border-b border-border-subtle">
                  <tr>
                    <th className="px-4 py-3">Fecha y Hora</th>
                    <th className="px-4 py-3">Usuario</th>
                    <th className="px-4 py-3">Acción</th>
                    <th className="px-4 py-3">Módulo</th>
                    <th className="px-4 py-3">Detalle del Evento</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle font-sans">
                  {filteredLogs.map(log => (
                    <tr key={log.id} className="hover:bg-surface-elevated/30">
                      <td className="px-4 py-2.5 text-text-muted font-mono whitespace-nowrap">
                        {log.timestamp ? new Date(log.timestamp).toLocaleString('es-MX') : '—'}
                      </td>
                      <td className="px-4 py-2.5 text-text-primary font-semibold">{log.username || 'sistema'}</td>
                      <td className="px-4 py-2.5">
                        <span className="px-2 py-0.5 rounded bg-surface-root text-indigo-500 font-mono text-[10px] font-bold border border-border-subtle">
                          {log.action}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-text-secondary">{log.module}</td>
                      <td className="px-4 py-2.5 text-text-secondary truncate max-w-md" title={log.details || ''}>
                        {log.details || '—'}
                      </td>
                    </tr>
                  ))}
                  {filteredLogs.length === 0 && (
                    <tr>
                      <td colSpan={5} className="text-center py-8 text-text-muted">
                        No se encontraron registros de auditoría.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* PLAYBOOKS & TAXONOMY TAB */}
        {activeTab === 'playbooks' && (
          <div className="p-6 rounded-xl bg-surface-card border border-border-subtle shadow-sm space-y-6">
            <div className="flex items-center justify-between border-b border-border-subtle pb-4">
              <div>
                <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-indigo-500" />
                  Catálogo de Playbooks & Procedimientos Operativos
                </h3>
                <p className="text-xs text-text-muted mt-0.5">
                  Protocolos formales de respuesta y contención por taxonomía SOC
                </p>
              </div>
              <Button
                variant="primary"
                size="sm"
                icon={<Plus className="w-3.5 h-3.5 mr-1" />}
                onClick={handleOpenCreatePlaybookModal}
              >
                + Nuevo Playbook
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {playbooks.map(p => (
                <div key={p.id} className="bg-surface-elevated/40 border border-border-subtle rounded-xl p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-bold text-text-primary text-sm">{p.name}</h4>
                      <span className="text-[11px] text-indigo-500 font-mono font-semibold">{p.category_code}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${p.is_active ? 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300' : 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300'
                        }`}>
                        {p.is_active ? 'Activo' : 'Inactivo'}
                      </span>
                      <button
                        onClick={() => handleOpenPlaybookModal(p)}
                        className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-surface-hover transition-colors"
                        title="Editar procedimiento"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                  <p className="text-xs text-text-secondary">{p.description}</p>

                  {p.steps && Array.isArray(p.steps) && (
                    <div className="space-y-1.5 pt-2 border-t border-border-subtle">
                      <span className="text-[10px] font-bold text-text-muted uppercase tracking-wider">
                        Pasos de Contención ({p.steps.length}):
                      </span>
                      <ol className="list-decimal list-inside text-xs text-text-secondary space-y-1">
                        {p.steps.map((s: any, idx: number) => (
                          <li key={idx} className="truncate">
                            <span className="font-medium text-text-primary">{s.title || s.step || s}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* RETENTION TAB */}
        {activeTab === 'retention' && <RetentionCapacityManager />}
      </div>

      {/* Edit Playbook Modal */}
      {editingPlaybook && (
        <Modal
          isOpen={!!editingPlaybook}
          onClose={() => setEditingPlaybook(null)}
          title={`Editar Playbook: ${editingPlaybook.name}`}
          subtitle={`Código canónico: ${editingPlaybook.code}`}
        >
          <div className="space-y-4 text-xs">
            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Nombre del Procedimiento
              </label>
              <input
                type="text"
                value={playbookForm.name || ''}
                onChange={(e) => setPlaybookForm({ ...playbookForm, name: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Descripción Operativa
              </label>
              <textarea
                rows={3}
                value={playbookForm.description || ''}
                onChange={(e) => setPlaybookForm({ ...playbookForm, description: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <label className="font-bold text-text-primary text-xs">Estado Activo</label>
              <input
                type="checkbox"
                checked={playbookForm.is_active ?? true}
                onChange={(e) => setPlaybookForm({ ...playbookForm, is_active: e.target.checked })}
                className="w-4 h-4 rounded text-indigo-600 focus:ring-0 cursor-pointer"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
              <Button variant="secondary" size="sm" onClick={() => setEditingPlaybook(null)}>
                Cancelar
              </Button>
              <Button
                variant="primary"
                size="sm"
                loading={savingPlaybook}
                onClick={handleSavePlaybook}
                icon={<Save className="w-3.5 h-3.5" />}
              >
                Guardar Playbook
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Create Playbook Modal */}
      {isCreatingPlaybook && (
        <Modal
          isOpen={isCreatingPlaybook}
          onClose={() => setIsCreatingPlaybook(false)}
          title="Crear Nuevo Playbook SOC"
          subtitle="Define un procedimiento estructurado de contención y respuesta técnica"
        >
          <div className="space-y-4 text-xs max-h-[75vh] overflow-y-auto pr-1">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Código Canónico <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  placeholder="ej. pb_c2_botnet"
                  value={playbookForm.code || ''}
                  onChange={(e) => setPlaybookForm({ ...playbookForm, code: e.target.value.toLowerCase().trim() })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Taxonomía / Categoría <span className="text-rose-500">*</span>
                </label>
                <select
                  value={playbookForm.category_code || ''}
                  onChange={(e) => setPlaybookForm({ ...playbookForm, category_code: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                >
                  {categories.map((c: any) => (
                    <option key={c.id || c.code} value={c.code}>
                      {c.name} ({c.code})
                    </option>
                  ))}
                  <option value="abuse_general">Abuso General (abuse_general)</option>
                  <option value="abuse_phishing">Phishing (abuse_phishing)</option>
                  <option value="abuse_malware">Malware / C2 (abuse_malware)</option>
                  <option value="abuse_spam">Spam / Outbound (abuse_spam)</option>
                  <option value="blacklist_delist">RBL / Blacklist (blacklist_delist)</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Nombre del Procedimiento <span className="text-rose-500">*</span>
                </label>
                <input
                  type="text"
                  placeholder="ej. Protocolo de Aislamiento y Mitigación de C2 Botnet"
                  value={playbookForm.name || ''}
                  onChange={(e) => setPlaybookForm({ ...playbookForm, name: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                  Versión
                </label>
                <input
                  type="text"
                  placeholder="1.0"
                  value={playbookForm.version || '1.0'}
                  onChange={(e) => setPlaybookForm({ ...playbookForm, version: e.target.value })}
                  className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs font-mono focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase text-text-muted mb-1">
                Descripción Operativa
              </label>
              <textarea
                rows={2}
                placeholder="Objetivo y ámbito de aplicación del procedimiento..."
                value={playbookForm.description || ''}
                onChange={(e) => setPlaybookForm({ ...playbookForm, description: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* Dynamic Step Builder */}
            <div className="space-y-3 pt-3 border-t border-border-subtle">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-bold uppercase text-text-primary flex items-center gap-1.5">
                    Pasos Operativos de Respuesta ({playbookForm.steps_json?.length || 0})
                  </h4>
                  <p className="text-[11px] text-text-muted">
                    Secuencia obligatoria u optativa que el analista debe certificar
                  </p>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<Plus className="w-3 h-3 mr-1" />}
                  onClick={handleAddStep}
                >
                  + Agregar Paso
                </Button>
              </div>

              <div className="space-y-2">
                {playbookForm.steps_json?.map((st: any, idx: number) => (
                  <div key={idx} className="p-3 rounded-lg bg-surface-elevated/60 border border-border-subtle space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-400 font-bold flex items-center justify-center text-[10px]">
                          {idx + 1}
                        </span>
                        <input
                          type="text"
                          placeholder={`Título del paso ${idx + 1}`}
                          value={st.title || ''}
                          onChange={(e) => {
                            const steps = [...playbookForm.steps_json];
                            steps[idx].title = e.target.value;
                            setPlaybookForm({ ...playbookForm, steps_json: steps });
                          }}
                          className="px-2 py-1 rounded bg-surface-root border border-border-subtle text-text-primary text-xs w-64 sm:w-80 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          disabled={idx === 0}
                          onClick={() => handleMoveStep(idx, 'up')}
                          className="p-1 rounded text-text-muted hover:text-text-primary disabled:opacity-30"
                          title="Subir paso"
                        >
                          <ArrowUp className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          disabled={idx === (playbookForm.steps_json?.length || 0) - 1}
                          onClick={() => handleMoveStep(idx, 'down')}
                          className="p-1 rounded text-text-muted hover:text-text-primary disabled:opacity-30"
                          title="Bajar paso"
                        >
                          <ArrowDown className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRemoveStep(idx)}
                          className="p-1 rounded text-rose-500 hover:bg-rose-500/10 ml-1"
                          title="Eliminar paso"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <input
                        type="text"
                        placeholder="Descripción o instrucción detallada para el analista..."
                        value={st.description || ''}
                        onChange={(e) => {
                          const steps = [...playbookForm.steps_json];
                          steps[idx].description = e.target.value;
                          setPlaybookForm({ ...playbookForm, steps_json: steps });
                        }}
                        className="px-2 py-1 rounded bg-surface-root border border-border-subtle text-text-muted text-[11px] focus:outline-none focus:border-indigo-500"
                      />
                      <div className="flex items-center justify-between gap-2">
                        <select
                          value={st.suggested_action_type || 'analisis'}
                          onChange={(e) => {
                            const steps = [...playbookForm.steps_json];
                            steps[idx].suggested_action_type = e.target.value;
                            setPlaybookForm({ ...playbookForm, steps_json: steps });
                          }}
                          className="px-2 py-1 rounded bg-surface-root border border-border-subtle text-text-secondary text-[11px] focus:outline-none focus:border-indigo-500"
                        >
                          <option value="analisis">Análisis e Inspección</option>
                          <option value="verificacion_dns_bastion">Verificación DNS / Bastion</option>
                          <option value="preservacion_evidencia">Preservación de Evidencia</option>
                          <option value="suspension_servicio">Suspensión de Servicio / Aislamiento</option>
                          <option value="bloqueo_ip_firewall">Bloqueo IP / Firewall</option>
                          <option value="notificacion_cliente">Notificación a Titular</option>
                          <option value="delist_request">Solicitud de Delist RBL</option>
                          <option value="resolucion_cierre">Verificación de Cierre</option>
                        </select>
                        <label className="flex items-center gap-1.5 text-[11px] text-text-secondary cursor-pointer">
                          <input
                            type="checkbox"
                            checked={st.mandatory ?? true}
                            onChange={(e) => {
                              const steps = [...playbookForm.steps_json];
                              steps[idx].mandatory = e.target.checked;
                              setPlaybookForm({ ...playbookForm, steps_json: steps });
                            }}
                            className="w-3.5 h-3.5 rounded text-indigo-600 focus:ring-0"
                          />
                          Obligatorio
                        </label>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-border-subtle">
              <label className="flex items-center gap-2 font-bold text-text-primary text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={playbookForm.is_active ?? true}
                  onChange={(e) => setPlaybookForm({ ...playbookForm, is_active: e.target.checked })}
                  className="w-4 h-4 rounded text-indigo-600 focus:ring-0"
                />
                Publicar como Playbook Activo inmediatamente
              </label>

              <div className="flex gap-2">
                <Button variant="secondary" size="sm" onClick={() => setIsCreatingPlaybook(false)}>
                  Cancelar
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  loading={savingPlaybook}
                  onClick={handleSaveNewPlaybook}
                  icon={<Save className="w-3.5 h-3.5" />}
                >
                  Guardar y Publicar
                </Button>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
