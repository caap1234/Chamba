import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import { CopilotProvider } from './context/CopilotContext';
import { Sidebar } from './components/navigation/Sidebar';
import { HeaderBar } from './components/navigation/HeaderBar';
import { FloatingCopilotDrawer } from './components/copilot/FloatingCopilotDrawer';

// Pages
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AlertsPage } from './pages/AlertsPage';
import { CasesPage } from './pages/CasesPage';
import { CaseWorkspacePage } from './pages/CaseWorkspacePage';
import { IngestPage } from './pages/IngestPage';
import { IngestHistoryPage } from './pages/IngestHistoryPage';
import { ConnectorsPage } from './pages/ConnectorsPage';
import { BlacklistMasterPage } from './pages/BlacklistMasterPage';
import { ReportsPage } from './pages/ReportsPage';
import { AdminPage } from './pages/AdminPage';

const MainLayout: React.FC = () => {
  const { user, loading } = useAuth();
  const [currentPath, setCurrentPath] = useState<string>(() => window.location.pathname || '/dashboard');

  useEffect(() => {
    const handlePopState = () => {
      setCurrentPath(window.location.pathname || '/dashboard');
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigate = (path: string) => {
    window.history.pushState({}, '', path);
    setCurrentPath(path);
  };

  if (loading) {
    return (
      <div className="h-screen w-screen bg-surface-root flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-text-muted text-sm font-mono">Iniciando DFIR-IRIS SOC Platform v3.1...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onLoginSuccess={() => navigate('/dashboard')} />;
  }

  // Parse path for cases/:id
  const caseMatch = currentPath.match(/^\/cases\/(\d+)/);
  const selectedCaseId = caseMatch ? parseInt(caseMatch[1], 10) : null;

  // Compute Page Title & Subtitle
  let title = 'Consola SOC';
  let subtitle = 'Plataforma Centralizada de Gestión de Abuso';

  if (currentPath === '/dashboard' || currentPath === '/') {
    title = 'Centro de Mando SOC';
    subtitle = 'Métricas operativas de respuesta a incidentes de abuso NEUBOX y Hospedando';
  } else if (currentPath === '/alerts') {
    title = 'Centro de Triage de Alertas';
    subtitle = 'Recepción, descarte, priorización y escalamiento hacia casos DFIR-IRIS';
  } else if (currentPath === '/cases') {
    title = 'Expedientes de Casos Activos';
    subtitle = 'Gestión estructurada, notas IRIS, evidencias y ciclo de vida de incidentes';
  } else if (selectedCaseId) {
    title = `Expediente de Caso #${selectedCaseId}`;
    subtitle = 'Investigación técnica, bitácora forense, contención y reporte ejecutivo';
  } else if (currentPath === '/ingest') {
    title = 'Recepción & Ingesta Multicanal';
    subtitle = 'Normalización asistida por IA para Zammad, WHMCS, IMAP, PDF, EML y texto';
  } else if (currentPath === '/ingest-history') {
    title = 'Historial de Ingesta & Trazabilidad';
    subtitle = 'Auditoría cronológica de eventos, hashes SHA-256 y reprocesamiento';
  } else if (currentPath === '/playbooks' || currentPath === '/settings?tab=playbooks') {
    title = 'Procedimientos & Playbooks SOC';
    subtitle = 'Protocolos de mitigación, contención y respuesta supervisada por categoría';
  } else if (currentPath === '/reports') {
    title = 'Informes Técnicos & Dictámenes SOC';
    subtitle = 'Generación automatizada de reportes vectoriales en PDF con membrete institucional';
  } else if (currentPath === '/connectors') {
    title = 'Conectores & Fuentes Externas';
    subtitle = 'Integraciones activas de polling, webhooks y credenciales cifradas';
  } else if (currentPath === '/blacklist') {
    title = 'Blacklist Master & Reputación RBL';
    subtitle = 'Diagnóstico en vivo contra proveedores RBL, seguimiento de delisting y reputación';
  } else if (['/settings', '/admin', '/users', '/gemini', '/audit'].includes(currentPath.split('?')[0])) {
    title = 'Configuración SOC & Gobernanza Centralizada';
    subtitle = 'Control de acceso basado en roles, modelos Gemini AI, auditoría y taxonomía';
  }

  // Determine initial admin tab from path
  const getAdminTab = (): 'users' | 'gemini' | 'audit' | 'playbooks' => {
    const p = currentPath.split('?')[0];
    if (p === '/gemini') return 'gemini';
    if (p === '/audit') return 'audit';
    if (p === '/playbooks') return 'playbooks';
    const params = new URLSearchParams(window.location.search);
    const tab = params.get('tab');
    if (tab && ['users', 'gemini', 'audit', 'playbooks'].includes(tab)) {
      return tab as any;
    }
    return 'users';
  };

  return (
    <div className="h-screen w-screen bg-surface-root flex overflow-hidden text-text-primary font-sans antialiased">
      {/* Primary Sidebar */}
      <Sidebar currentPath={currentPath} onNavigate={navigate} />

      {/* Main App Canvas */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <HeaderBar title={title} subtitle={subtitle} />

        <main className="flex-1 overflow-y-auto p-6 md:p-8 bg-surface-root">
          {selectedCaseId ? (
            <CaseWorkspacePage caseId={selectedCaseId} onNavigate={navigate} onBack={() => navigate('/cases')} />
          ) : currentPath === '/alerts' ? (
            <AlertsPage onNavigate={navigate} onOpenCase={(cId: number) => navigate(`/cases/${cId}`)} />
          ) : currentPath === '/cases' ? (
            <CasesPage onNavigate={navigate} onOpenCase={(cId: number) => navigate(`/cases/${cId}`)} />
          ) : currentPath === '/ingest' ? (
            <IngestPage onNavigate={navigate} onOpenCase={(cId: number) => navigate(`/cases/${cId}`)} />
          ) : currentPath === '/ingest-history' ? (
            <IngestHistoryPage onNavigate={navigate} onOpenCase={(cId: number) => navigate(`/cases/${cId}`)} />
          ) : currentPath === '/playbooks' ? (
            <AdminPage defaultTab="playbooks" />
          ) : currentPath === '/reports' ? (
            <ReportsPage onNavigate={navigate} onOpenCase={(cId: number) => navigate(`/cases/${cId}`)} />
          ) : currentPath === '/blacklist' ? (
            <BlacklistMasterPage />
          ) : currentPath === '/connectors' ? (
            <ConnectorsPage onNavigate={navigate} />
          ) : ['/settings', '/admin', '/users', '/gemini', '/audit'].includes(currentPath.split('?')[0]) ? (
            <AdminPage defaultTab={getAdminTab()} />
          ) : (
            <DashboardPage onNavigate={navigate} />
          )}
        </main>
      </div>

      {/* Global Floating AI Copilot Drawer */}
      <FloatingCopilotDrawer />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <CopilotProvider>
          <MainLayout />
        </CopilotProvider>
      </AuthProvider>
    </ThemeProvider>
  );
};
