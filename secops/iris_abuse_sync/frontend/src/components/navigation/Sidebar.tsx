import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  Bell,
  FolderLock,
  Inbox,
  History,
  RefreshCw,
  BookOpen,
  FileText,
  Network,
  AlertTriangle,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Menu,
  X,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  currentPath: string;
  onNavigate: (path: string) => void;
}

interface NavItem {
  id: string;
  label: string;
  path: string;
  icon: any;
}

interface NavSection {
  id: string;
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    id: 'operacion',
    title: 'Operación',
    items: [
      { id: 'dashboard', label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
      { id: 'alerts', label: 'Centro de Alertas', path: '/alerts', icon: Bell },
      { id: 'cases', label: 'Casos IRIS', path: '/cases', icon: FolderLock },
    ],
  },
  {
    id: 'recepcion',
    title: 'Recepción',
    items: [
      { id: 'ingest', label: 'Ingesta de Reportes', path: '/ingest', icon: Inbox },
      { id: 'ingest-history', label: 'Historial Ingesta', path: '/ingest-history', icon: History },
    ],
  },
  {
    id: 'herramientas',
    title: 'Herramientas SOC',
    items: [
      { id: 'playbooks', label: 'Procedimientos', path: '/playbooks', icon: BookOpen },
      { id: 'reports', label: 'Informes Técnicos', path: '/reports', icon: FileText },
    ],
  },
  {
    id: 'administracion',
    title: 'Administración',
    items: [
      { id: 'connectors', label: 'Conectores & Fuentes', path: '/connectors', icon: Network },
      { id: 'blacklist', label: 'Blacklist Master', path: '/blacklist', icon: AlertTriangle },
      { id: 'settings', label: 'Configuración SOC', path: '/settings', icon: Settings },
    ],
  },
];

export const Sidebar: React.FC<SidebarProps> = ({ currentPath, onNavigate }) => {
  const { user, logout } = useAuth();

  // Persist collapsed sidebar state
  const [collapsed, setCollapsed] = useState(() => {
    return localStorage.getItem('soc_sidebar_collapsed') === 'true';
  });

  const [mobileOpen, setMobileOpen] = useState(false);

  // Strict route matching: prevents partial prefix overlap (e.g. /playbooks activating /settings)
  const isItemActive = (itemPath: string, current: string) => {
    if (itemPath === '/cases') {
      return current === '/cases' || /^\/cases\/\d+/.test(current);
    }
    if (itemPath === '/playbooks') {
      return current === '/playbooks' || current === '/settings?tab=playbooks';
    }
    if (itemPath === '/settings') {
      if (current === '/playbooks' || current === '/settings?tab=playbooks') {
        return false;
      }
      return (
        current === '/settings' ||
        (current.startsWith('/settings?') && !current.includes('tab=playbooks')) ||
        ['/users', '/gemini', '/audit', '/admin'].includes(current.split('?')[0])
      );
    }
    if (itemPath === '/dashboard') {
      return current === '/dashboard' || current === '/';
    }
    return current === itemPath;
  };

  const handleItemClick = (path: string) => {
    onNavigate(path);
    setMobileOpen(false);
  };

  return (
    <>
      {/* Mobile Hamburger Button */}
      <button
        onClick={() => setMobileOpen(!mobileOpen)}
        className="lg:hidden fixed top-3.5 left-4 z-40 p-2 rounded-lg bg-surface-card border border-border-subtle text-text-muted hover:text-text-primary"
        aria-label="Abrir menú de navegación"
      >
        {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>

      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black/60 backdrop-blur-sm z-30 animate-fade-in"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main Sidebar - Stays dark navy #111C30 in both Dark and Light mode */}
      <aside
        className={`fixed lg:static top-0 left-0 h-screen bg-[#111C30] border-r border-[#1E293B] flex flex-col transition-all duration-300 z-30 select-none ${
          mobileOpen ? 'translate-x-0 w-64' : '-translate-x-full lg:translate-x-0'
        } ${collapsed ? 'lg:w-16' : 'lg:w-64'}`}
      >
        {/* Brand Header */}
        <div
          className={`h-16 border-b border-[#1E293B] flex items-center transition-all ${
            collapsed ? 'justify-center px-2' : 'justify-between px-5'
          }`}
        >
          <div
            className="flex items-center gap-3 overflow-hidden cursor-pointer"
            onClick={() => handleItemClick('/dashboard')}
            title="DFIR-IRIS Abuse Sync SOC Platform"
          >
            <div className="p-2 rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-400 shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-bold text-sm tracking-tight text-[#F8FAFC] leading-tight">
                  DFIR-IRIS <span className="text-blue-400">SOC</span>
                </span>
                <span className="text-[10px] text-[#94A3B8] uppercase tracking-widest font-semibold">
                  Abuse Sync v3.1
                </span>
              </div>
            )}
          </div>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className={`hidden lg:flex p-1.5 rounded-lg text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1E293B] transition-colors ${
              collapsed
                ? 'absolute -right-3 top-5 bg-[#162238] border border-[#1E293B] shadow-md z-40'
                : ''
            }`}
            title={collapsed ? 'Expandir menú lateral' : 'Contraer menú lateral'}
            aria-label={collapsed ? 'Expandir menú lateral' : 'Contraer menú lateral'}
          >
            {collapsed ? (
              <ChevronRight className="w-3.5 h-3.5 text-blue-400" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Permanent Navigation Groups (No collapsible dropdowns) */}
        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
          {navSections.map((sec) => (
            <div key={sec.id} className="space-y-1">
              {!collapsed ? (
                <div className="px-3 pt-1 pb-1 text-[10px] font-bold uppercase tracking-wider text-[#64748B]">
                  {sec.title}
                </div>
              ) : (
                <div className="w-full h-px bg-[#1E293B] my-2" />
              )}

              <div className="space-y-1">
                {sec.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = isItemActive(item.path, currentPath);
                  return (
                    <button
                      key={item.id}
                      onClick={() => handleItemClick(item.path)}
                      title={collapsed ? item.label : undefined}
                      className={`w-full flex items-center rounded-lg text-xs font-medium transition-all group ${
                        collapsed ? 'justify-center p-2.5' : 'gap-3 px-3 py-2'
                      } ${
                        isActive
                          ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40 font-semibold shadow-sm'
                          : 'text-[#94A3B8] hover:bg-[#1E293B] hover:text-[#F8FAFC]'
                      }`}
                    >
                      <Icon
                        className={`shrink-0 transition-colors ${
                          collapsed ? 'w-5 h-5' : 'w-4 h-4'
                        } ${
                          isActive
                            ? 'text-blue-400'
                            : 'text-[#64748B] group-hover:text-[#CBD5E1]'
                        }`}
                      />
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* User Footer Profile */}
        <div
          className={`border-t border-[#1E293B] bg-[#0D1524] p-2.5 ${
            collapsed ? 'flex flex-col items-center gap-2' : ''
          }`}
        >
          {!collapsed ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5 overflow-hidden">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-700 to-indigo-600 flex items-center justify-center text-xs font-bold text-white shrink-0 shadow-inner">
                  {user?.full_name ? user.full_name.charAt(0).toUpperCase() : 'A'}
                </div>
                <div className="flex flex-col truncate">
                  <span className="text-xs font-semibold text-[#F8FAFC] truncate">
                    {user?.full_name || 'Christian Aceves'}
                  </span>
                  <span className="text-[10px] text-[#64748B] uppercase tracking-wide font-medium">
                    {user?.role || 'admin'} &bull; {user?.allowed_orgs?.join('/') || 'NBX/HP'}
                  </span>
                </div>
              </div>
              <button
                onClick={() => logout()}
                title="Cerrar sesión"
                className="p-1.5 rounded-lg text-[#94A3B8] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                aria-label="Cerrar sesión"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2">
              <div
                className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-700 to-indigo-600 flex items-center justify-center text-xs font-bold text-white shadow-inner cursor-pointer"
                title={`${user?.full_name || 'Usuario'} (${user?.role || 'admin'})`}
              >
                {user?.full_name ? user.full_name.charAt(0).toUpperCase() : 'A'}
              </div>
              <button
                onClick={() => logout()}
                title="Cerrar sesión"
                className="p-1.5 rounded-lg text-[#94A3B8] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                aria-label="Cerrar sesión"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
