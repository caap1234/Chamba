import React, { useEffect, useState } from 'react';
import { Sparkles, Sun, Moon, Monitor, RefreshCw } from 'lucide-react';
import { useCopilot } from '../../context/CopilotContext';
import { useTheme } from '../../context/ThemeContext';
import { api } from '../../api/client';

interface HeaderBarProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}

export const HeaderBar: React.FC<HeaderBarProps> = ({ title, subtitle, actions }) => {
  const { isOpen, setIsOpen, activeContext } = useCopilot();
  const { theme, setTheme, isDark } = useTheme();
  const [irisStatus, setIrisStatus] = useState<'online' | 'offline' | 'checking'>('checking');
  const [irisHost, setIrisHost] = useState<string>('iris-server');
  const [geminiActive, setGeminiActive] = useState(false);
  const [checking, setChecking] = useState(false);

  const checkStatus = () => {
    setChecking(true);
    api
      .getDashboardSummary()
      .then((res) => {
        const isOk = Boolean(res.iris_connection?.ok || res.iris?.ok || res.iris?.status === 'online');
        setIrisStatus(isOk ? 'online' : 'offline');
        const rawUrl = res.iris_connection?.url || res.iris?.url;
        if (rawUrl) {
          try {
            setIrisHost(new URL(rawUrl).hostname);
          } catch {
            setIrisHost(rawUrl.replace(/^https?:\/\//, '').split('/')[0]);
          }
        }
      })
      .catch(() => setIrisStatus('offline'))
      .finally(() => setChecking(false));

    api
      .getGeminiConfig()
      .then((res) => {
        setGeminiActive(Boolean(res.gemini?.is_enabled && res.gemini?.has_api_key));
      })
      .catch(() => setGeminiActive(false));
  };

  useEffect(() => {
    checkStatus();
  }, []);

  return (
    <header className="h-16 px-6 md:px-8 border-b border-border-subtle bg-surface-card/80 backdrop-blur-md flex items-center justify-between z-20 shrink-0">
      {/* Title & Subtitle */}
      <div>
        <h1 className="text-base md:text-lg font-bold text-text-primary tracking-tight leading-tight">
          {title}
        </h1>
        {subtitle && (
          <p className="text-xs text-text-muted mt-0.5 truncate max-w-xl">
            {subtitle}
          </p>
        )}
      </div>

      {/* Global Controls */}
      <div className="flex items-center gap-3">
        {/* System Health Indicators */}
        <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-elevated/80 border border-border-subtle text-xs">
          <div
            className="flex items-center gap-1.5 cursor-pointer"
            title="Instancia Central DFIR-IRIS (Click para verificar)"
            onClick={checkStatus}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                irisStatus === 'online'
                  ? 'bg-emerald-400 animate-pulse'
                  : irisStatus === 'checking'
                  ? 'bg-amber-400'
                  : 'bg-red-400'
              }`}
            />
            <span className="font-mono text-[11px] text-text-secondary">
              {irisHost}
            </span>
            {checking && <RefreshCw className="w-2.5 h-2.5 animate-spin text-text-muted" />}
          </div>

          <div className="h-3 w-px bg-border-subtle mx-1" />

          <div className="flex items-center gap-1.5" title="Motor de Clasificación y Asistencia">
            <Sparkles className={`w-3.5 h-3.5 ${geminiActive ? 'text-cyan-500' : 'text-text-muted'}`} />
            <span className="text-[11px] text-text-secondary">
              {geminiActive ? 'Gemini AI' : 'Heurísticas'}
            </span>
          </div>
        </div>

        {/* Theme Toggle (Dark / Light / System) */}
        <div className="flex items-center rounded-lg bg-surface-elevated/80 border border-border-subtle p-0.5">
          <button
            onClick={() => setTheme('dark')}
            className={`p-1.5 rounded-md text-xs transition-colors ${
              theme === 'dark'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Modo Oscuro (SOC Dark)"
          >
            <Moon className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setTheme('light')}
            className={`p-1.5 rounded-md text-xs transition-colors ${
              theme === 'light'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-700'
            }`}
            title="Modo Claro Suave (Soft Blue-Slate Light)"
          >
            <Sun className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setTheme('system')}
            className={`p-1.5 rounded-md text-xs transition-colors ${
              theme === 'system'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-300'
            }`}
            title="Preferencia del Sistema"
          >
            <Monitor className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Contextual Page Actions passed from parent */}
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
    </header>
  );
};
