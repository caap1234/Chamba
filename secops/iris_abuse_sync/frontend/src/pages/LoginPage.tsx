import React, { useState } from 'react';
import { ShieldAlert, Lock, User, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Button } from '../components/common/Button';

interface LoginPageProps {
  onLoginSuccess?: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLoginSuccess }) => {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      if (onLoginSuccess) {
        onLoginSuccess();
      }
    } catch (err: any) {
      setError(err.message || 'Usuario o contraseña incorrectos.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface-root flex flex-col justify-center items-center p-4 selection:bg-blue-600/30">
      {/* Background radial gradient accent */}
      <div className="absolute top-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-surface-card border border-border-subtle rounded-2xl shadow-2xl p-8 z-10 relative">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="p-3.5 rounded-2xl bg-gradient-to-tr from-blue-700 to-indigo-600 text-white shadow-lg shadow-blue-900/30 mb-3">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-extrabold text-white tracking-tight">DFIR-IRIS Abuse Sync</h2>
          <div className="flex items-center gap-1.5 mt-1">
            <span className="text-xs text-blue-400 font-bold uppercase tracking-wider">SOC NEUBOX</span>
            <span className="text-slate-500">&bull;</span>
            <span className="text-xs text-purple-400 font-bold uppercase tracking-wider">HOSPEDANDO</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Consola centralizada de respuesta a incidentes y abuso v3.1
          </p>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-lg bg-red-950/60 border border-red-800/80 text-red-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wide">
              Usuario o Correo
            </label>
            <div className="relative flex items-center">
              <User className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 focus:outline-none transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wide">
              Contraseña
            </label>
            <div className="relative flex items-center">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-surface-root border border-border-subtle text-slate-200 text-xs focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 focus:outline-none transition-all"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 text-slate-400 hover:text-slate-200 transition-colors"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <Button
            type="submit"
            variant="primary"
            loading={loading}
            className="w-full py-2.5 mt-2 font-semibold"
          >
            Iniciar Sesión
          </Button>
        </form>

        <div className="mt-6 pt-5 border-t border-border-subtle text-center">
          <p className="text-[11px] text-slate-500">
            Conectado a DFIR-IRIS (<span className="text-slate-400 font-mono">iris.tokyo-03.com</span>)
          </p>
        </div>
      </div>
    </div>
  );
};
