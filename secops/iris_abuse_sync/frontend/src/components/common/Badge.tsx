import React from 'react';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'nbx' | 'hp' | 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral' | 'success' | 'gray' | 'green' | 'red' | 'blue' | 'purple';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({ children, variant = 'neutral', className = '' }) => {
  const variantStyles: Record<string, string> = {
    nbx: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-700/60',
    hp: 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-700/60',
    critical: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950/80 dark:text-red-300 dark:border-red-700/60',
    high: 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/80 dark:text-orange-300 dark:border-orange-700/60',
    medium: 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-700/60',
    low: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-700/60',
    success: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-700/60',
    info: 'bg-cyan-100 text-cyan-800 border-cyan-300 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-700/60',
    neutral: 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700',
    gray: 'bg-slate-200 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-700',
    green: 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-700/60',
    red: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950/80 dark:text-red-300 dark:border-red-700/60',
    blue: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950/80 dark:text-blue-300 dark:border-blue-700/60',
    purple: 'bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950/80 dark:text-purple-300 dark:border-purple-700/60',
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border tracking-wide uppercase ${variantStyles[variant]} ${className}`}
    >
      {children}
    </span>
  );
};

export const OrgBadge: React.FC<{ org: 'NBX' | 'HP' | string }> = ({ org }) => {
  const isHp = org?.toUpperCase() === 'HP';
  return (
    <Badge variant={isHp ? 'hp' : 'nbx'}>
      {isHp ? 'HP • Hospedando' : 'NBX • Neubox'}
    </Badge>
  );
};

export const ActionStatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const st = (status || '').toLowerCase();
  switch (st) {
    case 'ejecutada':
    case 'verificada':
      return <Badge variant="success">{st}</Badge>;
    case 'en_ejecucion':
    case 'autorizada':
      return <Badge variant="info">{st}</Badge>;
    case 'pendiente':
    case 'propuesta':
      return <Badge variant="medium">{st}</Badge>;
    case 'cancelada':
      return <Badge variant="critical">{st}</Badge>;
    case 'no_aplicable':
    default:
      return <Badge variant="neutral">{st}</Badge>;
  }
};
