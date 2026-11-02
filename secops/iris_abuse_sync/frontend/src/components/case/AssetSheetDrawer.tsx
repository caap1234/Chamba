import React from 'react';
import { createPortal } from 'react-dom';
import { X, HardDrive, ExternalLink, ShieldCheck, Ticket, User, Server, Globe } from 'lucide-react';
import { CaseExtension, AdminLinksBundle } from '../../types';

interface AssetSheetDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  extension: CaseExtension;
  adminLinks?: AdminLinksBundle;
  onChange: (field: keyof CaseExtension, value: any) => void;
}

export const AssetSheetDrawer: React.FC<AssetSheetDrawerProps> = ({
  isOpen,
  onClose,
  extension,
  adminLinks,
  onChange,
}) => {
  const isHp = extension.organization === 'HP' || extension.customer_id === 3;
  const orgCode = isHp ? 'HP' : 'NBX';
  const orgName = isHp ? 'Hospedando' : 'NEUBOX';

  const computedActions = adminLinks?.actions || [];
  const hasActions = computedActions.length > 0;

  const getTicketUrl = (ticketId?: string) => {
    if (!ticketId || ticketId.trim() === '') return null;
    return isHp
      ? `https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/supporttickets.php?ticketid=${encodeURIComponent(ticketId.trim())}`
      : `https://helpdesk.neubox.com/#ticket/zoom/${encodeURIComponent(ticketId.trim())}`;
  };

  const getClientUrl = (clientId?: string) => {
    if (!clientId || clientId.trim() === '') return null;
    return isHp
      ? `https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/clientssummary.php?userid=${encodeURIComponent(clientId.trim())}`
      : `https://clientes.neubox.com/NBX_4dmin/clientssummary.php?userid=${encodeURIComponent(clientId.trim())}`;
  };

  const getServiceUrl = (clientId?: string, serviceId?: string) => {
    if (!clientId || !serviceId || clientId.trim() === '' || serviceId.trim() === '') return null;
    return isHp
      ? `https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/clientsservices.php?userid=${encodeURIComponent(clientId.trim())}&id=${encodeURIComponent(serviceId.trim())}`
      : `https://clientes.neubox.com/NBX_4dmin/clientsservices.php?userid=${encodeURIComponent(clientId.trim())}&id=${encodeURIComponent(serviceId.trim())}`;
  };

  const getDomainUrl = (clientId?: string, domainId?: string) => {
    if (!clientId || !domainId || clientId.trim() === '' || domainId.trim() === '') return null;
    return isHp
      ? `https://www.hospedando.com.mx/paneldeclientes/administracion/hmx50269062uP4/clientsdomains.php?userid=${encodeURIComponent(clientId.trim())}&domainid=${encodeURIComponent(domainId.trim())}`
      : `https://clientes.neubox.com/NBX_4dmin/clientsdomains.php?userid=${encodeURIComponent(clientId.trim())}&domainid=${encodeURIComponent(domainId.trim())}`;
  };

  const abuseTicketLink = getTicketUrl(extension.abuse_ticket_id);
  const holderTicketLink = getTicketUrl(extension.holder_ticket_id);
  const clientLink = getClientUrl(extension.client_id);
  const serviceLink = getServiceUrl(extension.client_id, extension.service_id);
  const domainLink = getDomainUrl(extension.client_id, extension.domain_id);
  const irisLink = `https://iris.tokyo-03.com/case?cid=${extension.iris_case_id}`;

  const drawerContent = (
    <aside
      className={`fixed top-0 right-0 h-screen w-80 md:w-96 bg-[#111C30] border-l border-[#1E293B] shadow-2xl z-50 flex flex-col transition-transform duration-300 ease-in-out ${
        isOpen ? 'translate-x-0' : 'translate-x-full pointer-events-none'
      }`}
    >
      <div className="px-5 py-4 border-b border-[#1E293B] flex items-center justify-between bg-surface-elevated/40 shrink-0">
        <div className="flex items-center gap-2">
          <HardDrive className="w-4 h-4 text-blue-500" />
          <div>
            <h3 className="text-sm font-bold text-text-primary">Ficha del Activo & Cliente</h3>
            <span className="text-[10px] font-mono text-text-muted">
              Organización validada: <b className={isHp ? 'text-purple-400' : 'text-blue-400'}>{orgName} ({orgCode})</b>
            </span>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded text-text-muted hover:text-text-primary hover:bg-surface-hover transition-colors cursor-pointer"
          title="Cerrar ficha del activo"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
        {/* Dominio Primario */}
        <div>
          <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
            Dominio / Activo Primario
          </label>
          <input
            type="text"
            value={extension.primary_domain || ''}
            onChange={(e) => onChange('primary_domain', e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
            placeholder="ej. tramitadores.com"
          />
        </div>

        {/* Servidor */}
        <div>
          <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
            Servidor Asociado
          </label>
          <input
            type="text"
            value={extension.server_name || ''}
            onChange={(e) => onChange('server_name', e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
            placeholder="ej. svgt190 / svgp261"
          />
        </div>

        {/* Tickets */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              Ticket Abuso ({isHp ? 'WHMCS' : 'Zammad'})
            </label>
            <input
              type="text"
              value={extension.abuse_ticket_id || ''}
              onChange={(e) => onChange('abuse_ticket_id', e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="ej. 801587"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              Ticket Titular ({isHp ? 'WHMCS' : 'Helpdesk'})
            </label>
            <input
              type="text"
              value={extension.holder_ticket_id || ''}
              onChange={(e) => onChange('holder_ticket_id', e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="ej. 801587"
            />
          </div>
        </div>

        {/* Identificadores Administrativos (Cliente, Servicio, Dominio) */}
        <div className="grid grid-cols-3 gap-2">
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              ID Cliente
            </label>
            <input
              type="text"
              value={extension.client_id || ''}
              onChange={(e) => onChange('client_id', e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="ej. 38533"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              ID Servicio
            </label>
            <input
              type="text"
              value={extension.service_id || ''}
              onChange={(e) => onChange('service_id', e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="ej. 67936"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              ID Dominio
            </label>
            <input
              type="text"
              value={extension.domain_id || ''}
              onChange={(e) => onChange('domain_id', e.target.value)}
              className="w-full px-2.5 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="ej. 14203"
            />
          </div>
        </div>

        {/* IPs */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              IP Hosting
            </label>
            <input
              type="text"
              value={extension.hosting_ip || ''}
              onChange={(e) => onChange('hosting_ip', e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="209.59.180.xx"
            />
          </div>
          <div>
            <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
              IP Reportada
            </label>
            <input
              type="text"
              value={extension.reported_ip || ''}
              onChange={(e) => onChange('reported_ip', e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary font-mono text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
              placeholder="IP en denuncia"
            />
          </div>
        </div>

        {/* Marca Suplantada */}
        <div>
          <label className="block text-[10px] uppercase font-bold text-text-muted mb-1">
            Marca Suplantada (si aplica)
          </label>
          <input
            type="text"
            value={extension.impersonated_brand || ''}
            onChange={(e) => onChange('impersonated_brand', e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg bg-surface-root border border-border-subtle text-text-primary text-xs focus:ring-1 focus:ring-blue-500 focus:outline-none"
            placeholder="ej. CHECK24, BBVA, Banco Azteca"
          />
        </div>

        {/* ACCESOS ADMINISTRATIVOS INTELIGENTES POR ORGANIZACIÓN */}
        <div className="pt-3 border-t border-border-subtle space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold uppercase tracking-wider text-text-primary flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-blue-500" />
              Accesos Administrativos
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-elevated text-text-muted border border-border-subtle">
              {orgCode}
            </span>
          </div>

          {hasActions ? (
            // Render from backend generated admin_links
            computedActions.map((act) => (
              <a
                key={act.key}
                href={act.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
              >
                <div className="flex items-center gap-2 truncate">
                  {act.key.includes('ticket') ? (
                    <Ticket className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                  ) : act.key.includes('client') ? (
                    <User className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : act.key.includes('service') ? (
                    <Server className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  ) : act.key.includes('domain') ? (
                    <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  ) : (
                    <ShieldCheck className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                  )}
                  <span className="truncate group-hover:text-blue-400 font-medium">{act.label}</span>
                </div>
                <div className="flex items-center gap-1 shrink-0 ml-2">
                  <span className="text-[10px] text-text-muted font-mono">{act.system}</span>
                  <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-blue-400" />
                </div>
              </a>
            ))
          ) : (
            // Fallback render with strict valid identifier checks
            <>
              {abuseTicketLink && (
                <a
                  href={abuseTicketLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
                >
                  <div className="flex items-center gap-2 truncate">
                    <Ticket className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                    <span className="truncate group-hover:text-blue-400 font-medium">
                      Abrir Ticket de Abuso #{extension.abuse_ticket_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    <span className="text-[10px] text-text-muted font-mono">
                      {isHp ? 'WHMCS' : 'Zammad'}
                    </span>
                    <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-blue-400" />
                  </div>
                </a>
              )}

              {holderTicketLink && extension.holder_ticket_id !== extension.abuse_ticket_id && (
                <a
                  href={holderTicketLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
                >
                  <div className="flex items-center gap-2 truncate">
                    <Ticket className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                    <span className="truncate group-hover:text-blue-400 font-medium">
                      Abrir Ticket del Titular #{extension.holder_ticket_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    <span className="text-[10px] text-text-muted font-mono">
                      {isHp ? 'WHMCS' : 'Zammad'}
                    </span>
                    <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-blue-400" />
                  </div>
                </a>
              )}

              {clientLink && (
                <a
                  href={clientLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
                >
                  <div className="flex items-center gap-2 truncate">
                    <User className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span className="truncate group-hover:text-emerald-400 font-medium">
                      Ver Perfil del Cliente #{extension.client_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    <span className="text-[10px] text-text-muted font-mono">Panel</span>
                    <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-emerald-400" />
                  </div>
                </a>
              )}

              {serviceLink && (
                <a
                  href={serviceLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
                >
                  <div className="flex items-center gap-2 truncate">
                    <Server className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span className="truncate group-hover:text-amber-400 font-medium">
                      Ver Servicio de Hosting #{extension.service_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    <span className="text-[10px] text-text-muted font-mono">Hosting</span>
                    <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-amber-400" />
                  </div>
                </a>
              )}

              {domainLink && (
                <a
                  href={domainLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
                >
                  <div className="flex items-center gap-2 truncate">
                    <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="truncate group-hover:text-cyan-400 font-medium">
                      Ver Dominio Registrado #{extension.domain_id}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0 ml-2">
                    <span className="text-[10px] text-text-muted font-mono">Dominio</span>
                    <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-cyan-400" />
                  </div>
                </a>
              )}

              <a
                href={irisLink}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface-elevated hover:bg-surface-hover text-text-primary text-xs border border-border-subtle transition-colors group"
              >
                <div className="flex items-center gap-2 truncate">
                  <ShieldCheck className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                  <span className="truncate group-hover:text-indigo-400 font-medium">
                    Ver Expediente Oficial en IRIS #{extension.iris_case_id}
                  </span>
                </div>
                <div className="flex items-center gap-1 shrink-0 ml-2">
                  <span className="text-[10px] text-text-muted font-mono">IRIS</span>
                  <ExternalLink className="w-3 h-3 text-text-muted group-hover:text-indigo-400" />
                </div>
              </a>
            </>
          )}
        </div>
      </div>
    </aside>
  );

  return typeof document !== 'undefined' ? createPortal(drawerContent, document.body) : null;
};
