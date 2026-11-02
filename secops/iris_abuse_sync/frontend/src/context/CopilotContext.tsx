import React, { createContext, useContext, useState } from 'react';
import { api } from '../api/client';

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  text: string;
  timestamp: string;
  proposedChanges?: Record<string, any>;
}

interface CopilotContextType {
  isOpen: boolean;
  setIsOpen: (open: boolean) => void;
  activeContext: {
    type: 'case' | 'alert' | 'general';
    id?: number | string;
    title?: string;
    data?: any;
  };
  setActiveContext: (ctx: { type: 'case' | 'alert' | 'general'; id?: number | string; title?: string; data?: any }) => void;
  messages: CopilotMessage[];
  sendMessage: (text: string) => Promise<void>;
  clearMessages: () => void;
  isThinking: boolean;
}

const CopilotContext = createContext<CopilotContextType | undefined>(undefined);

export const CopilotProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [activeContext, setActiveContext] = useState<{
    type: 'case' | 'alert' | 'general';
    id?: number | string;
    title?: string;
    data?: any;
  }>({ type: 'general' });

  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      id: 'init-1',
      sender: 'assistant',
      text: '¡Hola! Soy tu Copiloto SOC con Google Gemini. Puedo asistirte en redacción, análisis de investigación, correlación de IOCs o sugerencias de acciones estructuradas.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const sendMessage = async (text: string) => {
    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };
    setMessages((prev) => [...prev, userMsg]);
    setIsThinking(true);

    try {
      const res = await api.chatWithCopilot(text, {
        context_type: activeContext.type,
        context_id: activeContext.id,
        context_data: activeContext.data,
      });

      const assistantMsg: CopilotMessage = {
        id: `msg-${Date.now() + 1}`,
        sender: 'assistant',
        text: res.reply || res.text || 'Análisis completado.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        proposedChanges: res.proposed_changes,
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          sender: 'system',
          text: `Error de asistencia: ${err.message || 'No se pudo comunicar con Gemini'}`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  };

  const clearMessages = () => {
    setMessages([]);
  };

  return (
    <CopilotContext.Provider
      value={{
        isOpen,
        setIsOpen,
        activeContext,
        setActiveContext,
        messages,
        sendMessage,
        clearMessages,
        isThinking,
      }}
    >
      {children}
    </CopilotContext.Provider>
  );
};

export const useCopilot = () => {
  const context = useContext(CopilotContext);
  if (!context) {
    throw new Error('useCopilot debe utilizarse dentro de CopilotProvider');
  }
  return context;
};

