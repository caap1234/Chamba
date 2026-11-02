import React, { useState, useEffect } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import { Markdown } from 'tiptap-markdown';
import { Table, TableRow, TableCell, TableHeader } from '@tiptap/extension-table';
import { Link } from '@tiptap/extension-link';
import {
  Bold,
  Italic,
  Code,
  Heading1,
  Heading2,
  List,
  ListOrdered,
  Table as TableIcon,
  Terminal,
  Quote,
  Minus,
  Undo2,
  Redo2,
  Copy,
  Check,
  FileCode,
  Sparkles,
} from 'lucide-react';

export const renderMarkdownToHtml = (md: string): { __html: string } => {
  if (!md || !md.trim()) {
    return { __html: '<p class="text-text-muted italic text-xs">Sin contenido documentado.</p>' };
  }

  // Normalizar saltos de línea (\r\n -> \n)
  let text = md.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Preprocesar bloques ``` si tienen espacio antes o después de la etiqueta de lenguaje
  text = text.replace(/```[ \t]+([a-zA-Z0-9_-]+)/g, '```$1');
  text = text.replace(/```([a-zA-Z0-9_-]+)[ \t]+([^\n`])/g, '```$1\n$2');

  // 1. Extraer y proteger bloques de código multilínea (```lang ... ```)
  const codeBlocks: string[] = [];
  text = text.replace(/(?:^|\n)[ \t]*```([a-zA-Z0-9_-]*)[ \t]*\n([\s\S]*?)\n?[ \t]*```[ \t]*(?=\n|$)/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    const escaped = code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    const langLabel = (lang || 'TERMINAL / LOG').toUpperCase();
    const lineCount = code.trim().split('\n').filter(Boolean).length || 1;

    codeBlocks.push(
      `<div class="my-3 rounded-xl overflow-hidden border border-border-subtle bg-[#0B132B] dark:bg-[#070D1B] shadow-sm">` +
      `<div class="px-3.5 py-1.5 bg-surface-elevated/90 border-b border-border-subtle text-[10px] font-mono font-bold text-blue-400 flex items-center justify-between">` +
      `<div class="flex items-center gap-1.5">` +
      `<span class="w-2 h-2 rounded-full bg-emerald-400"></span>` +
      `<span>${langLabel}</span>` +
      `</div>` +
      `<span class="text-text-muted text-[9px] font-mono">${lineCount} LÍNEAS</span>` +
      `</div>` +
      `<pre class="p-3 overflow-x-auto text-xs font-mono leading-relaxed text-emerald-400 dark:text-emerald-300"><code>${escaped}</code></pre>` +
      `</div>`
    );
    return `\n\n%%CODEBLOCK_${idx}%%\n\n`;
  });

  // Fallback para cualquier otro bloque ``` no capturado por el patrón anterior
  text = text.replace(/```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    const escaped = code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    const langLabel = (lang || 'TERMINAL / LOG').toUpperCase();
    const lineCount = code.trim().split('\n').filter(Boolean).length || 1;

    codeBlocks.push(
      `<div class="my-3 rounded-xl overflow-hidden border border-border-subtle bg-[#0B132B] dark:bg-[#070D1B] shadow-sm">` +
      `<div class="px-3.5 py-1.5 bg-surface-elevated/90 border-b border-border-subtle text-[10px] font-mono font-bold text-blue-400 flex items-center justify-between">` +
      `<div class="flex items-center gap-1.5">` +
      `<span class="w-2 h-2 rounded-full bg-emerald-400"></span>` +
      `<span>${langLabel}</span>` +
      `</div>` +
      `<span class="text-text-muted text-[9px] font-mono">${lineCount} LÍNEAS</span>` +
      `</div>` +
      `<pre class="p-3 overflow-x-auto text-xs font-mono leading-relaxed text-emerald-400 dark:text-emerald-300"><code>${escaped}</code></pre>` +
      `</div>`
    );
    return `\n\n%%CODEBLOCK_${idx}%%\n\n`;
  });

  // 2. Líneas horizontales separadoras (--- o ***)
  text = text.replace(/^[ \t]*(?:---|\*\*\*|___)[ \t]*$/gm, '<hr class="my-3 border-t border-border-subtle" />');

  // 3. Normalizar filas de tablas unidas (| ... | | ... |) insertando salto de línea
  text = text.replace(/\|\s*\|\s*/g, '|\n|');

  // Parser robusto de Tablas Markdown GFM (| Encabezado 1 | Encabezado 2 |)
  text = text.replace(/((?:^[ \t]*\|.*\|[ \t]*\n)+(?:^[ \t]*\|.*\|[ \t]*))/gm, (tableMatch) => {
    const lines = tableMatch.trim().split(/\n/).map(l => l.trim()).filter(Boolean);
    if (lines.length < 2) return tableMatch;

    const isDelimiter = /^\|[ \t]*:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)+\|?$/.test(lines[1]);
    if (!isDelimiter) return tableMatch;

    const parseRow = (row: string) => row.replace(/^\||\|$/g, '').split('|').map(c => c.trim());

    const headers = parseRow(lines[0]);
    const headerHtml = headers.map(h => {
      let cellText = h
        .replace(/\*\*([^\*\n]+?)\*\*/g, '<strong class="font-bold text-text-primary">$1</strong>')
        .replace(/(?<!`)`([^`\n]+)`(?!`)/g, '<code class="bg-surface-elevated text-blue-400 px-1 py-0.5 rounded text-[11px] font-mono border border-border-subtle">$1</code>');
      return `<th class="py-2.5 px-3.5 border-r border-border-subtle last:border-r-0 font-bold tracking-tight">${cellText}</th>`;
    }).join('');

    const dataRows = lines.slice(2);
    const bodyHtml = dataRows.map((row, rIdx) => {
      const cells = parseRow(row);
      const cellsHtml = cells.map(c => {
        let cellText = c
          .replace(/\*\*([^\*\n]+?)\*\*/g, '<strong class="font-bold text-text-primary">$1</strong>')
          .replace(/\*([^\*\n]+?)\*/g, '<em class="italic text-text-secondary">$1</em>')
          .replace(/(?<!`)`([^`\n]+)`(?!`)/g, '<code class="bg-surface-elevated text-blue-400 px-1.5 py-0.5 rounded text-[11px] font-mono border border-border-subtle font-semibold">$1</code>');
        return `<td class="py-2 px-3.5 border-r border-border-subtle last:border-r-0 text-text-secondary leading-snug">${cellText}</td>`;
      }).join('');
      const rowBg = rIdx % 2 === 1 ? 'bg-surface-elevated/20' : '';
      return `<tr class="hover:bg-surface-hover/40 transition-colors ${rowBg}">${cellsHtml}</tr>`;
    }).join('');

    return (
      `<div class="my-3 overflow-x-auto rounded-xl border border-border-subtle shadow-sm bg-surface-card">` +
      `<table class="w-full text-left text-xs border-collapse">` +
      `<thead class="bg-surface-elevated text-text-primary text-[11px] uppercase font-bold border-b border-border-subtle">` +
      `<tr>${headerHtml}</tr>` +
      `</thead>` +
      `<tbody class="divide-y divide-border-subtle text-text-secondary">${bodyHtml}</tbody>` +
      `</table>` +
      `</div>`
    );
  });

  // 4. Encabezados H1, H2, H3
  text = text
    .replace(/^### (.*$)/gim, '<h3 class="text-base font-bold text-text-primary mt-4 mb-2 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-lg font-bold text-text-primary mt-5 mb-2.5 pb-1 border-b border-border-subtle flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-indigo-500"></span>$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-xl font-extrabold text-text-primary mt-6 mb-3 pb-1.5 border-b-2 border-border-subtle">$1</h1>');

  // 5. Formato Inline
  text = text
    .replace(/\*\*([^\*\n]+?)\*\*/g, '<strong class="text-text-primary font-bold">$1</strong>')
    .replace(/(?<!\*)\*([^\*\n]+?)\*(?!\*)/g, '<em class="text-text-secondary italic">$1</em>')
    .replace(/(?<!`)`([^`\n]+)`(?!`)/g, '<code class="bg-surface-elevated text-blue-500 dark:text-cyan-300 px-1.5 py-0.5 rounded text-xs font-mono border border-border-subtle font-semibold">$1</code>')
    .replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:underline">$1</a>')
    .replace(/^> (.*$)/gim, '<blockquote class="border-l-4 border-blue-500 pl-3 py-1 my-2 text-text-muted italic bg-surface-elevated/40 rounded-r-lg">$1</blockquote>');

  // 6. Listas con viñetas (-, *, •) y listas numeradas (1., 2.)
  text = text.replace(/^[ \t]*[•\*\-][ \t]+(.*$)/gim, '<li class="ml-4 list-disc text-text-secondary my-0.5 leading-relaxed">$1</li>');
  text = text.replace(/^[ \t]*(\d+)\.[ \t]+(.*$)/gim, '<li class="ml-4 list-decimal text-text-secondary my-0.5 leading-relaxed"><strong class="font-bold text-text-primary mr-1">$1.</strong>$2</li>');

  // 7. Párrafos normales
  const paragraphs = text.split(/\n{2,}/);
  let finalHtml = paragraphs.map(p => {
    const trimmed = p.trim();
    if (!trimmed) return '';
    if (
      trimmed.startsWith('%%CODEBLOCK_') ||
      trimmed.startsWith('<div') ||
      trimmed.startsWith('<h1') ||
      trimmed.startsWith('<h2') ||
      trimmed.startsWith('<h3') ||
      trimmed.startsWith('<hr') ||
      trimmed.startsWith('<blockquote') ||
      trimmed.startsWith('<li')
    ) {
      return trimmed;
    }
    return `<p class="my-1.5 text-text-secondary leading-relaxed">${trimmed.replace(/\n/g, '<br/>')}</p>`;
  }).join('\n');

  // 8. Restaurar los bloques de código previamente protegidos
  codeBlocks.forEach((blockHtml, i) => {
    finalHtml = finalHtml.replace(`%%CODEBLOCK_${i}%%`, blockHtml);
  });

  return { __html: finalHtml };
};

interface MarkdownEditorProps {
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  minHeight?: string;
  textareaId?: string;
}

export const MarkdownEditor: React.FC<MarkdownEditorProps> = ({
  value,
  onChange,
  placeholder = 'Escribe directamente aquí tus notas técnicas... El formato Markdown (**negritas**, # títulos, listas) se interpreta y renderiza en tiempo real.',
  minHeight = '320px',
  textareaId = 'soc-md-textarea',
}) => {
  const [viewMode, setViewMode] = useState<'wysiwyg' | 'raw'>('wysiwyg');
  const [copied, setCopied] = useState(false);

  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        heading: {
          levels: [1, 2, 3],
        },
        codeBlock: {
          HTMLAttributes: {
            class: 'rounded-xl bg-[#0B132B] border border-border-subtle p-3.5 font-mono text-xs text-emerald-400 overflow-x-auto my-3 leading-relaxed',
          },
        },
      }),
      Markdown.configure({
        html: true,
        tightLists: true,
        bulletListMarker: '-',
        linkify: true,
        breaks: false,
        transformPastedText: true,
        transformCopiedText: true,
      }),
      Table.configure({
        resizable: true,
        HTMLAttributes: {
          class: 'w-full my-3 border-collapse rounded-xl border border-border-subtle overflow-hidden text-xs',
        },
      }),
      TableRow.configure({
        HTMLAttributes: {
          class: 'border-b border-border-subtle hover:bg-surface-elevated/30 transition-colors',
        },
      }),
      TableHeader.configure({
        HTMLAttributes: {
          class: 'bg-surface-elevated py-2.5 px-3.5 text-left font-bold text-text-primary border-r border-border-subtle last:border-r-0 uppercase text-[11px]',
        },
      }),
      TableCell.configure({
        HTMLAttributes: {
          class: 'py-2 px-3.5 text-text-secondary border-r border-border-subtle last:border-r-0',
        },
      }),
      Link.configure({
        openOnClick: false,
        HTMLAttributes: {
          class: 'text-blue-400 underline hover:text-blue-300 cursor-pointer',
        },
      }),
    ],
    content: value,
    editorProps: {
      attributes: {
        class: 'soc-tiptap-editor focus:outline-none p-5 text-sm text-text-primary leading-relaxed min-h-[260px]',
      },
    },
    onUpdate: ({ editor }) => {
      const md = (editor.storage as any).markdown.getMarkdown();
      onChange(md);
    },
  });

  // Mantener sincronizado si `value` cambia desde fuera (ej. al cambiar de nota en IRIS)
  useEffect(() => {
    if (editor && !editor.isDestroyed) {
      const currentMd = (editor.storage as any).markdown?.getMarkdown();
      if (value !== currentMd) {
        editor.commands.setContent(value || '', { emitUpdate: false });
      }
    }
  }, [value, editor]);

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card flex flex-col shadow-sm">
      {/* Estilos CSS para el editor WYSIWYG en vivo */}
      <style>{`
        .soc-tiptap-editor h1 {
          font-size: 1.35rem;
          font-weight: 800;
          color: #f1f5f9;
          margin-top: 1.25rem;
          margin-bottom: 0.65rem;
          padding-bottom: 0.35rem;
          border-bottom: 2px solid rgba(148, 163, 184, 0.2);
        }
        .soc-tiptap-editor h2 {
          font-size: 1.15rem;
          font-weight: 700;
          color: #e2e8f0;
          margin-top: 1.1rem;
          margin-bottom: 0.5rem;
          padding-bottom: 0.25rem;
          border-bottom: 1px solid rgba(148, 163, 184, 0.15);
        }
        .soc-tiptap-editor h3 {
          font-size: 1rem;
          font-weight: 600;
          color: #cbd5e1;
          margin-top: 0.85rem;
          margin-bottom: 0.35rem;
        }
        .soc-tiptap-editor p {
          margin-top: 0.45rem;
          margin-bottom: 0.45rem;
          color: #cbd5e1;
          line-height: 1.65;
        }
        .soc-tiptap-editor strong {
          font-weight: 700;
          color: #f8fafc;
        }
        .soc-tiptap-editor em {
          font-style: italic;
          color: #94a3b8;
        }
        .soc-tiptap-editor code:not(pre code) {
          background-color: rgba(30, 41, 59, 0.8);
          color: #38bdf8;
          padding: 0.15rem 0.4rem;
          border-radius: 0.375rem;
          font-size: 0.82rem;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          border: 1px solid rgba(148, 163, 184, 0.2);
        }
        .soc-tiptap-editor ul {
          list-style-type: disc;
          padding-left: 1.5rem;
          margin-top: 0.5rem;
          margin-bottom: 0.5rem;
          color: #cbd5e1;
        }
        .soc-tiptap-editor ol {
          list-style-type: decimal;
          padding-left: 1.5rem;
          margin-top: 0.5rem;
          margin-bottom: 0.5rem;
          color: #cbd5e1;
        }
        .soc-tiptap-editor li {
          margin-top: 0.2rem;
          margin-bottom: 0.2rem;
        }
        .soc-tiptap-editor blockquote {
          border-left: 4px solid #3b82f6;
          padding-left: 1rem;
          padding-top: 0.25rem;
          padding-bottom: 0.25rem;
          margin-top: 0.75rem;
          margin-bottom: 0.75rem;
          background-color: rgba(30, 41, 59, 0.4);
          border-radius: 0 0.5rem 0.5rem 0;
          font-style: italic;
          color: #94a3b8;
        }
        .soc-tiptap-editor hr {
          border: 0;
          border-top: 1px solid rgba(148, 163, 184, 0.2);
          margin-top: 1.25rem;
          margin-bottom: 1.25rem;
        }
        .soc-tiptap-editor table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 0.75rem;
          margin-bottom: 0.75rem;
        }
        .soc-tiptap-editor th, .soc-tiptap-editor td {
          border: 1px solid rgba(148, 163, 184, 0.2);
          padding: 0.5rem 0.75rem;
        }
        .soc-tiptap-editor th {
          background-color: rgba(30, 41, 59, 0.7);
          font-weight: 700;
        }
      `}</style>

      {/* Toolbar WYSIWYG interactiva */}
      <div className="flex flex-wrap items-center justify-between px-3 py-2 border-b border-border-subtle bg-surface-elevated/50 text-text-secondary text-xs gap-1">
        <div className="flex items-center flex-wrap gap-1">
          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleBold().run()}
            title="Negrita (Ctrl+B / **texto**)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('bold')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Bold className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleItalic().run()}
            title="Cursiva (Ctrl+I / *texto*)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('italic')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Italic className="w-4 h-4" />
          </button>

          <div className="h-4 w-px bg-border-subtle mx-1" />

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleHeading({ level: 1 }).run()}
            title="Título Principal (# Encabezado)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('heading', { level: 1 })
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Heading1 className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleHeading({ level: 2 }).run()}
            title="Subtítulo H2 (## Encabezado)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('heading', { level: 2 })
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Heading2 className="w-4 h-4" />
          </button>

          <div className="h-4 w-px bg-border-subtle mx-1" />

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleBulletList().run()}
            title="Lista con viñetas (- elemento)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('bulletList')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <List className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleOrderedList().run()}
            title="Lista numerada (1. elemento)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('orderedList')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <ListOrdered className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleBlockquote().run()}
            title="Cita / Bloque destacado (> texto)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('blockquote')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Quote className="w-4 h-4" />
          </button>

          <div className="h-4 w-px bg-border-subtle mx-1" />

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleCode().run()}
            title="Código en línea (`código`)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('code')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Code className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().toggleCodeBlock().run()}
            title="Bloque de comando / terminal (```)"
            className={`p-1.5 rounded transition-colors ${
              editor?.isActive('codeBlock')
                ? 'bg-blue-600 text-white font-bold'
                : 'hover:bg-surface-hover hover:text-text-primary text-text-secondary'
            }`}
          >
            <Terminal className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() =>
              editor
                ?.chain()
                .focus()
                .insertTable({ rows: 3, cols: 3, withHeaderRow: true })
                .run()
            }
            title="Insertar Tabla interactiva"
            className="p-1.5 rounded hover:bg-surface-hover hover:text-text-primary text-text-secondary transition-colors"
          >
            <TableIcon className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().setHorizontalRule().run()}
            title="Línea horizontal separadora (---)"
            className="p-1.5 rounded hover:bg-surface-hover hover:text-text-primary text-text-secondary transition-colors"
          >
            <Minus className="w-4 h-4" />
          </button>

          <div className="h-4 w-px bg-border-subtle mx-1" />

          <button
            type="button"
            onClick={() => editor?.chain().focus().undo().run()}
            disabled={!editor?.can().undo()}
            title="Deshacer (Ctrl+Z)"
            className="p-1.5 rounded hover:bg-surface-hover hover:text-text-primary text-text-secondary disabled:opacity-30 disabled:pointer-events-none transition-colors"
          >
            <Undo2 className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={() => editor?.chain().focus().redo().run()}
            disabled={!editor?.can().redo()}
            title="Rehacer (Ctrl+Y)"
            className="p-1.5 rounded hover:bg-surface-hover hover:text-text-primary text-text-secondary disabled:opacity-30 disabled:pointer-events-none transition-colors"
          >
            <Redo2 className="w-4 h-4" />
          </button>
        </div>

        {/* View Mode Controls & Copy */}
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center gap-1 px-2.5 py-1 rounded text-xs text-text-muted hover:text-text-primary hover:bg-surface-hover transition-colors"
            title="Copiar contenido en formato Markdown"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copiado' : 'Copiar'}</span>
          </button>

          <div className="h-4 w-px bg-border-subtle mx-0.5" />

          <button
            type="button"
            onClick={() => setViewMode('wysiwyg')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
              viewMode === 'wysiwyg'
                ? 'bg-blue-600 text-white font-medium shadow-sm'
                : 'hover:bg-surface-hover text-text-muted hover:text-text-primary'
            }`}
            title="Editor visual enriquecido en tiempo real"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Visual WYSIWYG</span>
          </button>

          <button
            type="button"
            onClick={() => setViewMode('raw')}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
              viewMode === 'raw'
                ? 'bg-blue-600 text-white font-medium shadow-sm'
                : 'hover:bg-surface-hover text-text-muted hover:text-text-primary'
            }`}
            title="Ver / editar sintaxis Markdown pura"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Código Markdown</span>
          </button>
        </div>
      </div>

      {/* Editor Body */}
      <div className="relative flex-1 bg-surface-card" style={{ minHeight }}>
        {viewMode === 'wysiwyg' && (
          <div className="w-full h-full cursor-text" onClick={() => editor?.commands.focus()}>
            <EditorContent editor={editor} />
          </div>
        )}

        {viewMode === 'raw' && (
          <textarea
            id={textareaId}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            className="w-full h-full p-5 bg-surface-card text-text-primary font-mono text-xs leading-relaxed focus:outline-none resize-none"
            style={{ minHeight }}
          />
        )}
      </div>

      {/* Footer indicador */}
      <div className="px-3.5 py-1.5 border-t border-border-subtle bg-surface-root/50 text-[10px] font-mono text-text-muted flex items-center justify-between">
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          <span>Editor enriquecido en vivo</span>
        </span>
        <span className="text-text-muted">Compatible con DFIR-IRIS y almacenamiento Markdown</span>
      </div>
    </div>
  );
};