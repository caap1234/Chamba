import React, { useState } from 'react';
import { UploadCloud, File, Image, Check, Hash, ExternalLink, Paperclip } from 'lucide-react';
import { Button } from '../common/Button';

interface EvidenceItem {
  id?: number;
  filename: string;
  file_size?: number;
  file_hash?: string;
  file_description?: string;
}

interface EvidenceManagerProps {
  evidences: EvidenceItem[];
  onUpload: (file: File, description: string) => Promise<void>;
}

export const EvidenceManager: React.FC<EvidenceManagerProps> = ({ evidences = [], onUpload }) => {
  const safeEvidences = evidences || [];
  const [uploading, setUploading] = useState(false);
  const [description, setDescription] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processFile(e.target.files[0]);
    }
  };

  const processFile = async (file: File) => {
    setUploading(true);
    try {
      await onUpload(file, description || file.name);
      setDescription('');
    } finally {
      setUploading(false);
    }
  };

  // Clipboard paste listener for screenshots
  const handlePaste = async (e: React.ClipboardEvent) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (let i = 0; i < items.length; i++) {
      if (items[i].type.indexOf('image') !== -1) {
        const file = items[i].getAsFile();
        if (file) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const fileConstructor = (window as any).File;
          const namedFile = fileConstructor ? new fileConstructor([file], `screenshot_${timestamp}.png`, { type: file.type }) : file;
          await processFile(namedFile);
          break;
        }
      }
    }
  };

  return (
    <div className="space-y-4" onPaste={handlePaste} tabIndex={0}>
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white">Bóveda de Evidencias Digitales</h3>
          <p className="text-xs text-slate-400">
            Preservación forense en Datastore DFIR-IRIS con integridad SHA-256
          </p>
        </div>
      </div>

      {/* Drag & Drop & Paste Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-6 text-center transition-all ${dragOver
          ? 'border-blue-500 bg-blue-950/20'
          : 'border-border-subtle bg-surface-card hover:border-slate-500'
          }`}
      >
        <div className="flex flex-col items-center justify-center space-y-2">
          <div className="p-3 rounded-full bg-blue-600/10 text-blue-400">
            <UploadCloud className="w-8 h-8" />
          </div>
          <div className="text-xs font-semibold text-slate-200">
            Arrastra archivos aquí o <span className="text-blue-400 underline cursor-pointer">selecciona de tu equipo</span>
          </div>
          <p className="text-[11px] text-slate-400">
            También puedes presionar <kbd className="px-1.5 py-0.5 rounded bg-surface-elevated text-slate-300 font-mono text-[10px] border border-border-subtle">Ctrl+V</kbd> para pegar capturas de pantalla directamente del portapapeles.
          </p>
          <input
            type="file"
            id="file-upload"
            className="hidden"
            onChange={handleFileSelect}
            disabled={uploading}
          />
          <label htmlFor="file-upload">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              loading={uploading}
              icon={<Paperclip className="w-3.5 h-3.5" />}
              className="mt-2"
              onClick={() => document.getElementById('file-upload')?.click()}
            >
              Seleccionar Archivo
            </Button>
          </label>
        </div>
      </div>

      {/* Evidences List */}
      <div className="border border-border-subtle rounded-xl overflow-hidden bg-surface-card shadow-sm">
        <div className="px-4 py-3 bg-surface-elevated/60 border-b border-border-subtle flex items-center justify-between text-xs">
          <span className="font-bold text-slate-200 uppercase text-[10px] tracking-wider">
            Archivos Registrados ({safeEvidences.length})
          </span>
        </div>
        <div className="divide-y divide-border-subtle">
          {safeEvidences.length === 0 ? (
            <div className="py-8 text-center text-slate-500 text-xs italic">
              No hay evidencias adjuntas a este caso aún.
            </div>
          ) : (
            safeEvidences.map((ev, idx) => (
              <div key={ev.id || idx} className="p-3.5 flex items-center justify-between hover:bg-surface-elevated/30 transition-colors text-xs">
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="p-2 rounded-lg bg-surface-elevated border border-border-subtle text-blue-400 shrink-0">
                    {ev.filename.match(/\.(png|jpe?g|webp|gif)$/i) ? (
                      <Image className="w-4 h-4" />
                    ) : (
                      <File className="w-4 h-4" />
                    )}
                  </div>
                  <div className="flex flex-col truncate">
                    <span className="font-semibold text-white truncate">{ev.filename}</span>
                    <div className="flex items-center gap-2 text-[10px] text-slate-400 mt-0.5 font-mono truncate">
                      <span>{ev.file_size ? `${Math.round(ev.file_size / 1024)} KB` : 'Archivo adjunto'}</span>
                      {ev.file_hash && (
                        <span className="truncate" title={`SHA-256: ${ev.file_hash}`}>
                          &bull; SHA-256: {ev.file_hash.substring(0, 16)}...
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 text-[10px] font-semibold flex items-center gap-1">
                    <Check className="w-3 h-3" /> Datastore IRIS
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
