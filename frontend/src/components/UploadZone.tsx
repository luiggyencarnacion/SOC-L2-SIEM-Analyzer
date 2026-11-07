// UploadZone.tsx - Carga del Excel con validaciones del lado API.
import { useRef, useState } from "react";
import { uploadFile } from "../api";
import type { UploadResponse } from "../types";

export function UploadZone({
  onUploaded,
  onError,
}: {
  onUploaded: (res: UploadResponse) => void;
  onError: (msg: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);

  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    onError("");
    try {
      const res = await uploadFile(file);
      onUploaded(res);
    } catch (e) {
      onError(e instanceof Error ? e.message : "Error al subir el archivo");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-white rounded-lg border border-slate-200 p-8">
      <h2 className="text-base font-semibold mb-1">Subir archivo de logs (.xlsx)</h2>
      <p className="text-sm text-slate-500 mb-6">
        Exportado del SIEM. Límites: 25 MB · 50 hojas · 100 columnas · 100.000 filas. Solo .xlsx; se rechazan macros (.xlsm), .xls y archivos corruptos.
      </p>
      <div
        className={`border-2 border-dashed rounded-lg p-10 text-center transition ${
          dragging ? "border-sky-500 bg-sky-50" : "border-slate-300 hover:bg-slate-50"
        }`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          void handleFile(e.dataTransfer.files?.[0]);
        }}
      >
        <p className="text-slate-500 mb-4 text-sm">Arrastra el archivo aquí o</p>
        <button
          type="button"
          disabled={busy}
          onClick={() => inputRef.current?.click()}
          className="rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white px-5 py-2 text-sm"
        >
          {busy ? "Procesando…" : "Seleccionar .xlsx"}
        </button>
        <input
          ref={inputRef}
          type="file"
          accept=".xlsx"
          className="hidden"
          onChange={(e) => void handleFile(e.target.files?.[0])}
        />
      </div>
    </div>
  );
}
