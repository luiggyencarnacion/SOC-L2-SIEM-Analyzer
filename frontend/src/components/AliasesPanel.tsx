// AliasesPanel.tsx - Relaciones de identidades: exact / probable / candidate.
import type { AliasRelation } from "../types";

export function AliasesPanel({ aliases }: { aliases: { hosts: AliasRelation[]; users: AliasRelation[] } }) {
  return (
    <div className="bg-white rounded-lg border border-slate-200 p-6 space-y-4">
      <h3 className="text-sm font-semibold">Alias de identidades</h3>
      <p className="text-xs text-slate-500">
        exact = sin ambigüedad · probable = misma clave normalizada con valores crudos distintos (inferencia) ·
        candidate = valores parecidos con claves distintas (no se fusionan). El valor crudo nunca se sobrescribe.
      </p>
      <div className="grid md:grid-cols-2 gap-6">
        <AliasList title="Hosts" relations={aliases.hosts} />
        <AliasList title="Usuarios" relations={aliases.users} />
      </div>
    </div>
  );
}

function AliasList({ title, relations }: { title: string; relations: AliasRelation[] }) {
  const interesting = relations.filter((r) => r.status !== "exact" || r.members.length > 1);
  return (
    <section>
      <h4 className="text-xs font-semibold text-slate-600 mb-2">{title} ({relations.length})</h4>
      {interesting.length === 0 ? (
        <p className="text-xs text-slate-500">Sin relaciones relevantes: todas las identidades son únicas.</p>
      ) : (
        <ul className="space-y-1.5 max-h-64 overflow-y-auto">
          {interesting.map((r, i) => (
            <li key={`${r.key}-${i}`} className="text-xs flex gap-2 items-start">
              <span className={`rounded px-1.5 py-0.5 ${badge(r.status)}`}>{r.status}</span>
              <span className="font-mono">{r.members.join(" ↔ ")}</span>
              {r.status === "candidate" && <span className="text-slate-500">(canon: {r.key}, no fusionados)</span>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function badge(status: string): string {
  switch (status) {
    case "probable":
      return "bg-amber-100 text-amber-800";
    case "candidate":
      return "bg-sky-100 text-sky-800";
    default:
      return "bg-emerald-100 text-emerald-800";
  }
}
