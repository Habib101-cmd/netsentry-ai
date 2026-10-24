import { useEffect, useState } from "react";
import { api, errMsg } from "../api";
import { ErrorAlert, LEVELS, LEVEL_COLOR, LEVEL_FR, fmtDate } from "../components";

const ORDER = ["info", "low", "medium", "high", "critical"]; // du bas vers le haut de la pile

function StackedBars({ rows }) {
  const W = 760, H = 280, pad = 40;
  const max = Math.max(1, ...rows.map((r) => r.findings));
  const slot = (W - pad * 2) / rows.length;
  const bw = Math.min(60, slot - 10);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} role="img" style={{ maxWidth: "100%" }}
      aria-label="Nombre de constats par scan et par niveau de risque. Le tableau suivant donne les mêmes valeurs.">
      <line x1={pad} y1={H - pad} x2={W - pad} y2={H - pad} stroke="#6c757d" />
      <line x1={pad} y1={pad} x2={pad} y2={H - pad} stroke="#6c757d" />
      <text x={pad - 6} y={pad + 4} textAnchor="end" fontSize="11">{max}</text>
      <text x={pad - 6} y={H - pad + 4} textAnchor="end" fontSize="11">0</text>
      {rows.map((r, i) => {
        const x = pad + i * slot + (slot - bw) / 2;
        let y = H - pad;
        return (
          <g key={r.id}>
            {ORDER.map((l) => {
              const n = r.by_level[l] || 0;
              if (!n) return null;
              const h = (n / max) * (H - pad * 2);
              y -= h;
              return (
                <rect key={l} x={x} y={y} width={bw} height={h} fill={LEVEL_COLOR[l]} stroke="#212529" strokeWidth="0.5">
                  <title>{`Scan #${r.id} : ${n} constat(s) ${LEVEL_FR[l]}`}</title>
                </rect>
              );
            })}
            <text x={x + bw / 2} y={H - pad + 14} textAnchor="middle" fontSize="11">#{r.id}</text>
          </g>
        );
      })}
    </svg>
  );
}

export default function Timeline() {
  const [rows, setRows] = useState([]);
  const [profile, setProfile] = useState("standard");
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try { setRows(await api(`/scans/timeline?profile=${profile}`)); setError(""); }
      catch (e) { setError(errMsg(e)); }
    })();
  }, [profile]);

  return (
    <>
      <h1 className="h3 mb-3">Chronologie de l'exposition</h1>
      <ErrorAlert error={error} />
      <div className="mb-3" style={{ maxWidth: 320 }}>
        <label htmlFor="tp" className="form-label">Profil de scan</label>
        <select id="tp" className="form-select" value={profile} onChange={(e) => setProfile(e.target.value)}>
          <option value="standard">Standard</option>
          <option value="deep">Approfondi</option>
          <option value="discovery">Découverte rapide</option>
        </select>
      </div>
      <p className="text-muted small">
        Comparez des scans de même profil et de même cible : un changement de cible ou de profil modifie les chiffres
        sans que le réseau ait évolué.
      </p>
      {rows.length === 0 ? <p className="text-muted">Aucun scan terminé pour ce profil.</p> : (
        <>
          <StackedBars rows={rows} />
          <p className="small">
            {[...LEVELS].reverse().map((l) => (
              <span key={l} className="me-3">
                <span style={{ display: "inline-block", width: 12, height: 12, background: LEVEL_COLOR[l], border: "1px solid #212529" }} /> {LEVEL_FR[l]}
              </span>
            ))}
          </p>
          <table className="table table-sm mt-3">
            <caption className="caption-top">Détail par scan</caption>
            <thead><tr><th>Scan</th><th>Date</th><th>Cible</th><th>Équipements actifs</th><th>Ports ouverts</th><th>Constats</th><th>Score cumulé</th>
              {LEVELS.map((l) => <th key={l}>{LEVEL_FR[l]}</th>)}</tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}><td>#{r.id}</td><td>{fmtDate(r.finished_at)}</td><td>{r.target}</td>
                  <td>{r.hosts_up}</td><td>{r.open_ports}</td><td>{r.findings}</td><td>{r.total_score}</td>
                  {LEVELS.map((l) => <td key={l}>{r.by_level[l]}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}