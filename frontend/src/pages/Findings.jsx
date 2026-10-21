import { Fragment, useEffect, useState } from "react";
import { api, errMsg } from "../api";
import { ErrorAlert, FINDING_STATUS_FR, LEVELS, LEVEL_FR, LevelBadge, fmtDate } from "../components";

const FACTOR_FR = {
  rule_severity: "Sévérité de la règle",
  host_criticality: "Criticité de l'équipement",
  exposure: "Exposition",
  cvss: "Gravité des CVE (CVSS)",
  confidence: "Confiance d'identification",
};

function FindingDetail({ f, onSaved }) {
  const [status, setStatus] = useState(f.status);
  const [comment, setComment] = useState(f.accepted_comment || "");
  const [error, setError] = useState("");

  async function save() {
    setError("");
    try {
      const updated = await api(`/findings/${f.id}`, {
        method: "PATCH",
        body: { status, comment: status === "accepted" ? comment : null },
      });
      onSaved(updated);
    } catch (e) { setError(errMsg(e)); }
  }

  return (
    <div className="p-2">
      <p><strong>Risque :</strong> {f.justification}</p>
      <p className="mb-1"><strong>Preuves :</strong></p>
      <pre className="small border rounded p-2">{f.evidence}</pre>
      <p><strong>Recommandation :</strong> {f.recommendation}</p>
      <p className="small text-muted">
        Règle {f.rule_id} v{f.rule_version} · première observation {fmtDate(f.first_seen)} · dernière {fmtDate(f.last_seen)}
      </p>
      <table className="table table-sm w-auto">
        <caption className="caption-top">Détail du score ({f.score}/100)</caption>
        <thead><tr><th>Facteur</th><th>Valeur</th><th>Poids</th><th>Contribution</th></tr></thead>
        <tbody>
          {f.factors.map((x) => (
            <tr key={x.factor}>
              <td>{FACTOR_FR[x.factor] || x.factor}</td><td>{x.value}</td>
              <td>{Math.round(x.weight * 100)}%</td><td>{x.contribution}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <ErrorAlert error={error} />
      <div className="row g-2 align-items-end">
        <div className="col-md-3">
          <label htmlFor={`st-${f.id}`} className="form-label">Statut</label>
          <select id={`st-${f.id}`} className="form-select" value={status} onChange={(e) => setStatus(e.target.value)}>
            {Object.entries(FINDING_STATUS_FR).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        {status === "accepted" && (
          <div className="col-md-6">
            <label htmlFor={`cm-${f.id}`} className="form-label">Commentaire (obligatoire)</label>
            <input id={`cm-${f.id}`} className="form-control" value={comment} maxLength={1000}
              onChange={(e) => setComment(e.target.value)} />
          </div>
        )}
        <div className="col-md-2"><button className="btn btn-primary" onClick={save}>Enregistrer</button></div>
      </div>
    </div>
  );
}

export default function Findings() {
  const [items, setItems] = useState([]);
  const [level, setLevel] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [openId, setOpenId] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const t = setTimeout(async () => {
      const params = new URLSearchParams({ limit: "200" });
      if (level) params.set("level", level);
      if (status) params.set("status", status);
      if (q.trim()) params.set("q", q.trim());
      try { setItems(await api(`/findings?${params}`)); setError(""); } catch (e) { setError(errMsg(e)); }
    }, 250);
    return () => clearTimeout(t);
  }, [level, status, q]);

  return (
    <>
      <h1 className="h3 mb-3">Constats</h1>
      <ErrorAlert error={error} />
      <div className="row g-2 mb-3 align-items-end">
        <div className="col-md-2">
          <label htmlFor="lv" className="form-label">Niveau</label>
          <select id="lv" className="form-select" value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="">Tous</option>
            {LEVELS.map((l) => <option key={l} value={l}>{LEVEL_FR[l]}</option>)}
          </select>
        </div>
        <div className="col-md-2">
          <label htmlFor="stt" className="form-label">Statut</label>
          <select id="stt" className="form-select" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Tous</option>
            {Object.entries(FINDING_STATUS_FR).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </div>
        <div className="col-md-4">
          <label htmlFor="qq" className="form-label">Recherche dans le titre</label>
          <input id="qq" className="form-control" value={q} maxLength={100} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="col-md-4">{/* EXPORT_BUTTONS */}</div>
      </div>
      <table className="table table-hover align-middle">
        <thead>
          <tr><th>Niveau</th><th>Score</th><th>Constat</th><th>Équipement</th><th>Statut</th>
            <th><span className="visually-hidden">Détails</span></th></tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <Fragment key={f.id}>
              <tr>
                <td><LevelBadge level={f.level} /></td><td>{f.score}</td><td>{f.title}</td><td>{f.host_ip}</td>
                <td>{FINDING_STATUS_FR[f.status] || f.status}</td>
                <td>
                  <button className="btn btn-sm btn-outline-primary" aria-expanded={openId === f.id}
                    onClick={() => setOpenId(openId === f.id ? null : f.id)}>
                    {openId === f.id ? "Masquer" : "Détails"}
                  </button>
                </td>
              </tr>
              {openId === f.id && (
                <tr><td colSpan={6} className="bg-body-tertiary">
                  <FindingDetail f={f} onSaved={(u) => setItems(items.map((x) => (x.id === u.id ? u : x)))} />
                </td></tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
      {items.length === 0 && <p className="text-muted">Aucun constat.</p>}
    </>
  );
}