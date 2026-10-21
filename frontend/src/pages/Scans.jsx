import { useCallback, useEffect, useState } from "react";
import { api, errMsg } from "../api";
import { ErrorAlert, ScanStatus, fmtDate } from "../components";

const PROFILES = [
  { id: "discovery", label: "Découverte rapide", desc: "Liste les hôtes actifs, sans ports" },
  { id: "standard", label: "Standard", desc: "1000 ports courants, services et versions" },
  { id: "deep", label: "Approfondi", desc: "Tous les ports et détection d'OS (long)" },
];

export default function Scans() {
  const [scopes, setScopes] = useState([]);
  const [scans, setScans] = useState([]);
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("standard");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const loadScans = useCallback(async () => {
    try { setScans(await api("/scans")); } catch (e) { setError(errMsg(e)); }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const sc = await api("/scopes");
        setScopes(sc);
        setTarget((t) => t || sc[0]?.cidr || "");
      } catch (e) { setError(errMsg(e)); }
    })();
    loadScans();
    const id = setInterval(loadScans, 3000);
    return () => clearInterval(id);
  }, [loadScans]);

  async function launch(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/scans", { method: "POST", body: { target: target.trim(), profile } });
      await loadScans();
    } catch (err) { setError(errMsg(err)); } finally { setBusy(false); }
  }

  async function cancel(id) {
    try { await api(`/scans/${id}/cancel`, { method: "POST" }); await loadScans(); }
    catch (err) { setError(errMsg(err)); }
  }

  return (
    <>
      <h1 className="h3 mb-3">Scans</h1>
      {scopes.length === 0 && (
        <div className="alert alert-warning" role="status">
          Aucun périmètre autorisé. Un administrateur doit en créer un (Administration, onglet Périmètres).
        </div>
      )}
      <form onSubmit={launch} className="card card-body mb-4">
        <ErrorAlert error={error} />
        <div className="row g-3 align-items-end">
          <div className="col-md-4">
            <label htmlFor="target" className="form-label">Cible (IP ou CIDR, dans un périmètre autorisé)</label>
            <input id="target" className="form-control" value={target} list="scope-list"
              onChange={(e) => setTarget(e.target.value)} required maxLength={64} />
            <datalist id="scope-list">{scopes.map((s) => <option key={s.id} value={s.cidr}>{s.name}</option>)}</datalist>
          </div>
          <div className="col-md-5">
            <label htmlFor="profile" className="form-label">Profil</label>
            <select id="profile" className="form-select" value={profile} onChange={(e) => setProfile(e.target.value)}>
              {PROFILES.map((p) => <option key={p.id} value={p.id}>{p.label} : {p.desc}</option>)}
            </select>
          </div>
          <div className="col-md-3">
            <button className="btn btn-primary w-100" disabled={busy || !target}>Lancer le scan</button>
          </div>
        </div>
      </form>
      <table className="table align-middle">
        <thead><tr><th>#</th><th>Cible</th><th>Profil</th><th>Statut</th><th>Créé</th><th>Terminé</th><th>Détail</th><th></th></tr></thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td>{s.id}</td><td>{s.target}</td><td>{s.profile}</td>
              <td><ScanStatus status={s.status} /></td>
              <td>{fmtDate(s.created_at)}</td><td>{fmtDate(s.finished_at)}</td>
              <td className="small text-danger">{s.error}</td>
              <td>
                {(s.status === "pending" || s.status === "running") && (
                  <button className="btn btn-sm btn-outline-danger" onClick={() => cancel(s.id)}>Annuler</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}