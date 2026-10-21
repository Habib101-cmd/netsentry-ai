import { useCallback, useEffect, useState } from "react";
import { api, errMsg } from "../api";
import { ErrorAlert, fmtDate } from "../components";

function Users() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  const load = useCallback(async () => {
    try { setUsers(await api("/users")); } catch (e) { setError(errMsg(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function create(e) {
    e.preventDefault();
    setError(""); setOk("");
    try {
      await api("/users", { method: "POST", body: form });
      setOk(`Compte « ${form.username} » créé : mot de passe à changer à la première connexion.`);
      setForm({ username: "", password: "", role: "analyst" });
      load();
    } catch (err) { setError(errMsg(err)); }
  }

  return (
    <>
      <ErrorAlert error={error} />
      {ok && <div className="alert alert-success" role="status">{ok}</div>}
      <form onSubmit={create} className="row g-2 mb-4 align-items-end">
        <div className="col-md-3">
          <label htmlFor="nu" className="form-label">Identifiant</label>
          <input id="nu" className="form-control" value={form.username} required minLength={3} maxLength={64}
            onChange={(e) => setForm({ ...form, username: e.target.value })} />
        </div>
        <div className="col-md-4">
          <label htmlFor="np" className="form-label">Mot de passe temporaire (12+)</label>
          <input id="np" type="password" className="form-control" value={form.password} required
            autoComplete="new-password" onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </div>
        <div className="col-md-3">
          <label htmlFor="nr" className="form-label">Rôle</label>
          <select id="nr" className="form-select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="analyst">Analyste sécurité</option><option value="admin">Administrateur</option>
          </select>
        </div>
        <div className="col-md-2"><button className="btn btn-primary w-100">Créer</button></div>
      </form>
      <table className="table">
        <thead><tr><th>#</th><th>Identifiant</th><th>Rôle</th><th>Actif</th><th>Dernière connexion</th></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}><td>{u.id}</td><td>{u.username}</td><td>{u.role}</td>
              <td>{u.is_active ? "Oui" : "Non"}</td><td>{fmtDate(u.last_login)}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Scopes() {
  const empty = { name: "", cidr: "", description: "", allow_public: false, authorization_confirmed: false };
  const [scopes, setScopes] = useState([]);
  const [form, setForm] = useState(empty);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try { setScopes(await api("/scopes")); } catch (e) { setError(errMsg(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function create(e) {
    e.preventDefault();
    setError("");
    try { await api("/scopes", { method: "POST", body: form }); setForm(empty); load(); }
    catch (err) { setError(errMsg(err)); }
  }

  return (
    <>
      <div className="alert alert-warning" role="note">
        <strong>Avertissement légal :</strong> ne définissez que des périmètres dont vous êtes propriétaire ou
        pour lesquels vous avez une autorisation écrite. Votre confirmation est journalisée.
      </div>
      <ErrorAlert error={error} />
      <form onSubmit={create} className="row g-2 mb-4">
        <div className="col-md-3">
          <label htmlFor="sn" className="form-label">Nom</label>
          <input id="sn" className="form-control" value={form.name} required maxLength={100}
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="col-md-3">
          <label htmlFor="sc" className="form-label">CIDR</label>
          <input id="sc" className="form-control" value={form.cidr} required maxLength={43} placeholder="172.30.0.0/24"
            onChange={(e) => setForm({ ...form, cidr: e.target.value })} />
        </div>
        <div className="col-md-6">
          <label htmlFor="sd" className="form-label">Description</label>
          <input id="sd" className="form-control" value={form.description} maxLength={500}
            onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </div>
        <div className="col-12 form-check ms-2">
          <input id="sp" type="checkbox" className="form-check-input" checked={form.allow_public}
            onChange={(e) => setForm({ ...form, allow_public: e.target.checked })} />
          <label htmlFor="sp" className="form-check-label">Autoriser une plage publique (déconseillé)</label>
        </div>
        <div className="col-12 form-check ms-2">
          <input id="sa" type="checkbox" className="form-check-input" checked={form.authorization_confirmed} required
            onChange={(e) => setForm({ ...form, authorization_confirmed: e.target.checked })} />
          <label htmlFor="sa" className="form-check-label">Je confirme être autorisé à analyser ce périmètre</label>
        </div>
        <div className="col-12"><button className="btn btn-primary">Créer le périmètre</button></div>
      </form>
      <table className="table">
        <thead><tr><th>#</th><th>Nom</th><th>CIDR</th><th>Description</th><th>Publique</th></tr></thead>
        <tbody>
          {scopes.map((s) => (
            <tr key={s.id}><td>{s.id}</td><td>{s.name}</td><td>{s.cidr}</td><td>{s.description}</td>
              <td>{s.allow_public ? "Oui" : "Non"}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Audit() {
  const [rows, setRows] = useState([]);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try { setRows(await api(`/audit-logs?limit=100&offset=${offset}`)); } catch (e) { setError(errMsg(e)); }
    })();
  }, [offset]);

  return (
    <>
      <ErrorAlert error={error} />
      <table className="table table-sm">
        <thead><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>Cible</th><th>IP source</th><th>Résultat</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}><td>{fmtDate(r.created_at)}</td><td>{r.username || "-"}</td><td>{r.action}</td>
              <td>{r.target || "-"}</td><td>{r.source_ip || "-"}</td><td>{r.result}</td></tr>
          ))}
        </tbody>
      </table>
      <button className="btn btn-outline-secondary me-2" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Précédent</button>
      <button className="btn btn-outline-secondary" disabled={rows.length < 100} onClick={() => setOffset(offset + 100)}>Suivant</button>
    </>
  );
}

export default function Admin() {
  const [tab, setTab] = useState("users");
  const tabs = [["users", "Utilisateurs"], ["scopes", "Périmètres"], ["audit", "Journal d'audit"]];
  return (
    <>
      <h1 className="h3 mb-3">Administration</h1>
      <ul className="nav nav-tabs mb-3">
        {tabs.map(([k, label]) => (
          <li className="nav-item" key={k}>
            <button className={`nav-link ${tab === k ? "active" : ""}`} aria-current={tab === k} onClick={() => setTab(k)}>{label}</button>
          </li>
        ))}
      </ul>
      {tab === "users" && <Users />}
      {tab === "scopes" && <Scopes />}
      {tab === "audit" && <Audit />}
    </>
  );
}