import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { api, errMsg } from "../api";
import { ErrorAlert } from "../components";

export default function ChangePassword() {
  const { user, loading, forget } = useAuth();
  const nav = useNavigate();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  if (loading) return null;
  if (!user && !done) return <Navigate to="/login" replace />;

  async function submit(e) {
    e.preventDefault();
    setError("");
    if (next.length < 12) return setError("12 caractères minimum.");
    if (next !== confirm) return setError("La confirmation ne correspond pas.");
    setBusy(true);
    try {
      await api("/auth/change-password", {
        method: "POST",
        body: { current_password: current, new_password: next },
      });
      setDone(true);
      forget(); // le serveur a révoqué les sessions : on repasse par la connexion
      nav("/login", { replace: true, state: { message: "Mot de passe modifié. Reconnectez-vous." } });
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container py-5" style={{ maxWidth: 460 }}>
      <h1 className="h4 mb-3">Changer le mot de passe</h1>
      {user?.must_change_password && (
        <p className="alert alert-info" role="status">Un nouveau mot de passe est obligatoire avant de continuer.</p>
      )}
      <form onSubmit={submit} className="card card-body">
        <ErrorAlert error={error} />
        <label htmlFor="cur" className="form-label">Mot de passe actuel</label>
        <input id="cur" type="password" className="form-control mb-3" value={current}
          onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
        <label htmlFor="new" className="form-label">Nouveau mot de passe (12 caractères minimum)</label>
        <input id="new" type="password" className="form-control mb-3" value={next}
          onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required />
        <label htmlFor="conf" className="form-label">Confirmation</label>
        <input id="conf" type="password" className="form-control mb-3" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required />
        <button className="btn btn-primary" disabled={busy}>Enregistrer</button>
      </form>
    </div>
  );
}