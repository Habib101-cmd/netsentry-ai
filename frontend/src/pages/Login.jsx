import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { ApiError, errMsg } from "../api";
import { ErrorAlert } from "../components";

export default function Login() {
  const { user, login } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to={user.must_change_password ? "/change-password" : "/"} replace />;

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const me = await login(username, password);
      nav(me.must_change_password ? "/change-password" : "/", { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError("Trop de tentatives ou compte temporairement verrouillé (15 min). Réessayez plus tard.");
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Identifiant ou mot de passe incorrect.");
      } else {
        setError(errMsg(err));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container py-5" style={{ maxWidth: 460 }}>
      <h1 className="h3 mb-3">NetSentry AI</h1>
      {location.state?.message && <div className="alert alert-success" role="status">{location.state.message}</div>}
      <div className="alert alert-warning" role="note">
        <strong>Avertissement légal :</strong> cet outil ne doit être utilisé que sur des réseaux dont vous
        êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite. Analyse non destructive
        uniquement.
      </div>
      <form onSubmit={submit} className="card card-body">
        <ErrorAlert error={error} />
        <label htmlFor="username" className="form-label">Identifiant</label>
        <input id="username" className="form-control mb-3" value={username} autoComplete="username"
          onChange={(e) => setUsername(e.target.value)} required maxLength={64} />
        <label htmlFor="password" className="form-label">Mot de passe</label>
        <input id="password" type="password" className="form-control mb-3" value={password}
          autoComplete="current-password" onChange={(e) => setPassword(e.target.value)} required maxLength={256} />
        <button className="btn btn-primary" disabled={busy}>{busy ? "Connexion…" : "Se connecter"}</button>
      </form>
    </div>
  );
}