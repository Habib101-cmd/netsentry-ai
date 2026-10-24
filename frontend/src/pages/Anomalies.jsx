import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errMsg } from "../api";
import { ErrorAlert, fmtDate } from "../components";

export default function Anomalies() {
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [data, setData] = useState(null);
  const [openId, setOpenId] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const done = (await api("/scans")).filter((s) => s.status === "done");
        setScans(done);
        if (done[0]) setScanId(String(done[0].id));
      } catch (e) { setError(errMsg(e)); }
    })();
  }, []);

  useEffect(() => {
    if (!scanId) return;
    (async () => {
      try { setData(await api(`/scans/${scanId}/anomalies`)); setOpenId(null); setError(""); }
      catch (e) { setError(errMsg(e)); }
    })();
  }, [scanId]);

  return (
    <>
      <h1 className="h3 mb-3">Comportements atypiques</h1>
      <div className="alert alert-info" role="note">
        Résultat d'un modèle statistique (Isolation Forest) entraîné sur des données synthétiques. Un comportement
        atypique est <strong>à vérifier</strong> : ce n'est ni une vulnérabilité, ni une attaque confirmée.
      </div>
      <ErrorAlert error={error} />
      <div className="mb-3" style={{ maxWidth: 420 }}>
        <label htmlFor="anscan" className="form-label">Scan</label>
        <select id="anscan" className="form-select" value={scanId} onChange={(e) => setScanId(e.target.value)}>
          {scans.map((s) => <option key={s.id} value={s.id}>#{s.id} : {s.target} ({s.profile}) {fmtDate(s.finished_at)}</option>)}
        </select>
      </div>
      {data?.message && <div className="alert alert-warning" role="status">{data.message}</div>}
      {data && data.results.length > 0 && (
        <>
          <p className="text-muted small">Modèle : {data.model_version} · seuil d'alerte : {data.results[0].explanation.threshold}</p>
          <table className="table align-middle">
            <thead><tr><th>Équipement</th><th>Score d'anomalie</th><th>Verdict</th><th><span className="visually-hidden">Détails</span></th></tr></thead>
            <tbody>
              {data.results.map((r) => (
                <Fragment key={r.id}>
                  <tr>
                    <td><Link to={`/hosts/${r.host_id}`}>{r.host_ip}</Link></td>
                    <td>{r.score}</td>
                    <td>{r.is_anomaly
                      ? <span className="badge bg-warning text-dark">Comportement atypique à vérifier</span>
                      : <span className="badge bg-light text-dark border">Dans la norme apprise</span>}</td>
                    <td><button className="btn btn-sm btn-outline-primary" aria-expanded={openId === r.id}
                      onClick={() => setOpenId(openId === r.id ? null : r.id)}>{openId === r.id ? "Masquer" : "Pourquoi ?"}</button></td>
                  </tr>
                  {openId === r.id && (
                    <tr><td colSpan={4} className="bg-body-tertiary">
                      <p className="mb-2">{r.explanation.summary}</p>
                      <table className="table table-sm w-auto mb-0">
                        <caption className="caption-top">Écarts par rapport au comportement normal appris</caption>
                        <thead><tr><th>Caractéristique</th><th>Valeur observée</th><th>Moyenne normale</th><th>Écart (σ)</th><th>Part de l'écart</th></tr></thead>
                        <tbody>
                          {r.explanation.details.map((d) => (
                            <tr key={d.feature}><td>{d.label}</td><td>{d.value}</td><td>{d.baseline_mean}</td>
                              <td>{d.z}</td><td>{Math.round(d.contribution * 100)} %</td></tr>
                          ))}
                        </tbody>
                      </table>
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}