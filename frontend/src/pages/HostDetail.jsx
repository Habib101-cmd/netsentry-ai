import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, errMsg } from "../api";
import { ErrorAlert } from "../components";

export default function HostDetail() {
  const { id } = useParams();
  const [host, setHost] = useState(null);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    (async () => {
      try { setHost(await api(`/hosts/${id}`)); } catch (e) { setError(errMsg(e)); }
    })();
  }, [id]);

  async function setCriticality(c) {
    setError(""); setMsg("");
    try {
      setHost(await api(`/hosts/${id}`, { method: "PATCH", body: { criticality: c } }));
      setMsg("Criticité enregistrée : elle sera prise en compte au prochain scan.");
    } catch (e) { setError(errMsg(e)); }
  }

  if (error && !host) return <ErrorAlert error={error} />;
  if (!host) return <p>Chargement…</p>;

  return (
    <>
      <p><Link to="/hosts">&larr; Équipements</Link></p>
      <h1 className="h3">{host.ip}</h1>
      <ErrorAlert error={error} />
      {msg && <div className="alert alert-success" role="status">{msg}</div>}
      <dl className="row">
        <dt className="col-sm-2">Nom d'hôte</dt><dd className="col-sm-10">{host.hostname || "-"}</dd>
        <dt className="col-sm-2">MAC</dt><dd className="col-sm-10">{host.mac || "-"}</dd>
        <dt className="col-sm-2">OS estimé</dt><dd className="col-sm-10">{host.os_guess || "-"}</dd>
        <dt className="col-sm-2"><label htmlFor="crit">Criticité</label></dt>
        <dd className="col-sm-10">
          <select id="crit" className="form-select w-auto" value={host.criticality} onChange={(e) => setCriticality(e.target.value)}>
            <option value="low">Faible</option><option value="normal">Normale</option><option value="high">Élevée</option>
          </select>
        </dd>
      </dl>
      <h2 className="h5">Services</h2>
      <table className="table">
        <thead><tr><th>Port</th><th>État</th><th>Service</th><th>Produit / version</th><th>Confiance</th><th>CVE potentielles</th></tr></thead>
        <tbody>
          {host.services.map((s) => (
            <tr key={s.id}>
              <td>{s.port}/{s.protocol}</td><td>{s.state}</td><td>{s.name || "inconnu"}</td>
              <td>{[s.product, s.version].filter(Boolean).join(" ") || "-"}</td>
              <td>{s.confidence}%</td>
              <td>{s.vulnerabilities.length === 0 ? "-" : s.vulnerabilities.map((v) => `${v.cve} (${v.cvss})`).join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}