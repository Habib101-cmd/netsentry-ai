import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errMsg } from "../api";
import { ErrorAlert, fmtDate } from "../components";

const CRIT_FR = { low: "Faible", normal: "Normale", high: "Élevée" };

export default function Hosts() {
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [hosts, setHosts] = useState([]);
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
      try { setHosts(await api(`/hosts?scan_id=${scanId}`)); } catch (e) { setError(errMsg(e)); }
    })();
  }, [scanId]);

  return (
    <>
      <h1 className="h3 mb-3">Équipements</h1>
      <ErrorAlert error={error} />
      <div className="mb-3" style={{ maxWidth: 420 }}>
        <label htmlFor="scan" className="form-label">Scan</label>
        <select id="scan" className="form-select" value={scanId} onChange={(e) => setScanId(e.target.value)}>
          {scans.map((s) => <option key={s.id} value={s.id}>#{s.id} : {s.target} ({s.profile}) {fmtDate(s.finished_at)}</option>)}
        </select>
      </div>
      <table className="table table-hover align-middle">
        <thead><tr><th>IP</th><th>Nom</th><th>MAC</th><th>État</th><th>Ports ouverts</th><th>Criticité</th><th></th></tr></thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.id}>
              <td>{h.ip}</td><td>{h.hostname || "-"}</td><td>{h.mac || "-"}</td>
              <td>{h.state === "up" ? "Actif" : h.state}</td>
              <td>{h.services.filter((s) => s.state === "open").length}</td>
              <td>{CRIT_FR[h.criticality] || h.criticality}</td>
              <td><Link to={`/hosts/${h.id}`}>Détails</Link></td>
            </tr>
          ))}
        </tbody>
      </table>
      {hosts.length === 0 && <p className="text-muted">Aucun équipement pour ce scan.</p>}
    </>
  );
}