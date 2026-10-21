import { useCallback, useEffect, useState } from "react";
import { api, download, errMsg } from "../api";
import { ErrorAlert, fmtDate } from "../components";

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.all([api("/reports"), api("/scans")]);
      setReports(r);
      const done = s.filter((x) => x.status === "done");
      setScans(done);
      setScanId((cur) => cur || (done[0] ? String(done[0].id) : ""));
    } catch (e) { setError(errMsg(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function generate(e) {
    e.preventDefault();
    setBusy(true); setError("");
    try { await api("/reports", { method: "POST", body: { scan_id: Number(scanId) } }); await load(); }
    catch (err) { setError(errMsg(err)); } finally { setBusy(false); }
  }

  async function get(r) {
    try { await download(`/reports/${r.id}/download`, `netsentry-scan-${r.scan_id}-rapport-${r.id}.pdf`); }
    catch (err) { setError(errMsg(err)); }
  }

  return (
    <>
      <h1 className="h3 mb-3">Rapports</h1>
      <ErrorAlert error={error} />
      <form onSubmit={generate} className="row g-2 align-items-end mb-4">
        <div className="col-md-5">
          <label htmlFor="rs" className="form-label">Scan</label>
          <select id="rs" className="form-select" value={scanId} onChange={(e) => setScanId(e.target.value)}>
            {scans.map((s) => <option key={s.id} value={s.id}>#{s.id} : {s.target} ({s.profile}) {fmtDate(s.finished_at)}</option>)}
          </select>
        </div>
        <div className="col-md-3">
          <button className="btn btn-primary w-100" disabled={busy || !scanId}>{busy ? "Génération…" : "Générer le rapport PDF"}</button>
        </div>
      </form>
      <table className="table align-middle">
        <thead><tr><th>#</th><th>Scan</th><th>Généré le</th><th>Taille</th><th></th></tr></thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.id}>
              <td>{r.id}</td><td>#{r.scan_id}</td><td>{fmtDate(r.created_at)}</td>
              <td>{Math.round(r.size_bytes / 1024)} Ko</td>
              <td><button className="btn btn-sm btn-outline-primary" onClick={() => get(r)}>Télécharger</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}