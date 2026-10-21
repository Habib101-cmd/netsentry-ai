import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, errMsg } from "../api";
import { ErrorAlert, LEVELS, LEVEL_FR, ScanStatus, fmtDate } from "../components";

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const [summary, scans, hosts] = await Promise.all([
          api("/findings/summary"), api("/scans"), api("/hosts"),
        ]);
        setData({ summary, scans, hosts });
      } catch (e) {
        setError(errMsg(e));
      }
    })();
  }, []);

  if (error) return <ErrorAlert error={error} />;
  if (!data) return <p>Chargement…</p>;
  const { summary, scans, hosts } = data;
  const lastDone = scans.find((s) => s.status === "done");

  return (
    <>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h1 className="h3 m-0">Tableau de bord</h1>
        <Link to="/scans" className="btn btn-primary">Lancer un scan</Link>
      </div>
      <p className="text-muted">
        {lastDone ? `Dernier scan terminé : #${lastDone.id} (${fmtDate(lastDone.finished_at)})` : "Aucun scan terminé pour l'instant."}
      </p>
      <div className="row g-3 mb-4">
        <div className="col-6 col-md-3 col-xl">
          <div className="card text-center"><div className="card-body">
            <div className="display-6">{hosts.length}</div><div>Machines</div>
          </div></div>
        </div>
        <div className="col-6 col-md-3 col-xl">
          <div className="card text-center"><div className="card-body">
            <div className="display-6">{scans.length}</div><div>Scans</div>
          </div></div>
        </div>
        {LEVELS.map((l) => (
          <div key={l} className="col-6 col-md-3 col-xl">
            <div className="card text-center"><div className="card-body">
              <div className="display-6">{summary.by_level[l] ?? 0}</div><div>{LEVEL_FR[l]}</div>
            </div></div>
          </div>
        ))}
      </div>
      <h2 className="h5">Derniers scans</h2>
      <table className="table">
        <thead><tr><th>#</th><th>Cible</th><th>Profil</th><th>Statut</th><th>Date</th></tr></thead>
        <tbody>
          {scans.slice(0, 5).map((s) => (
            <tr key={s.id}><td>{s.id}</td><td>{s.target}</td><td>{s.profile}</td>
              <td><ScanStatus status={s.status} /></td><td>{fmtDate(s.created_at)}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}