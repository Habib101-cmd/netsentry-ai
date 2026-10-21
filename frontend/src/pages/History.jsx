import { useEffect, useState } from "react";
import { api, errMsg } from "../api";
import { ErrorAlert, LEVELS, LEVEL_FR, LevelBadge, fmtDate } from "../components";

function Block({ title, items, render }) {
  return (
    <section className="mb-4">
      <h2 className="h5">{title} <span className="badge bg-secondary">{items.length}</span></h2>
      {items.length === 0 ? <p className="text-muted">Aucun.</p> : (
        <ul className="list-group">
          {items.map((it, i) => <li key={i} className="list-group-item">{render(it)}</li>)}
        </ul>
      )}
    </section>
  );
}

const sig = (x) => [x.product, x.version].filter(Boolean).join(" ") || x.name || "inconnu";
const delta = (a, b) => (b - a > 0 ? `+${b - a}` : String(b - a));

export default function History() {
  const [scans, setScans] = useState([]);
  const [base, setBase] = useState("");
  const [other, setOther] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const done = (await api("/scans")).filter((s) => s.status === "done");
        setScans(done);
        if (done.length >= 2) { setOther(String(done[0].id)); setBase(String(done[1].id)); }
      } catch (e) { setError(errMsg(e)); }
    })();
  }, []);

  async function compare(e) {
    e.preventDefault();
    setError(""); setResult(null);
    try { setResult(await api(`/scans/${base}/compare/${other}`)); } catch (err) { setError(errMsg(err)); }
  }

  const label = (s) => `#${s.id} : ${s.target} (${s.profile}) ${fmtDate(s.finished_at)}`;
  const f = result?.findings;
  const sb = result?.summary.base;
  const so = result?.summary.other;

  return (
    <>
      <h1 className="h3 mb-3">Historique et comparaison</h1>
      <ErrorAlert error={error} />
      <form onSubmit={compare} className="row g-2 align-items-end mb-4">
        <div className="col-md-4">
          <label htmlFor="b" className="form-label">Scan de référence (avant)</label>
          <select id="b" className="form-select" value={base} onChange={(e) => setBase(e.target.value)}>
            <option value="">Choisir…</option>
            {scans.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}
          </select>
        </div>
        <div className="col-md-4">
          <label htmlFor="o" className="form-label">Scan comparé (après)</label>
          <select id="o" className="form-select" value={other} onChange={(e) => setOther(e.target.value)}>
            <option value="">Choisir…</option>
            {scans.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}
          </select>
        </div>
        <div className="col-md-2">
          <button className="btn btn-primary w-100" disabled={!base || !other || base === other}>Comparer</button>
        </div>
      </form>
      {scans.length < 2 && <p className="text-muted">Il faut au moins deux scans terminés pour comparer.</p>}

      {result && (
        <>
          {result.notes.map((n, i) => <div key={i} className="alert alert-warning" role="status">{n}</div>)}
          <table className="table w-auto mb-4">
            <caption className="caption-top">Évolution</caption>
            <thead><tr><th></th><th>Avant (#{result.base.id})</th><th>Après (#{result.other.id})</th><th>Écart</th></tr></thead>
            <tbody>
              <tr><td>Équipements actifs</td><td>{sb.hosts_up}</td><td>{so.hosts_up}</td><td>{delta(sb.hosts_up, so.hosts_up)}</td></tr>
              <tr><td>Constats</td><td>{sb.findings}</td><td>{so.findings}</td><td>{delta(sb.findings, so.findings)}</td></tr>
              <tr><td>Score cumulé</td><td>{sb.total_score}</td><td>{so.total_score}</td><td>{delta(sb.total_score, so.total_score)}</td></tr>
              {LEVELS.map((l) => (
                <tr key={l}><td>{LEVEL_FR[l]}</td><td>{sb.by_level[l]}</td><td>{so.by_level[l]}</td><td>{delta(sb.by_level[l], so.by_level[l])}</td></tr>
              ))}
            </tbody>
          </table>

          <Block title="Nouveaux équipements" items={result.new_hosts}
            render={(h) => `${h.ip} : ports ouverts ${h.open_ports.join(", ") || "-"}`} />
          <Block title="Équipements qui ne répondent plus" items={result.missing_hosts}
            render={(h) => (<>{h.ip}<div className="small text-muted">{h.note}</div></>)} />
          <Block title="Nouveaux ports ouverts" items={result.new_ports}
            render={(x) => `${x.ip} : ${x.port}/${x.protocol} (${x.service || "inconnu"})`} />
          <Block title="Ports qui ne sont plus ouverts" items={result.closed_ports}
            render={(x) => `${x.ip} : ${x.port}/${x.protocol} (${x.service || "inconnu"})`} />
          <Block title="Changements de service ou de version" items={result.service_changes}
            render={(x) => `${x.ip} : ${x.port}/${x.protocol} : ${sig(x.before)} → ${sig(x.after)}`} />
          {f.compared && (
            <>
              <Block title="Nouveaux constats" items={f.new}
                render={(x) => (<><LevelBadge level={x.level} /> {x.title} : {x.ip} ({x.port}), score {x.score}</>)} />
              <Block title="Constats non observés lors du second scan" items={f.resolved}
                render={(x) => (<><LevelBadge level={x.level} /> {x.title} : {x.ip} ({x.port})</>)} />
              <Block title="Constats dont le score a changé" items={f.changed}
                render={(x) => `${x.title} : ${x.ip} (${x.port}) : score ${x.score_before} → ${x.score_after}`} />
            </>
          )}
        </>
      )}
    </>
  );
}