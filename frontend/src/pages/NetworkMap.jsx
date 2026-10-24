import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import cytoscape from "cytoscape";
import { api, errMsg } from "../api";
import { ErrorAlert, LEVEL_COLOR, LEVEL_FR, fmtDate } from "../components";

const STYLE = [
  { selector: "node[type='host']", style: {
    label: "data(label)", "text-wrap": "wrap", "text-valign": "bottom", "text-margin-y": 6, "font-size": 11,
    "background-color": "data(color)", width: 34, height: 34, "border-width": 2, "border-color": "#212529" } },
  { selector: "node[type='scanner']", style: {
    shape: "diamond", "background-color": "#0d6efd", label: "data(label)", "text-valign": "bottom",
    "text-margin-y": 6, "font-size": 12, width: 40, height: 40, "border-width": 2, "border-color": "#212529" } },
  { selector: "node[type='subnet']", style: {
    shape: "round-rectangle", "background-color": "#6c757d", "background-opacity": 0.06, "border-style": "dashed",
    "border-width": 2, "border-color": "#6c757d", label: "data(label)", "text-valign": "top", "font-size": 12, padding: 24 } },
  { selector: "edge[kind='observed']", style: { "line-style": "solid", width: 2, "line-color": "#212529", "curve-style": "bezier" } },
  { selector: "edge[kind='assumed']", style: { "line-style": "dashed", width: 2, "line-color": "#6c757d", "curve-style": "bezier" } },
  { selector: ":selected", style: { "overlay-color": "#0d6efd", "overlay-opacity": 0.2 } },
];

function toElements(map) {
  const nodes = map.nodes.map((n) => {
    const data = { ...n };
    if (n.type === "host") {
      data.color = LEVEL_COLOR[n.worst_level || "none"];
      data.label = `${n.ip}\n${n.open_ports} port(s) · ${n.worst_level ? LEVEL_FR[n.worst_level] : "aucun constat"}`;
    }
    return { data };
  });
  return [...nodes, ...map.edges.map((e) => ({ data: { ...e } }))];
}

export default function NetworkMap() {
  const [scans, setScans] = useState([]);
  const [scanId, setScanId] = useState("");
  const [map, setMap] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const box = useRef(null);

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
      try { setMap(await api(`/scans/${scanId}/map`)); setSelected(null); setError(""); }
      catch (e) { setError(errMsg(e)); }
    })();
  }, [scanId]);

  useEffect(() => {
    if (!map || !box.current) return undefined;
    const cy = cytoscape({
      container: box.current, elements: toElements(map), style: STYLE,
      layout: { name: "cose", animate: false, padding: 30 }, minZoom: 0.3, maxZoom: 3,
    });
    cy.on("tap", "node[type='host']", (evt) => setSelected(evt.target.data()));
    cy.on("tap", "edge", (evt) => setSelected(evt.target.data()));
    cy.on("tap", (evt) => { if (evt.target === cy) setSelected(null); });
    return () => cy.destroy();
  }, [map]);

  const hostNodes = map ? map.nodes.filter((n) => n.type === "host") : [];

  return (
    <>
      <h1 className="h3 mb-3">Carte du réseau</h1>
      <ErrorAlert error={error} />
      <div className="mb-3" style={{ maxWidth: 420 }}>
        <label htmlFor="mapscan" className="form-label">Scan</label>
        <select id="mapscan" className="form-select" value={scanId} onChange={(e) => setScanId(e.target.value)}>
          {scans.map((s) => <option key={s.id} value={s.id}>#{s.id} : {s.target} ({s.profile}) {fmtDate(s.finished_at)}</option>)}
        </select>
      </div>
      {map && (
        <>
          <div className="alert alert-info" role="note">
            {map.notes.map((n, i) => <p key={i} className="mb-1">{n}</p>)}
          </div>
          <p className="small">
            <span style={{ display: "inline-block", width: 40, borderTop: "3px solid #212529", verticalAlign: "middle" }} /> relation observée
            {" · "}
            <span style={{ display: "inline-block", width: 40, borderTop: "3px dashed #6c757d", verticalAlign: "middle" }} /> relation supposée
            {" · "}◆ scanner · cercle : équipement (couleur = niveau de risque le plus élevé, toujours écrit en toutes lettres)
          </p>
          <div className="row g-3">
            <div className="col-lg-9">
              <div ref={box} role="img" aria-label={`Carte de ${hostNodes.length} équipements du scan ${scanId}. Une liste équivalente suit la carte.`}
                style={{ height: 560, border: "1px solid #adb5bd", borderRadius: 6 }} />
            </div>
            <div className="col-lg-3">
              <div className="card"><div className="card-body" aria-live="polite">
                {!selected && <p className="text-muted mb-0">Cliquez sur un équipement ou une relation.</p>}
                {selected?.type === "host" && (
                  <>
                    <h2 className="h6">{selected.ip}</h2>
                    <p className="mb-1">{selected.open_ports} port(s) ouvert(s)</p>
                    <p className="mb-2">Risque le plus élevé : {selected.worst_level ? LEVEL_FR[selected.worst_level] : "aucun constat"}</p>
                    <Link to={`/hosts/${selected.host_id}`}>Voir les détails</Link>
                  </>
                )}
                {selected?.reason && (
                  <>
                    <h2 className="h6">{selected.kind === "observed" ? "Relation observée" : "Relation supposée"}</h2>
                    <p className="mb-0">{selected.reason}</p>
                  </>
                )}
              </div></div>
            </div>
          </div>
          <h2 className="h5 mt-4">Équipements (liste équivalente à la carte)</h2>
          <table className="table table-sm">
            <thead><tr><th>IP</th><th>Ports ouverts</th><th>Risque le plus élevé</th><th></th></tr></thead>
            <tbody>
              {hostNodes.map((n) => (
                <tr key={n.id}><td>{n.ip}</td><td>{n.open_ports}</td>
                  <td>{n.worst_level ? LEVEL_FR[n.worst_level] : "aucun constat"}</td>
                  <td><Link to={`/hosts/${n.host_id}`}>Détails</Link></td></tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {!map && !error && <p className="text-muted">Aucun scan terminé.</p>}
    </>
  );
}