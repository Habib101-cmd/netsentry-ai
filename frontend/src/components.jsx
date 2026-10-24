export const LEVELS = ["critical", "high", "medium", "low", "info"];
export const LEVEL_FR = { critical: "Critique", high: "Élevé", medium: "Moyen", low: "Faible", info: "Info" };
const LEVEL_CLASS = {
  critical: "bg-danger",
  high: "bg-warning text-dark",
  medium: "bg-info text-dark",
  low: "bg-secondary",
  info: "bg-light text-dark border",
};

// Le niveau est toujours écrit en toutes lettres : la couleur seule ne porte pas l'information.
export function LevelBadge({ level }) {
  return <span className={`badge ${LEVEL_CLASS[level] || "bg-secondary"}`}>{LEVEL_FR[level] || level}</span>;
}

export const SCAN_STATUS_FR = {
  pending: "En attente", running: "En cours", done: "Terminé", failed: "Échoué", cancelled: "Annulé",
};
const SCAN_CLASS = {
  pending: "bg-secondary", running: "bg-primary", done: "bg-success", failed: "bg-danger", cancelled: "bg-dark",
};
export function ScanStatus({ status }) {
  return <span className={`badge ${SCAN_CLASS[status] || "bg-secondary"}`}>{SCAN_STATUS_FR[status] || status}</span>;
}

export const FINDING_STATUS_FR = {
  new: "Nouveau", in_progress: "En cours d'analyse", fixed: "Corrigé", accepted: "Accepté",
};

export function ErrorAlert({ error }) {
  if (!error) return null;
  return <div className="alert alert-danger" role="alert">{error}</div>;
}

export function fmtDate(s) {
  return s ? new Date(s).toLocaleString("fr-FR") : "-";
}
export const LEVEL_COLOR = {
  critical: "#dc3545", high: "#fd7e14", medium: "#ffc107", low: "#6c757d", info: "#adb5bd", none: "#198754",
};