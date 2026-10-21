const BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
let accessToken = null; // en mémoire uniquement
let onAuthLost = () => {};
let refreshPromise = null;

export class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
    this.status = status;
    this.detail = detail;
  }
}

export function errMsg(e) {
  if (e instanceof ApiError) {
    if (Array.isArray(e.detail)) return e.detail.map((d) => d.msg).join(" ; ");
    return e.message;
  }
  return "Erreur réseau : l'API est-elle démarrée ?";
}

export const setAuthLostHandler = (fn) => {
  onAuthLost = fn;
};
export const getRefreshToken = () => sessionStorage.getItem("ns_refresh");
export const hasRefresh = () => !!getRefreshToken();
export function setTokens(access, refresh) {
  accessToken = access;
  if (refresh) sessionStorage.setItem("ns_refresh", refresh);
}
export function clearTokens() {
  accessToken = null;
  sessionStorage.removeItem("ns_refresh");
}

async function doRefresh() {
  const rt = getRefreshToken();
  if (!rt) throw new Error("no refresh token");
  const r = await fetch(`${BASE}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: rt }),
  });
  if (!r.ok) throw new Error("refresh failed");
  const d = await r.json();
  setTokens(d.access_token, d.refresh_token);
  return d;
}

// Une seule requête de refresh à la fois (le jeton est à usage unique côté serveur)
export function refreshSession() {
  if (!refreshPromise) {
    refreshPromise = doRefresh().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

export async function api(
  path,
  { method = "GET", body, auth = true, _retry = false } = {}
) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401 && auth && !_retry) {
    try {
      await refreshSession();
      return api(path, { method, body, auth, _retry: true });
    } catch {
      clearTokens();
      onAuthLost();
      throw new ApiError(401, "Session expirée");
    }
  }
  if (!r.ok) {
    let detail = r.statusText;
    try {
      const j = await r.json();
      detail = j.detail ?? detail;
    } catch {
      /* corps non JSON */
    }
    throw new ApiError(r.status, detail);
  }
  return r.status === 204 ? null : r.json();
}

// Téléchargement authentifié (utilisé à l'étape 9 : PDF, CSV, JSON)
export async function download(path, filename) {
  const doFetch = () =>
    fetch(`${BASE}${path}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  let r = await doFetch();
  if (r.status === 401) {
    await refreshSession();
    r = await doFetch();
  }
  if (!r.ok) throw new ApiError(r.status, "Téléchargement impossible");
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
