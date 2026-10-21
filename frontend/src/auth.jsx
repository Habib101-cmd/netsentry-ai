import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, clearTokens, getRefreshToken, hasRefresh, refreshSession, setAuthLostHandler, setTokens } from "./api";

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setAuthLostHandler(() => setUser(null));
    (async () => {
      if (hasRefresh()) {
        try {
          await refreshSession();
          setUser(await api("/auth/me"));
        } catch {
          clearTokens();
        }
      }
      setLoading(false);
    })();
  }, []);

  const login = useCallback(async (username, password) => {
    const d = await api("/auth/login", { method: "POST", body: { username, password }, auth: false });
    setTokens(d.access_token, d.refresh_token);
    const me = await api("/auth/me");
    setUser(me);
    return me;
  }, []);

  const logout = useCallback(async () => {
    const rt = getRefreshToken();
    try {
      if (rt) await api("/auth/logout", { method: "POST", body: { refresh_token: rt } });
    } catch { /* on se déconnecte quand même */ }
    clearTokens();
    setUser(null);
  }, []);

  const forget = useCallback(() => {
    clearTokens();
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, forget }}>
      {children}
    </AuthContext.Provider>
  );
}