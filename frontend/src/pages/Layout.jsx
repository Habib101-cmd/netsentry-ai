import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";

export default function Layout() {
  const { user, logout } = useAuth();
  const link = ({ isActive }) => "nav-link" + (isActive ? " active fw-semibold" : "");
  return (
    <>
      <a href="#main" className="visually-hidden-focusable">Aller au contenu</a>
      <nav className="navbar navbar-expand navbar-dark bg-dark px-3" aria-label="Navigation principale">
        <span className="navbar-brand">NetSentry AI</span>
        <ul className="navbar-nav me-auto">
          <li className="nav-item"><NavLink end to="/" className={link}>Tableau de bord</NavLink></li>
          <li className="nav-item"><NavLink to="/scans" className={link}>Scans</NavLink></li>
          <li className="nav-item"><NavLink to="/hosts" className={link}>Équipements</NavLink></li>
          <li className="nav-item"><NavLink to="/findings" className={link}>Constats</NavLink></li>
          <li className="nav-item"><NavLink to="/history" className={link}>Historique</NavLink></li>
          <li className="nav-item"><NavLink to="/reports" className={link}>Rapports</NavLink></li>
          <li className="nav-item"><NavLink to="/map" className={link}>Carte</NavLink></li>
          <li className="nav-item"><NavLink to="/timeline" className={link}>Chronologie</NavLink></li>
          <li className="nav-item"><NavLink to="/anomalies" className={link}>Anomalies</NavLink></li>
          {user.role === "admin" && (
            <li className="nav-item"><NavLink to="/admin" className={link}>Administration</NavLink></li>
          )}
        </ul>
        <span className="navbar-text me-3">
          {user.username} ({user.role === "admin" ? "administrateur" : "analyste"})
        </span>
        <button className="btn btn-outline-light btn-sm" onClick={logout}>Déconnexion</button>
      </nav>
      <main id="main" className="container-fluid py-4"><Outlet /></main>
    </>
  );
}