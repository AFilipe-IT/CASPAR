import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ClipboardCheck,
  BookOpen,
  Puzzle,
  Hammer,
  Eye,
  FileText,
  Settings,
  ShieldCheck,
} from "lucide-react";
import styles from "./Sidebar.module.css";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/assessment", label: "Assessment", icon: ClipboardCheck },
  { to: "/knowledge-base", label: "Knowledge Base", icon: BookOpen },
  { to: "/plugins", label: "Plugins", icon: Puzzle },
  { to: "/build", label: "Build", icon: Hammer },
  { to: "/watch", label: "Watch", icon: Eye },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  return (
    <aside className={styles.sidebar}>
      <div className={styles.brand}>
        <span className={styles.brandIcon}>
          <ShieldCheck size={22} />
        </span>
        <div>
          <div className={styles.brandName}>CVM</div>
          <div className={styles.brandSub}>Configuration Vulnerability Meter</div>
        </div>
      </div>

      <nav className={styles.nav}>
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => [styles.navItem, isActive ? styles.active : ""].join(" ")}
          >
            <Icon size={18} strokeWidth={2} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className={styles.footer}>
        <span className={styles.version}>v0.1.0</span>
      </div>
    </aside>
  );
}
