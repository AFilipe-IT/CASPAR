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

/* Os mesmos 8 destinos de sempre, agora agrupados pelo que a pessoa está a
   fazer: ver o estado, avaliar, gerir o que a ferramenta sabe. Os grupos são
   só um rótulo visual — nenhuma rota mudou. */
const NAV_GROUPS = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
      { to: "/watch", label: "Watch", icon: Eye },
    ],
  },
  {
    label: "Assess",
    items: [
      { to: "/assessment", label: "Assessment", icon: ClipboardCheck },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    label: "Knowledge",
    items: [
      { to: "/knowledge-base", label: "Knowledge Base", icon: BookOpen },
      { to: "/plugins", label: "Plugins", icon: Puzzle },
      { to: "/build", label: "Build", icon: Hammer },
    ],
  },
  {
    label: "System",
    items: [{ to: "/settings", label: "Settings", icon: Settings }],
  },
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
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className={styles.group}>
            <div className={styles.groupLabel}>{group.label}</div>
            {group.items.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  [styles.navItem, isActive ? styles.active : ""].join(" ")
                }
              >
                <Icon size={18} strokeWidth={2} />
                {label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className={styles.footer}>
        <span className={styles.version}>v0.1.0</span>
      </div>
    </aside>
  );
}
