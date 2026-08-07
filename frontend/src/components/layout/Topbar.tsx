import { Moon, Sun, Circle } from "lucide-react";
import { useTheme } from "@/context/ThemeContext";
import { useHealth } from "@/api/health";
import styles from "./Topbar.module.css";

export function Topbar() {
  const { theme, toggleTheme } = useTheme();
  const { data: health, isError } = useHealth();

  const live = !isError && health?.status === "ok";

  return (
    <header className={styles.topbar}>
      <div className={styles.status}>
        <Circle
          size={9}
          fill={live ? "var(--ok)" : "var(--sev-critical)"}
          color={live ? "var(--ok)" : "var(--sev-critical)"}
        />
        <span className={styles.statusText}>
          {live ? "API connected" : "API unreachable"}
        </span>
        {live && health && (
          <span className={styles.statusMeta}>
            · {health.plugins_registered} plugins registered
          </span>
        )}
      </div>

      <button
        className={styles.themeToggle}
        onClick={toggleTheme}
        aria-label="Toggle theme"
        title="Toggle theme"
      >
        {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
      </button>
    </header>
  );
}
