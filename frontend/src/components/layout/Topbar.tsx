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
      {/* O cabeçalho só mostra o que é verdade: o CASPAR não tem contas nem
          notificações, e um avatar ou um sino com um "3" seriam decoração a
          fingir estado. O estado da API é real e é o que importa aqui — se
          estiver em baixo, nada do resto da consola significa alguma coisa. */}
      <div
        className={[styles.status, live ? styles.statusOk : styles.statusDown].join(" ")}
      >
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

      <div className={styles.actions}>
        <button
          className={styles.iconButton}
          onClick={toggleTheme}
          aria-label="Toggle theme"
          title="Toggle theme"
        >
          {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
        </button>
      </div>
    </header>
  );
}
