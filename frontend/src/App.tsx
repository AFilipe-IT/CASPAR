import { useLocation, useRoutes } from "react-router-dom";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { ErrorBoundary } from "@/components/layout/ErrorBoundary";
import { routes } from "@/routes";

export function App() {
  const element = useRoutes(routes);
  const location = useLocation();

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-main">
        <Topbar />
        {/* A fronteira envolve só o conteúdo: se uma página falhar, a barra
            lateral fica montada e dá para sair dela. A chave é a rota, para
            que navegar limpe o erro. */}
        <main className="app-content">
          <ErrorBoundary resetKey={location.pathname}>{element}</ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
