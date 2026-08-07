import { useRoutes } from "react-router-dom";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { routes } from "@/routes";

export function App() {
  const element = useRoutes(routes);

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-main">
        <Topbar />
        <main className="app-content">{element}</main>
      </div>
    </div>
  );
}
