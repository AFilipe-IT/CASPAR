import type { RouteObject } from "react-router-dom";
import { DashboardPage } from "@/pages/DashboardPage";
import { AssessmentPage } from "@/pages/AssessmentPage";
import { KnowledgeBasePage } from "@/pages/KnowledgeBasePage";
import { PluginsPage } from "@/pages/PluginsPage";
import { BuildPage } from "@/pages/BuildPage";
import { WatchPage } from "@/pages/WatchPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SettingsPage } from "@/pages/SettingsPage";

export const routes: RouteObject[] = [
  { path: "/", element: <DashboardPage /> },
  { path: "/assessment", element: <AssessmentPage /> },
  { path: "/knowledge-base", element: <KnowledgeBasePage /> },
  { path: "/plugins", element: <PluginsPage /> },
  { path: "/build", element: <BuildPage /> },
  { path: "/watch", element: <WatchPage /> },
  { path: "/reports", element: <ReportsPage /> },
  { path: "/settings", element: <SettingsPage /> },
];
