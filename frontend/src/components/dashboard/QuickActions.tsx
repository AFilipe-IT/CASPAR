import { useNavigate } from "react-router-dom";
import { PlayCircle, Eye, FileOutput, Puzzle } from "lucide-react";
import { Button } from "@/components/ui/Button";
import styles from "./QuickActions.module.css";

export function QuickActions() {
  const navigate = useNavigate();

  return (
    <div className={styles.grid}>
      <Button variant="primary" icon={<PlayCircle size={16} />} onClick={() => navigate("/assessment")}>
        New Assessment
      </Button>
      <Button icon={<Eye size={16} />} onClick={() => navigate("/watch")}>
        Start Monitoring
      </Button>
      <Button icon={<FileOutput size={16} />} onClick={() => navigate("/reports")}>
        Generate Report
      </Button>
      <Button icon={<Puzzle size={16} />} onClick={() => navigate("/plugins")}>
        Manage Plugins
      </Button>
    </div>
  );
}
