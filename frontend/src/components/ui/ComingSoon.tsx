import type { ReactNode } from "react";
import { Sparkles } from "lucide-react";
import { Card } from "./Card";
import styles from "./ComingSoon.module.css";

interface ComingSoonProps {
  icon: ReactNode;
  title: string;
  description: string;
  phase: string;
  capabilities: string[];
}

export function ComingSoon({ icon, title, description, phase, capabilities }: ComingSoonProps) {
  return (
    <Card>
      <div className={styles.wrap}>
        <div className={styles.iconLarge}>{icon}</div>
        <h2 className={styles.title}>{title}</h2>
        <p className={styles.description}>{description}</p>
        <ul className={styles.list}>
          {capabilities.map((cap) => (
            <li key={cap}>{cap}</li>
          ))}
        </ul>
        <span className={styles.phase}>
          <Sparkles size={14} />
          Landing in {phase}
        </span>
      </div>
    </Card>
  );
}
