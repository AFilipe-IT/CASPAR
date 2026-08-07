import { BookOpen } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";
import type { Benchmark } from "@/api/types";
import styles from "./BenchmarkList.module.css";

interface BenchmarkListProps {
  benchmarks: Benchmark[];
  selected: string | null;
  onSelect: (name: string) => void;
}

export function BenchmarkList({ benchmarks, selected, onSelect }: BenchmarkListProps) {
  if (benchmarks.length === 0) {
    return <EmptyState icon={<BookOpen size={22} />} title="No benchmarks installed" />;
  }

  return (
    <ul className={styles.list}>
      {benchmarks.map((b) => (
        <li key={b.name}>
          <button
            className={[styles.item, selected === b.name ? styles.active : ""].join(" ")}
            onClick={() => onSelect(b.name)}
          >
            <span className={styles.name}>{b.name}</span>
            <span className={styles.meta}>{b.benchmark_source} · v{b.version}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}
