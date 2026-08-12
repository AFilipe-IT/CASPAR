import type { ReactNode } from "react";
import styles from "./Table.module.css";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  width?: string;
}

interface TableProps<T> {
  columns: Column<T>[];
  rows: T[];
  /** O índice serve para desempatar linhas cuja identidade não é única — ver
   *  a nota em FindingsTable, onde o id é o da regra e não o da ocorrência. */
  rowKey: (row: T, index: number) => string;
  onRowClick?: (row: T) => void;
  /** Limita a altura e rola dentro do cartão, com o cabeçalho fixo. Para as
   *  listas sem tecto natural — os Relatórios trazem 100 avaliações, as regras
   *  de um benchmark chegam às 220. */
  capped?: boolean;
}

export function Table<T>({ columns, rows, rowKey, onRowClick, capped }: TableProps<T>) {
  return (
    <div className={[styles.wrap, capped ? styles.wrapCapped : ""].join(" ").trim()}>
      <table className={styles.table}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} style={{ width: col.width }}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr
              key={rowKey(row, index)}
              className={onRowClick ? styles.clickable : undefined}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map((col) => (
                <td key={col.key}>{col.render(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
