import type React from "react";
import {
  Server,
  Feather,
  Container,
  Database,
  TerminalSquare,
  Cloud,
  Boxes,
  FileCode,
  Globe,
  AppWindow,
  Router,
} from "lucide-react";
import styles from "./ServiceIcon.module.css";

/* Um glifo e uma cor por tecnologia. As listas de serviços eram uma coluna de
   texto onde todas as linhas começavam igual; o ícone é o que deixa encontrar
   o Nginx no meio de cinco apaches sem ler nome nenhum.

   Nota: são cores de marca da tecnologia, não de severidade. O score ao lado
   é que diz se está bem ou mal — daí o ícone do Redis ser sempre vermelho,
   mesmo com score 0. */
const ICONS: Record<string, { icon: typeof Server; className: string }> = {
  "apache-httpd": { icon: Feather, className: styles.apache },
  nginx: { icon: Globe, className: styles.nginx },
  docker: { icon: Container, className: styles.docker },
  dockerfile: { icon: FileCode, className: styles.docker },
  kubernetes: { icon: Boxes, className: styles.kubernetes },
  mysql: { icon: Database, className: styles.mysql },
  postgresql: { icon: Database, className: styles.postgres },
  redis: { icon: Database, className: styles.redis },
  ssh: { icon: TerminalSquare, className: styles.ssh },
  ubuntu: { icon: Server, className: styles.ubuntu },
  tomcat: { icon: Server, className: styles.tomcat },
  "azure-iac": { icon: Cloud, className: styles.azure },
};

/* O catálogo traz 37 alvos que não estão instalados — `ubuntu2204`, `rhel9`,
   `windows-server-2022`, `cisco-ios` — e por nome exacto caíam todos no mesmo
   quadrado cinzento. Aqui é a *família* que decide, por ordem: um SO é um
   servidor, uma base de dados é um cilindro, um equipamento de rede é um
   router. Ordem importa — "oracle-linux-8" tem de bater em linux antes de
   bater em oracle, senão vestia-se de base de dados. */
const FAMILIES: [RegExp, { icon: typeof Server; className: string }][] = [
  [/^apache($|-)/, { icon: Feather, className: styles.apache }],
  [/ubuntu|debian/, { icon: Server, className: styles.ubuntu }],
  [/rhel|oracle-linux|sles|centos|fedora/, { icon: Server, className: styles.redhat }],
  [/windows|^iis/, { icon: AppWindow, className: styles.windows }],
  [/macos/, { icon: Server, className: styles.apple }],
  [/aix|solaris/, { icon: Server, className: styles.unix }],
  [/mongo|mariadb|sqlserver|oracle-db|db2|epas|postgres/, { icon: Database, className: styles.db }],
  [/cisco|juniper|arista|palo-alto|f5-|ndm|fw$/, { icon: Router, className: styles.network }],
  [/openshift|rke2|kube/, { icon: Boxes, className: styles.kubernetes }],
  [/jboss/, { icon: Server, className: styles.tomcat }],
];

interface ServiceIconProps {
  /** O nome do alvo tal como vem da API (`apache-httpd`, `nginx`, …). */
  name: string;
  size?: number;
}

export function ServiceIcon({ name, size = 16 }: ServiceIconProps) {
  // Nome exacto primeiro, família depois, genérico em último: um alvo novo
  // entra sem partir a lista, e um alvo de uma família conhecida já entra
  // vestido a rigor sem precisar de linha própria.
  const key = name.toLowerCase();
  const entry =
    ICONS[key] ??
    FAMILIES.find(([re]) => re.test(key))?.[1] ??
    { icon: Server, className: styles.generic };
  const Glyph = entry.icon;
  return (
    <span
      className={[styles.badge, entry.className].join(" ")}
      style={{ "--glyph": `${size}px` } as React.CSSProperties}
      aria-hidden
    >
      <Glyph size={size} />
    </span>
  );
}
