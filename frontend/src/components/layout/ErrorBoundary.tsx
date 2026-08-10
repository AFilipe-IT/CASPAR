import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

interface Props {
  /** Muda quando a rota muda: repõe a fronteira ao navegar. */
  resetKey?: string;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Impede que um erro de render numa página derrube a consola inteira.
 *
 * Sem isto, uma excepção em qualquer página desmontava toda a árvore — o
 * `App` inclusive — e o que sobrava era um ecrã escuro que não recuperava
 * nem mudando a URL, porque já não havia router montado para reagir. Foi o
 * que aconteceu com o `PluginsPage` a ler `data.installed.length` de uma
 * resposta sem `installed`.
 *
 * A fronteira fica *dentro* do shell (à volta do conteúdo, não do `App`),
 * para que a barra lateral continue montada e navegável enquanto uma página
 * está em erro. O `resetKey` limpa o erro na mudança de rota: caso
 * contrário, uma página falhada mantinha a fronteira aberta e as outras
 * deixavam de renderizar.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // A consola do browser é o único sítio onde isto é diagnosticável em
    // produção — o painel mostra a mensagem, mas não a pilha.
    console.error("Erro ao renderizar a página:", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div role="alert" style={{ padding: "2rem", maxWidth: "44rem" }}>
        <h2
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            marginBottom: "0.75rem",
          }}
        >
          <AlertTriangle size={20} aria-hidden="true" />
          Esta página não conseguiu abrir
        </h2>
        <p style={{ marginBottom: "1rem" }}>
          O resto da consola continua a funcionar — escolha outra secção na barra
          lateral, ou recarregue a página.
        </p>
        <pre
          style={{
            overflowX: "auto",
            padding: "0.75rem",
            borderRadius: "6px",
            fontSize: "0.85rem",
            background: "var(--surface-2, rgba(127,127,127,0.12))",
          }}
        >
          {error.message}
        </pre>
      </div>
    );
  }
}
