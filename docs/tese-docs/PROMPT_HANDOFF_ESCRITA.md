# Prompt de handoff — escrita da dissertação em PT-PT

> Cola o texto abaixo (a partir de "Vou escrever...") numa nova conversa para
> avançar com a escrita da dissertação em português de Portugal.

---

Vou escrever, em português de portugal, um documento de trabalho para a dissertação de mestrado sobre o CVM — *Configuration Vulnerability Meter* (a tradução para inglês fica para depois, noutra sessão — não escrevas em inglês agora).

Contexto: a tese em inglês já existe e está a compilar (LaTeX em `tese/`, 7 capítulos, 117 páginas). Este novo documento em PT-PT NÃO é uma tradução mecânica dela nem vai substituí-la — é prosa nova, pensada para um leitor português, que uso como rascunho de trabalho antes de eu próprio traduzir para inglês mais tarde.

Material-fonte que vou anexar a esta conversa (não tentes adivinhar conteúdo que não te dei; se eu ainda não tiver anexado um dos ficheiros abaixo quando precisares dele, pede-mo):
1. **DISSERTACAO_REFERENCIA.md** — documento de referência único em PT-PT com a contribuição científica, funcionalidades, arquitectura, resultados de validação (20/20 concordância CCE/DISA, 96/96 recall, 100% precisão/F1 em dez alvos, 29/30 estabilidade build-time, comparação com Trivy/OpenSCAP) e as obrigações de resposta aos revisores do INForum. Já está atualizado com os IC de Wilson a 95%, a admissão de falta de análise de sensibilidade, e o gap de conflito CIS/STIG. Atenção a uma descontinuidade deliberada nesse documento: §4 congela as medições de 2026-07-09 (11 alvos) enquanto §2.2 descreve o estado actual (12 alvos, com o `postgresql` acrescentado depois); não é contradição e não deve ser "corrigido" — são momentos diferentes, e o motor de scoring não mudou entretanto.
2. Os capítulos em inglês da tese, um ficheiro `.tex` por capítulo (Chapter1_Introduction, Chapter2_Background, Chapter3_RelatedWork, Chapter4_AEGIS, Chapter5_AEGIS, Chapter6_Evaluation, Chapter7_Conclusion) — servem de base de conteúdo e de argumento já validado (inclui a distinção validade interna/externa, a distinção decisões Classe 1 vs Classe 2, a fundamentação build-time/runtime) mas o texto inglês NÃO deve ser traduzido literalmente frase a frase; o objectivo é reescrever com fluência natural de português europeu, não decalcar sintaxe inglesa.

Regras para a escrita:
- Português de Portugal (não brasileiro): "está a fazer" não "está fazendo", "ficheiro" não "arquivo", "camada" não "layer" traduzido à letra onde já existe termo comum, etc.
- Tom: académico mas sem inflação — evita "demonstra"/"garante"/"prova que" quando o resultado é evidência dentro de um corpus controlado, não uma lei geral. Distingue sempre validade interna (fidelidade da implementação ao standard, sobre dados onde a fonte da verdade coincide com os dados de teste por construção) de validade externa (desempenho em produção não curada) quando apresentares os números de validação.
- Não inventes números, citações ou nomes de secções que não estejam no material-fonte fornecido. Se precisares de um número e não o tiveres, pergunta em vez de estimar.
- Nomenclatura: **CVM** (*Configuration Vulnerability Meter*) é o nome da metodologia/contribuição científica (usa-o quando falares do argumento, da separação build-time/runtime, da generalização). **CASPAR** é o nome real da ferramenta/CLI que a implementa (Configuration Analysis, Security Posture Assessment and Reporting) — usa-o quando descreveres comandos, código ou a prova de conceito concreta. O comando do terminal é `caspar` (ex.: `caspar promote`, `caspar plugin fetch`), não `sca`. Não inventes nem uses "AMiSA", "AEGIS" nem "sca" — são nomes de fases anteriores do projecto e já não se usam na prosa (o "AEGIS" que resta em `Chapter4_AEGIS.tex` é só o nome do ficheiro).
- CCSS mantém-se sempre "CCSS" (nome do standard, não se traduz).

Vamos avançar capítulo a capítulo (ou secção a secção, como preferires organizar). Achas que o material que vou dar é suficiente para começares, ou precisas de mais alguma coisa de mim antes do primeiro capítulo?
