# Prompt para migração CASPAR → AEGIS

Copia e cola isto numa nova sessão de IA (com acesso ao filesystem, ex. Claude Code) a partir da pasta `/home/albertojf/`.

---

## Contexto

Existe um projeto chamado **CASPAR** em `/home/albertojf/caspar/`, já internamente renomeado para **AEGIS** (nome completo: `AEGIS-Automated-Evaluation-Governance-of-Infrastructure-Security---Security-Configuration-Assessment`; comando CLI: `sca`). O rename de código já está feito e testado (623/623 testes a passar) — o que falta é **criar o novo repositório limpo** copiando apenas o que é relevante.

## Objetivo

Criar uma nova pasta `/home/albertojf/AEGIS/` contendo **apenas** o conteúdo relevante do projeto, pronta para:
1. Ser testada e executada a partir desse repo (`pip install -e .`, `pytest`, `sca scan ...`, Docker).
2. Ser clonada/testada noutra máquina (portabilidade total — sem paths absolutos hardcoded que só existam na máquina atual, sem dependências de ficheiros fora do repo).
3. Servir de base para começar a escrever a dissertação (README/HANDOFF/DISSERTACAO_REFERENCIA equivalentes incluídos, tudo já em nome AEGIS).

**Não é um `git clone`/`cp -r` ingénuo.** É uma cópia seletiva — deixa para trás tudo o que é lixo, cache, ambiente virtual, ou material que o utilizador decidiu explicitamente não levar.

## O que VIAJA para `/home/albertojf/AEGIS/`

Cria a nova pasta como **um novo repositório git** (`git init` limpo — não copies o histórico do `.git/` do caspar; esta é uma decisão deliberada de começar historial novo no AEGIS) e copia para lá:

### Código e configuração do projeto (raiz do novo repo)
- `cli/`, `config_assessment/`, `scripts/`, `tests/`, `test_target/`
- `data/` (inclui `ccss_canonical.sql` — a seed DB canónica)
- `docker/` (a pasta já se chama `docker/aegis/` no caspar — traz o conteúdo, podes achatar para `docker/` diretamente no novo repo ou manter a estrutura `docker/aegis/`, o que fizer mais sentido)
- `docs/` (screenshots do README)
- `sources/` (benchmarks/STIGs usados pelo `plugin fetch` — pequeno, ~12MB)
- `nistir7502.pdf` (especificação CCSS — faz parte da base de conhecimento RAG, tem de viajar)
- `test_httpd.conf`, `test_nginx.conf` (fixtures de teste na raiz)
- `pyproject.toml`, `requirements.txt`, `install.sh`, `install-native.sh`, `docker-compose.yml`
- `.github/` (workflow de CI)
- `.dockerignore`, `.gitignore` (revê o `.gitignore` — algumas exclusões são específicas do caspar, ex. `caspar_inforum2026/`, `dissertacao/`, `FCUP_thesis_layout/`, `tese/`; substitui/limpa essas linhas já que essas pastas não existem no novo repo)
- `reports/` (só a pasta vazia com `.gitkeep`, não o conteúdo gerado)

### Documentação (raiz do novo repo)
- `README.md`, `GUIA_AEGIS.md`, `GUIA_TECNICO.md`, `GUIA_TESTE_MAQUINA.md`
- `HANDOFF.md`, `DISSERTACAO_REFERENCIA.md`, `VALIDACAO.md`, `AVALIACAO_FUNCIONAL.md`

Estes já estão todos em nome AEGIS/`sca` — não precisam de mais rename, só de cópia. **Revê rapidamente cada um depois de copiado à procura de paths absolutos do tipo `/home/albertojf/caspar/...`** (podem existir em exemplos de output/logs colados no texto) e substitui por `/home/albertojf/AEGIS/...` ou por um caminho relativo/genérico, para não confundir quem ler a documentação numa clonagem nova.

### Material de investigação (pasta dedicada — NÃO misturar com o código)
Cria uma pasta própria, por exemplo `research/` ou `material-fonte/`, e traz para lá:
- `documentosccss/`
- `CIS_Microsoft_Azure/`
- `caspar_inforum2026/` (mantém o nome desta pasta como está — é a submissão já feita ao INForum 2026, com esse nome real; não faz sentido renomear um artefacto histórico já submetido)
- `RELATORIO_CASPAR.docx` (mesma razão — mantém o nome, é um documento histórico)

## O que NÃO VIAJA (fica para trás, é "lixo" para este repo)

- `.venv/` — ambiente virtual, recria com `pip install -e .` no destino
- `.git/` — histórico do caspar; o AEGIS começa histórico git novo
- `.pytest_cache/`, `.ccss_cache/`, `__pycache__/`, `build/`, `*.egg-info/`
- `ccss.db` (DB de trabalho local gerada) e quaisquer `ccss-report-*`, `ccss_*.json`, `ccss_*.html`, `*.dashboard.html` na raiz — outputs de scans anteriores
- `reports/*.jsonl`, `reports/determinism_runs.jsonl` — outputs gerados (o script que os gera vai junto em `scripts/`, os dados não)
- `.claude/` — configuração local do harness, específica desta máquina/sessão
- `tese/`, `tese-pt/`, `FCUP_thesis_layout/`, `dissertacao/` — a dissertação será escrita de raiz no novo repo; nenhuma destas pastas viaja
- Qualquer `*.pyc`, `*.log`, ficheiros temporários

## Passos sugeridos para quem for executar isto

1. `mkdir -p /home/albertojf/AEGIS && cd /home/albertojf/AEGIS && git init`
2. Copiar cada item da lista "VIAJA" com `cp -r` (ou `rsync -a --exclude=...` a partir de `/home/albertojf/caspar/`), preservando a estrutura de pastas indicada.
3. Criar a pasta `research/` (ou nome à tua escolha) e mover para lá os 4 itens de material de investigação.
4. Rever e ajustar o `.gitignore` copiado, removendo as linhas que referenciam pastas que já não existem neste repo (`caspar_inforum2026/`, `documentosccss/`, `CIS_Microsoft_Azure/`, `dissertacao/`, `FCUP_thesis_layout/`, `tese/`) — ou simplificar essas exceções para apontarem para a nova pasta `research/` se fizer sentido mantê-la fora do controlo de versão também (a decidir: o utilizador disse que este material "viaja numa pasta própria", o que sugere que deve ficar dentro do repo AEGIS e não necessariamente fora do git — usa o teu critério, mas por omissão sugiro versionar `research/` normalmente já que agora faz parte do "pacote" do projeto).
5. Procurar e corrigir paths absolutos residuais: `grep -rn "/home/albertojf/caspar" .` em todos os ficheiros de texto copiados (incluindo os `.md`) e substituir por `/home/albertojf/AEGIS` ou remover se for só um exemplo ilustrativo.
6. Validar que o projeto fica funcional:
   - `python3 -m venv .venv && .venv/bin/pip install -e .[dev]` — **atenção em Ubuntu 22.04**: o pip antigo do python3.10 rebenta com `ResolutionTooDeep` neste comando; ver `GUIA_TESTE_MAQUINA.md` (secção de setup) para o workaround (atualizar o pip primeiro e/ou instalar as dependências diretamente antes do `-e .`)
   - `.venv/bin/pytest tests/ -q` → confirmar 623/623 a passar
   - `.venv/bin/sca doctor` → DB saudável
   - `.venv/bin/sca scan test_target/ubuntu_demo/sysctl.conf` (ou outro fixture) → confirmar output de scan real
   - Opcional mas recomendado para "pronto a testar noutra máquina": construir a imagem Docker (`docker build -t aegis:latest -f docker/aegis/Dockerfile .` ou o caminho equivalente após a reorganização) e correr `docker run --rm aegis:latest doctor`
7. Fazer o primeiro commit no novo repositório com uma mensagem tipo `chore: import inicial do AEGIS (a partir do CASPAR, renomeado e limpo)`.
8. Confirmar que `README.md`/`HANDOFF.md`/`DISSERTACAO_REFERENCIA.md` estão coerentes com a nova localização e prontos para servir de ponto de partida à escrita da dissertação.

## Notas importantes para quem for executar

- O renaming CASPAR→AEGIS e caspar→sca **já está feito e testado** em `/home/albertojf/caspar` — não precisas de repetir esse trabalho, só copiar.
- O conceito **CCSS** (Common Configuration Scoring System, NISTIR 7502) é uma norma técnica independente do nome do projeto — não confundir com "CASPAR"/"AEGIS". Fica tudo como `ccss.py`, `ccss.db`, "pontuação CCSS", etc.
- Se encontrares qualquer referência residual a "caspar"/"CASPAR" fora das exceções explicitamente listadas acima (pasta `caspar_inforum2026/`, ficheiro `RELATORIO_CASPAR.docx`), é sinal de que escapou ao rename original — reporta isso mas não é bloqueante para a migração.
