# CVM v2 — Plano de execução

**Objectivo declarado:** produto utilizável por terceiros, duas a três dimensões
novas, UI v2 completa gerada no Lovable.

Levantado contra o repositório em `c58f2c7`. Os custos abaixo são estimativas de
esforço, não datas.

---

## 1. O achado que decide a arquitectura

A preocupação inicial era que dimensões novas (permissões, exposição) não
coubessem no modelo de dados actual, obrigando a reescrever o núcleo. **Não é o
caso**, e isso reduz o custo da v2 de forma decisiva.

O modelo `Misconfiguration` — o achado que o scoring consome, a base grava e a UI
mostra — **não depende de a origem ser um ficheiro de configuração**. Os campos
que descrevem o problema (`directive`, `bad_value`, `good_value`, métricas CCSS,
`justification`, `recommendation`) são agnósticos quanto à proveniência, e o
único campo que liga a um ficheiro, `source_directive`, é **opcional**.

O que assume ficheiros é apenas a etapa de **recolha**: o contrato `Target`
define `parse_config(path) -> list[Directive]`, e `Directive` traz `source_file`
e `line_number`. Mas `Directive` só é referido em **cinco ficheiros do núcleo**
(`target.py`, `models.py`, `engines/assessment.py`, `unknown_directives.py`,
`watch_loop.py`).

**Consequência:** a generalização necessária é localizada na recolha. O scoring,
a persistência, a API, os relatórios, as cadeias e a consola funcionam sem
alteração com achados de qualquer dimensão. É a diferença entre uma reescrita e
uma extensão.

## 2. Como se generaliza a recolha

`Directive` passa a ser um caso particular de **evidência**: um facto observado
sobre o sistema, com um identificador, um valor observado e uma proveniência.

| Dimensão | Identificador | Valor observado | Proveniência |
|---|---|---|---|
| Configuração *(hoje)* | `ServerTokens` | `Full` | ficheiro + linha |
| Permissões | `/etc/shadow:mode` | `0644` | inode |
| Exposição | `tcp/0.0.0.0:6379` | `redis-server` | socket + processo |

As regras continuam a ser pares (identificador, valor inseguro) com métricas
CCSS — o motor de correspondência que já existe (`match_value_rules`,
`detect_absences`) opera igual. O que muda é quem produz as evidências.

Recomendação concreta: acrescentar ao contrato `Target` um método opcional
`collect_evidence(path) -> list[Evidence]`, com `parse_config` a manter-se como
o caso ficheiro (implementado por omissão em termos do novo método). Os doze
plugins existentes não são tocados.

**Risco assumido:** `core/target.py` diz hoje "zero modificações a este
ficheiro". Esta alteração contradiz essa regra. É uma alteração aditiva e
retrocompatível, mas é uma decisão de arquitectura consciente e deve ficar
registada como tal no PRD (§9).

## 3. Sequência

A ordem não é preferência: decorre de dependências verificadas.

### Fase A — Scoring multidimensional *(pré-requisito de tudo o resto)*

Sem isto, uma dimensão nova não tem onde aparecer: o indicador global é hoje o
pior achado individual (`engines/aggregation.py::aggregate_scan`), sem noção de
dimensão.

- Cada achado passa a declarar a dimensão a que pertence.
- Agregação produz um indicador por dimensão + um global parametrizável.
- Manifesto passa a gravar versão do modelo de scoring e pesos aplicados.
- Cobertura explícita: dimensões não avaliadas ≠ dimensões limpas.
- Séries temporais segmentam na fronteira de versão do modelo.

**Custo:** moderado. Toca em `aggregation.py`, `manifest.py`, `models.py`,
schema da base (aditivo), e nos testes de agregação.
**Valor de tese:** é a §6 do PRD tornada executável. É também o que permite a
análise de sensibilidade.

### Fase B — Permissões

Segunda dimensão. Reutiliza o motor de regras e o scoring; não precisa de
inventário nem de fontes externas.

Nota relevante: o plugin `ubuntu` **já declara permissões como limitação
assumida** — *"whole-system state checks (file permissions, kernel modules,
running services) are OpenSCAP's domain, out of scope here"*. Implementá-la não
é âmbito arbitrário: fecha uma limitação que a dissertação já reconhece, e
melhora directamente a comparação com o OpenSCAP.

Âmbito: dono/grupo/modo de ficheiros sensíveis, ficheiros graváveis por todos,
binários SUID/SGID, política de `sudo`, permissões do socket do Docker.

**Custo:** moderado. Plugin novo + regras curadas (sem LLM: são regras
determinísticas e bem documentadas no CIS) + fixtures de teste.

### Fase C — Exposição de rede

Terceira dimensão, e a que traz infraestrutura nova: **requer um conceito de
sistema avaliado (inventário) que hoje não existe** — a unidade de avaliação é
um caminho de configuração.

Âmbito: portas à escuta, interfaces de escuta, processo associado, protocolos
obsoletos/inseguros.

**Custo:** o mais alto dos três, sobretudo pelo inventário. É também onde as
cadeias de ataque ganham mais força (uma directiva insegura *e* o serviço
acessível externamente é qualitativamente diferente de qualquer uma sozinha).

**Decisão em aberto:** se o prazo apertar, esta é a fase a cortar — A+B já
sustentam a afirmação de que a metodologia generaliza, e a análise de
sensibilidade precisa apenas de ≥2 dimensões.

## 4. UI no Lovable — como não perder a ligação

A geração da UI antes do backend só é segura com uma condição: **o Lovable
desenha sobre um contrato de dados fixo, não sobre estruturas que invente.**

Se as formas dos dados forem inventadas, a ligação passa a ser tradução, e é aí
que se perdem semanas. Se lhe for dado o schema exacto que o backend servirá, a
ligação é substituição de mocks por chamadas reais.

Entregável antes de abrir o Lovable: **um documento de contrato de API** com as
respostas em JSON de cada endpoint da v2 — nomes de campos, tipos, valores
possíveis dos enums, o que pode vir vazio, e o que significa "dimensão não
avaliada". Esse documento é o prompt do Lovable.

Dois avisos a incorporar nesse contrato:

1. **Cobertura tem de ser visível na UI.** Se o ecrã mostra seis dimensões e só
   duas foram avaliadas, as outras quatro não podem aparecer como 0 ou verdes —
   têm de aparecer como não avaliadas. Se a UI não previr esse estado, o produto
   mente ao utilizador.
2. **O ecrã de cadeias não é uma lista de achados.** É a contribuição mais
   distintiva do projecto e merece representação própria (composição, o que cada
   elo contribui, porque é que a combinação é pior do que as partes).

O que já existe e não deve ser deitado fora: tokens de cor/tipografia, o
`ServiceIcon` (resolve 37 alvos por família), a estrutura de temas claro/escuro
em três blocos, e 55 testes de frontend. Se a UI do Lovable for adoptada, estes
elementos devem ser portados para ela em vez de reinventados.

## 5. Ordem de trabalho recomendada

1. **Contrato de API da v2** — o documento que serve de base ao Lovable.
   Bloqueia a UI, portanto é o primeiro.
2. **Fase A (scoring multidimensional)** — em paralelo com o desenho da UI.
3. **Fase B (permissões)** — primeira dimensão nova a preencher o modelo.
4. **Ligação da UI** ao backend real.
5. **Fase C (exposição)** — se o prazo permitir.
6. **Análise de sensibilidade** — resultado de validação, precisa de A+B.

## 6. Riscos a manter à vista

- **A dissertação está por escrever e a parte prática estava fechada e
  validada.** Reabri-la é a decisão de maior risco deste plano. As fases estão
  ordenadas para que parar depois de A+B deixe um resultado coerente e
  defensável, em vez de um sistema meio-migrado.
- **Regressão na base validada.** As 846 passagens de teste e os números de
  avaliação (20/20 CCE, 96/96 deteção) são o activo mais valioso do projecto.
  Devem ser re-executados ao fim de cada fase, e qualquer alteração ao scoring
  tem de manter a comparabilidade documentada ou versioná-la explicitamente.
- **Seis dimensões anunciadas, duas ou três entregues.** O PRD deve declarar o
  estado de cada dimensão, para que a UI e o documento não prometam mais do que
  o sistema entrega.
