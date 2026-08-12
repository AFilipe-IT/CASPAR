# PRD CVM v2 — secções propostas

Duas secções para integrar no PRD, mais uma alteração pequena à §5.
Todos os números foram verificados contra o repositório (`scripts/evaluate.py`,
commit `c58f2c7`), não estimados.

---

## §0. Estado Atual do Projeto

*(a inserir imediatamente antes da §1 Visão, ou como §1.1)*

O CVM não parte de zero. A metodologia tem uma implementação de referência
funcional e validada experimentalmente, denominada **CASPAR**, desenvolvida no
âmbito da dissertação e disponível em código aberto. Esta secção descreve o que
existe hoje, para que a evolução proposta nas secções seguintes seja lida como
extensão de uma base medida e não como proposta de raiz.

### O que está implementado

A implementação atual avalia **doze tecnologias** através de plugins
independentes: Apache HTTPD, nginx, SSH, MySQL, PostgreSQL, Redis, Tomcat,
Docker, Dockerfile, Kubernetes, Azure IaC e Ubuntu. A base de conhecimento
contém **514 regras** e **32 cadeias de ataque**, com proveniência declarada por
alvo — regras derivadas de benchmarks CIS, de guias STIG, ou curadas
manualmente.

A construção da base de conhecimento e a sua utilização estão deliberadamente
separadas. A extração de regras a partir de documentação — benchmarks CIS em
PDF, conteúdos XCCDF, documentação oficial — é feita **uma única vez, em
build-time**, recorrendo a um modelo de linguagem com recuperação aumentada
(RAG) sobre os documentos de origem. A avaliação em **runtime é inteiramente
determinística**: lê regras já persistidas e não invoca qualquer modelo de
linguagem. Esta separação é o que torna as avaliações reproduzíveis.

O cálculo de risco assenta no **CCSS** (Common Configuration Scoring System),
produzindo para cada configuração insegura um score base e um score temporal.
As **cadeias de ataque** são detetadas quando um conjunto de directivas
inseguras coexiste, e recebem um score amplificado próprio, limitado por tipo de
impacto — uma cadeia puramente de divulgação de informação não pode atingir
severidade crítica, independentemente do factor de amplificação.

Cada avaliação grava um **manifesto de reprodutibilidade**: a versão do código,
a versão de Python, e o SHA-256 do conteúdo da base de conhecimento que produziu
aqueles resultados. Duas avaliações com o mesmo manifesto e o mesmo ficheiro de
entrada produzem, por construção, resultados idênticos — e essa afirmação é
auditável a partir do próprio relatório, sem ser preciso confiar na ferramenta.

A plataforma disponibiliza ainda uma **interface web** (inventário, score global,
distribuição por severidade, cadeias, evolução temporal, navegação até ao detalhe
de cada finding), uma **API REST**, geração de relatórios em vários formatos, e
um mecanismo de **monitorização contínua** (`watch`) que re-avalia
automaticamente sempre que um ficheiro monitorizado — ou qualquer ficheiro por
ele incluído — é alterado.

### Validação experimental

A implementação foi validada em **Ubuntu 22.04**, sobre serviços reais
instalados e configurados, e não apenas sobre ficheiros sintéticos.

**Correção dos scores.** Os scores produzidos foram comparados com os valores
publicados no CCE (Common Configuration Enumeration). Das 105 entradas CCE
consideradas, **20 possuem score publicado**; nessas 20, a concordância foi
**total** (20/20, taxa de discordância 0%). As restantes 85 entradas não têm
score de referência publicado e são reportadas como tal, sem serem contabilizadas
a favor nem contra.

**Deteção.** Sobre um conjunto de configurações deliberadamente vulneráveis,
cobrindo os vários alvos suportados, foram detetadas **96 de 96** configurações
inseguras esperadas — *recall* de 100% — sem qualquer falso positivo
(*precision* 100%, F1 = 1.0).

**Comparação com ferramentas existentes.** Foram executadas comparações com
Trivy e OpenSCAP sobre os mesmos alvos, documentadas na dissertação.

A suite de testes automatizados conta atualmente **846 testes**.

### O que a versão atual deliberadamente não faz

Para que a §5 seja lida corretamente, importa ser explícito quanto aos limites
da implementação atual:

- A avaliação incide sobre **ficheiros de configuração**. Não há análise de
  exposição de rede, de permissões do sistema de ficheiros, de segredos
  expostos, nem correlação com vulnerabilidades de versões instaladas.
- Não existe **inventário de hosts** como conceito de primeira ordem: a unidade
  de avaliação é um caminho de configuração, não um sistema inventariado.
- O indicador global é o **score do pior achado individual**. As cadeias de
  ataque são pontuadas e reportadas, mas não entram nesse número — por decisão
  de design, discutida na §6.

---

## §6. Modelo de Avaliação *(revisto)*

A versão atual representa o risco através de um indicador único, derivado da
avaliação de configurações. Com a introdução de novas dimensões de análise
(§5), essa representação deixa de ser suficiente: um sistema com configurações
corretas mas com segredos expostos e serviços desnecessariamente acessíveis não
está seguro, e um número só não o consegue exprimir.

### Indicadores por dimensão

A postura de segurança passa a ser representada por um **indicador próprio para
cada dimensão de análise** — configuração, permissões, exposição de rede,
segredos, atualização de software e proteção do sistema operativo — mantendo-se
um indicador global obtido pela sua agregação.

Esta decomposição não é apenas apresentacional: é o que permite responder não só
"qual é o risco?" mas "que factores o produzem?", que é a pergunta acionável.

### Agregação parametrizável e versionada

A combinação das diferentes dimensões será realizada através de um **modelo de
agregação parametrizável**, cujos pesos serão explicitamente documentados e
versionados, garantindo que alterações futuras não comprometem a comparabilidade
histórica das avaliações.

Concretamente, isto implica três garantias:

1. **O modelo de scoring tem versão própria**, gravada em cada avaliação. O
   mecanismo já existe: o manifesto de reprodutibilidade (§0) grava hoje a
   versão do código e o SHA-256 da base de conhecimento; passa a gravar também
   a versão do modelo de agregação e os pesos efetivamente aplicados.

2. **Avaliações produzidas por modelos diferentes nunca são comparadas
   diretamente.** As séries temporais (§7) segmentam nas fronteiras de versão do
   modelo, tornando visível que houve uma alteração de fórmula, em vez de a
   diluir numa curva que pareceria uma variação de risco real.

3. **Dimensões não avaliadas são explicitamente distinguidas de dimensões
   avaliadas sem achados.** Um sistema onde apenas a análise de configuração foi
   executada não pode produzir o mesmo indicador que um sistema onde as seis
   dimensões foram avaliadas e nada foi encontrado. O indicador global é
   acompanhado da **cobertura** que o produziu, e o modelo declara se dimensões
   ausentes são excluídas da normalização ou tratadas como desconhecidas.

### Cadeias de ataque

A implementação atual deteta cadeias de ataque e atribui-lhes um score
amplificado próprio, mas mantém o indicador global atribuível a um único achado
individual. A justificação é de acionabilidade: um indicador que o operador não
consegue rastrear até uma directiva concreta que possa corrigir é um indicador
sobre o qual não pode agir. Quando uma cadeia é pontuada acima do indicador
global, esse facto é assinalado explicitamente no relatório em vez de ser
silenciosamente incorporado no total.

A versão 2 **mantém este princípio** e evolui a sua representação: as cadeias
passam a ter um **indicador de risco combinado próprio**, apresentado ao lado do
indicador global e não fundido nele. Assim, dois sistemas cujo pior achado
individual é idêntico deixam de ser indistinguíveis quando um deles apresenta
múltiplas configurações inseguras que se combinam — sem que o indicador global
perca a atribuibilidade que o torna acionável.

Esta é também a dimensão em que a plataforma mais se distingue das ferramentas
descritas na §2, que reportam achados isolados sem modelar a sua composição.

### Validação do modelo

Sendo os pesos um parâmetro declarado e não um valor derivado empiricamente, a
sua escolha será acompanhada de uma **análise de sensibilidade**: verificar em
que medida a ordenação dos riscos identificados se mantém estável quando os
pesos são perturbados (por exemplo, ±10%). Um ordenamento estável sob perturbação
demonstra que as conclusões da ferramenta não dependem criticamente da escolha
particular dos pesos — o que constitui uma validação mais defensável do que uma
calibração que a dimensão do estudo não permitiria sustentar.

---

## §5. Evolução Funcional — nota de sequenciamento *(a acrescentar no fim da secção)*

Os módulos descritos não são independentes entre si nem apresentam o mesmo grau
de maturidade. A ordem de desenvolvimento proposta decorre das suas dependências
técnicas:

| Ordem | Módulo | Dependência / justificação |
|---|---|---|
| 1 | **Configuração** | Já implementado e validado (§0). Base sobre a qual os restantes assentam. |
| 2 | **Permissões** | Reutiliza a infraestrutura de recolha e o modelo de regras existentes; a análise incide sobre metadados do sistema de ficheiros em vez de directivas. |
| 3 | **Exposição de rede** | Requer a noção de sistema avaliado — inexistente hoje, em que a unidade é um caminho de configuração. Introduz, ou depende de, um inventário de hosts. |
| 4 | **Segredos** | Introduz desafios novos: falsos positivos por natureza probabilística da deteção, e manuseamento de dados sensíveis (o que se grava, e o que nunca deve ser gravado). |
| 5 | **Atualização de software** | Depende de fontes externas (feeds de vulnerabilidades) e do respetivo ciclo de vida, introduzindo uma dependência de disponibilidade que os módulos anteriores não têm. |
| 6 | **Containers / Kubernetes** | Existem já plugins parciais (`docker`, `dockerfile`, `kubernetes`); a evolução é de aprofundamento e não de raiz. |
| 7 | **Cloud** | O maior âmbito e o mais dependente de fornecedor. O plugin `azure-iac` cobre hoje análise estática de IaC, não avaliação de recursos em execução. |

Esta ordenação não constitui um calendário: exprime dependências e maturidade,
não datas.
