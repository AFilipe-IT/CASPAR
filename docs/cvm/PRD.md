# Product Requirements Document (PRD)

# Configuration Vulnerability Meter (CVM)

**Versão:** 1.0 (Draft)

**Autor:** Alberto Januário Filipe

## 1. Visão do Produto

O Configuration Vulnerability Meter (CVM) é uma plataforma para avaliação quantitativa da vulnerabilidade de configurações de sistemas, serviços e infraestruturas.

Ao contrário das ferramentas tradicionais de conformidade, que apenas verificam se uma determinada recomendação foi cumprida, o CVM mede o nível de vulnerabilidade introduzido pelas configurações existentes, produzindo uma avaliação contínua, reproduzível, auditável e explicável.

O CVM pretende estabelecer uma nova categoria de plataformas de segurança, posicionando-se entre os scanners de vulnerabilidades e as ferramentas de conformidade.

## 2. Problema

As soluções atuais verificam conformidade ou detetam vulnerabilidades conhecidas, mas não medem quantitativamente a gravidade das configurações inseguras nem permitem priorizar objetivamente a mitigação.

## 3. Objetivo

Disponibilizar uma plataforma capaz de medir quantitativamente a vulnerabilidade da configuração de um sistema, produzindo:

- Pontuação contínua;
- Classificação qualitativa;
- Recomendações;
- Justificação técnica;
- Evidência;
- Rastreabilidade;
- Reprodutibilidade.

## 4. Público-alvo

- Administradores de sistemas
- DevSecOps
- Equipas SOC
- Auditores
- Pentesters
- Cloud Engineers

## 5. Âmbito

O CVM deverá suportar avaliação de:

- Serviços individuais (Apache, SSH, Nginx, MySQL, etc.);
- Sistemas operativos;
- Plataformas (Docker e Kubernetes);
- Infrastructure as Code;
- Infraestruturas completas.

## 6. Categorias de Configuração

- Autenticação
- Autorização
- Exposição de serviços
- Configuração criptográfica
- Configuração de serviços
- Conformidade com CIS Benchmarks e DISA STIG
- Cadeias de ataque (risco composto)

## 7. Modelo de Avaliação

Cada configuração deverá produzir:

- Pontuação contínua;
- Severidade;
- Justificação;
- Recomendação;
- Referencial;
- Vetor CCSS.

## 8. Níveis de Avaliação

- Regra
- Serviço
- Sistema
- Infraestrutura
- Organização

## 9. Funcionalidades Principais

- Avaliação determinística
- Reprodutibilidade
- Auditabilidade
- Explicabilidade
- Priorização automática
- Agregação por níveis
- Avaliação de cadeias de ataque

## 10. Arquitetura

### Build-time

- Interpretação de referenciais
- Construção da base de conhecimento
- Utilização de LLM + RAG
- Validação das regras

### Runtime

- Análise das configurações
- Consulta determinística
- Cálculo das pontuações
- Geração de relatórios

## 11. Requisitos Não Funcionais

- Offline
- Determinístico
- Auditável
- Reproduzível
- Modular
- Extensível

## 12. Diferenciação

O CVM complementa scanners de vulnerabilidades e ferramentas de conformidade ao introduzir uma medição quantitativa da vulnerabilidade decorrente das configurações.

## 13. Contribuições Científicas

1. Definição do conceito de Configuration Vulnerability Meter.
2. Metodologia para construção de um CVM.
3. Arquitetura Build-time/Runtime.
4. Modelo para risco composto.
5. Estrutura de conhecimento baseada em referenciais.
6. Prova de conceito validada experimentalmente.

## 14. Visão de Longo Prazo

O CVM pretende estabelecer uma nova categoria de plataformas de segurança dedicadas à medição quantitativa da vulnerabilidade de configurações, mantendo propriedades de determinismo, auditabilidade, reprodutibilidade e explicabilidade.
