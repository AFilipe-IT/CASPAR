# Configuration Vulnerability Meter (CVM)

> **Product Vision and Conceptual Specification**  
> **Versão:** 1.0 (Draft)

---

# 1. Introdução

O **Configuration Vulnerability Meter (CVM)** é uma plataforma concebida para medir quantitativamente a vulnerabilidade introduzida pelas configurações de sistemas, serviços e infraestruturas. A sua finalidade não é substituir scanners de vulnerabilidades nem ferramentas tradicionais de conformidade, mas complementar estas abordagens através da produção de uma medida contínua, reproduzível, auditável e explicável da exposição criada pelas opções de configuração.

Nas infraestruturas modernas, a configuração tornou-se um dos principais fatores que determinam a postura de segurança. Imagens de sistemas operativos, contentores, manifestos Kubernetes e modelos de Infrastructure as Code permitem replicar rapidamente ambientes completos, mas também propagam automaticamente configurações inseguras. Um único erro pode ser reproduzido em dezenas ou centenas de instâncias, aumentando proporcionalmente a superfície de ataque da organização.

Embora existam referenciais consolidados, como os **CIS Benchmarks** e os **DISA STIGs**, e ferramentas capazes de verificar a conformidade com esses referenciais, continua a faltar uma plataforma capaz de responder a uma questão simples: **quão vulnerável é uma configuração?** O CVM nasce precisamente para responder a essa necessidade.

---

# 2. Visão

A visão do Configuration Vulnerability Meter consiste em estabelecer uma nova categoria de plataformas de segurança dedicada à avaliação quantitativa da vulnerabilidade das configurações. Enquanto um scanner de conformidade responde se uma recomendação foi cumprida e um scanner de vulnerabilidades identifica software afetado por vulnerabilidades conhecidas, o CVM procura medir o impacto que as decisões de configuração têm na segurança global de um sistema.

O conceito é suficientemente genérico para ser aplicado a diferentes domínios tecnológicos, permitindo avaliar desde um único ficheiro de configuração até uma infraestrutura completa. Desta forma, o CVM fornece uma visão hierárquica da segurança das configurações, mantendo sempre o mesmo modelo conceptual de avaliação.

---

# 3. Objetivos

O CVM tem como objetivo disponibilizar uma plataforma capaz de produzir avaliações quantitativas da vulnerabilidade de configurações, permitindo comparar sistemas entre si, priorizar ações de mitigação e justificar cada decisão tomada durante o processo de avaliação.

A plataforma procura reduzir a subjetividade inerente à análise manual de referenciais de segurança, automatizando a transformação dessas recomendações em conhecimento estruturado e reutilizável. Simultaneamente, pretende assegurar propriedades fundamentais para ambientes de produção, como determinismo, reprodutibilidade, auditabilidade e explicabilidade.

---

# 4. Domínio de Aplicação

O Configuration Vulnerability Meter foi concebido para avaliar diferentes níveis de granularidade. A unidade mais elementar corresponde a uma regra de configuração individual. A partir desta unidade podem ser produzidas avaliações para ficheiros de configuração completos, serviços específicos, sistemas operativos, clusters, ambientes cloud e infraestruturas inteiras.

Esta abordagem permite que a mesma plataforma seja utilizada tanto para analisar um único serviço, como um servidor Apache ou um serviço SSH, como para avaliar a configuração global de um ambiente composto por múltiplos sistemas e tecnologias.

As categorias de configuração suportadas podem abranger autenticação, autorização, exposição de serviços, políticas criptográficas, configuração de sistemas operativos, serviços de infraestrutura, plataformas cloud, contentores, Kubernetes e Infrastructure as Code, mantendo sempre uma representação homogénea da vulnerabilidade das configurações.

---

# 5. Princípios Fundamentais

O CVM assenta em cinco princípios fundamentais. Em primeiro lugar, a avaliação deve ser quantitativa, produzindo uma pontuação contínua em vez de uma decisão binária. Em segundo lugar, todas as avaliações devem ser reproduzíveis, garantindo que a mesma configuração produz sempre o mesmo resultado quando analisada com a mesma base de conhecimento. Em terceiro lugar, cada decisão deve ser auditável, permitindo compreender exatamente quais as regras utilizadas e como a pontuação foi calculada. Em quarto lugar, a plataforma deve ser explicável, apresentando a fundamentação técnica de cada resultado. Finalmente, o modelo deve ser extensível, permitindo incorporar novos referenciais, tecnologias e domínios de configuração sem alterar a arquitetura principal.

---

# 6. Arquitetura Conceptual

O funcionamento do CVM divide-se conceptualmente em duas fases independentes. A primeira corresponde à construção da base de conhecimento, onde os referenciais de segurança são interpretados, estruturados e enriquecidos com informação necessária ao processo de avaliação. Esta fase pode recorrer a modelos de linguagem e técnicas de Retrieval-Augmented Generation para transformar documentação orientada a humanos em conhecimento estruturado.

A segunda fase corresponde à avaliação propriamente dita. Nesta etapa, a plataforma interpreta as configurações fornecidas pelo utilizador, identifica as regras aplicáveis, calcula as respetivas pontuações e produz um relatório detalhado. Como a base de conhecimento já se encontra construída, esta fase decorre de forma totalmente determinística, sem necessidade de recorrer novamente a modelos de linguagem.

---

# 7. Diferenciação

O Configuration Vulnerability Meter distingue-se das ferramentas existentes por não se limitar a verificar conformidade nem a identificar vulnerabilidades conhecidas. O seu objetivo consiste em medir a vulnerabilidade decorrente das configurações, produzindo uma representação quantitativa da exposição ao risco.

Esta abordagem permite comparar diferentes sistemas, estabelecer prioridades de mitigação, representar risco composto através da combinação de múltiplas configurações inseguras e disponibilizar indicadores globais para serviços, sistemas e infraestruturas, preservando simultaneamente a rastreabilidade e a explicabilidade de cada decisão.

---

# 8. Visão Futura

O CVM pretende evoluir para uma plataforma extensível capaz de integrar novos referenciais de segurança, novos serviços e novos modelos de avaliação sem alterar os seus princípios fundamentais. A longo prazo, poderá suportar ambientes híbridos, infraestruturas multicloud e integração contínua em pipelines DevSecOps, mantendo sempre como objetivo central a medição quantitativa da vulnerabilidade das configurações.
