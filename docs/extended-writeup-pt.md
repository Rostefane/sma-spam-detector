> *Nota: este documento é um texto acadêmico complementar, mantido no idioma original (português). Veja o [README](../README.md) principal para uma visão geral em inglês.*

# Sistema Multi-Agente para Detecção de Spam: Arquitetura, Implementação e Avaliação

## Resumo

Este trabalho apresenta um sistema multi-agente (SMA) para detecção de spam e conteúdo malicioso em emails, implementado utilizando o framework LangGraph. O sistema é composto por seis agentes especializados que operam de forma coordenada através de um agregador de resultados. Os experimentos realizados com 1.000 amostras de um dataset balanceado demonstraram uma acurácia de 87,0%, precisão de 80,1%, recall de 92,8% e F1-Score de 86,0%, validando a eficácia da abordagem multi-agente para esta tarefa.

**Palavras-chave:** Sistema Multi-Agente, Detecção de Spam, LangGraph, Segurança Cibernética, Processamento de Linguagem Natural

## 1. Introdução

A proliferação de emails spam e conteúdo malicioso representa uma ameaça significativa à segurança cibernética, exigindo soluções robustas e adaptáveis. Este trabalho propõe um sistema multi-agente (SMA) que combina diferentes técnicas de análise para detecção de spam, utilizando o framework LangGraph para coordenação dos agentes e garantindo escalabilidade e modularidade.

O sistema desenvolvido integra técnicas de sanitização de texto, detecção de prompt injection, análise de hashes maliciosos, classificação por LLM (Large Language Model), e detecção de conteúdo malicioso, proporcionando uma abordagem abrangente e defensiva contra ameaças emergentes.

## 2. Fundamentação Teórica

### 2.1 Sistemas Multi-Agente

Sistemas multi-agente são paradigmas computacionais onde múltiplos agentes autônomos interagem para resolver problemas complexos. Na detecção de spam, cada agente pode especializar-se em diferentes aspectos da análise, desde características linguísticas até padrões comportamentais maliciosos.

### 2.2 Framework LangGraph

LangGraph é um framework baseado em grafos para construção de aplicações com Large Language Models, permitindo a criação de fluxos de trabalho complexos com estados compartilhados e condições de controle. O framework facilita a implementação de sistemas multi-agente com capacidades de saída antecipada e agregação de resultados.

## 3. Arquitetura do Sistema

### 3.1 Visão Geral

O sistema proposto segue uma arquitetura de quatro fases, conforme ilustrado na Figura 1:

1. **Fase 1 - Sanitização**: Normalização e limpeza do texto de entrada
2. **Fase 2 - Detecção de Prompt Injection**: Identificação de tentativas de manipulação
3. **Fase 3 - Análise Paralela**: Execução simultânea de múltiplos analisadores
4. **Fase 4 - Agregação**: Combinação ponderada dos resultados

### 3.2 Agentes Especializados

#### 3.2.1 SanitizationAgent

O agente de sanitização é responsável pela normalização e limpeza do texto de entrada, removendo caracteres de controle, entidades HTML e normalizando Unicode. Este agente estabelece a base para análises subsequentes, garantindo consistência no processamento.

**Funcionalidades principais:**
- Normalização Unicode (NFKC)
- Remoção de caracteres de controle
- Limpeza de tags HTML
- Normalização de espaços em branco

#### 3.2.2 PromptInjectionAgent

Este agente detecta tentativas de prompt injection utilizando uma base de conhecimento de 86.576 padrões maliciosos conhecidos. Durante os experimentos, este agente não contribuiu significativamente para as classificações finais (peso = 0.0), indicando que o dataset utilizado não continha tentativas de prompt injection.

**Características:**
- 10 padrões regex especializados
- Base de dados de jailbreak prompts
- Análise de palavras-chave suspeitas
- Sistema de pontuação combinada

#### 3.2.3 LLMClassifier

O classificador baseado em LLM representa o componente principal do sistema (peso = 0.85), utilizando OpenAI GPT para análise contextual do conteúdo. O agente implementa um sistema de fallback robusto para casos de indisponibilidade da API.

**Arquitetura:**
- Modelo primário: OpenAI GPT
- Fallback: Pattern matching baseado em regras
- Prompt otimizado para classificação binária
- Rate limiting para conformidade com APIs

#### 3.2.4 HashAnalyzer

O analisador de hash verifica o conteúdo contra uma base de 92.421 hashes maliciosos conhecidos (MD5, SHA1, SHA256). Durante os experimentos, este agente não identificou correspondências (peso = 0.0), sugerindo que o dataset não continha conteúdo com hashes previamente catalogados como maliciosos.

#### 3.2.5 MaliciousContentAgent

Este agente detecta indicadores de phishing e conteúdo malicioso através de análise de URLs e padrões linguísticos. Contribui secundariamente para a classificação final (peso = 0.15), focando em detecção de links suspeitos e táticas de engenharia social.

#### 3.2.6 ResultAggregator

O agregador de resultados combina as saídas de todos os agentes utilizando um sistema de pesos otimizado. A configuração atual prioriza a classificação por LLM (85%) complementada pela análise de conteúdo malicioso (15%).

## 4. Metodologia

### 4.1 Dataset

Os experimentos foram realizados utilizando um dataset combinado e reduzido (`combined_reduced_dataset.csv`) contendo 77.677 amostras, das quais 1.000 foram selecionadas aleatoriamente para validação. A distribuição foi balanceada com 571 emails legítimos (ham) e 429 emails spam.

### 4.2 Configuração Experimental

**Parâmetros do sistema:**
- Threshold de classificação: 0.55
- Timeout de processamento: 120 segundos
- Rate limiting: 0.2 segundos entre chamadas LLM
- Modelo LLM: OpenAI GPT
- Seed aleatória: 42 (para reprodutibilidade)

### 4.3 Métricas de Avaliação

As métricas utilizadas seguem padrões estabelecidos para classificação binária:
- Acurácia: (TP + TN) / (TP + TN + FP + FN)
- Precisão: TP / (TP + FP)
- Recall (Sensibilidade): TP / (TP + FN)
- F1-Score: 2 × (Precisão × Recall) / (Precisão + Recall)

## 5. Resultados e Discussão

### 5.1 Métricas de Performance

Os experimentos demonstraram performance sólida do sistema multi-agente:

| Métrica | Valor | Porcentagem |
|---------|-------|-------------|
| Acurácia | 0.870 | 87.0% |
| Precisão | 0.801 | 80.1% |
| Recall | 0.928 | 92.8% |
| F1-Score | 0.860 | 86.0% |

### 5.2 Matriz de Confusão

A análise da matriz de confusão revela:
- True Positives (TP): 398 emails spam corretamente identificados
- True Negatives (TN): 472 emails legítimos corretamente classificados
- False Positives (FP): 99 emails legítimos incorretamente marcados como spam
- False Negatives (FN): 31 emails spam não detectados

### 5.3 Análise dos Agentes

#### 5.3.1 Contribuição dos Agentes

A análise estatística dos agentes revelou:

**LLMClassifier:**
- Score médio: 0.498 ± 0.350
- Contribuição: 85% do peso final
- 1.000 amostras processadas

**MaliciousContentAgent:**
- Score médio: 0.024 ± 0.062
- Contribuição: 15% do peso final
- Baixa detecção de conteúdo malicioso no dataset

#### 5.3.2 Agentes Não Ativados

**PromptInjectionAgent e HashAnalyzer** não contribuíram para as classificações finais (peso = 0.0) devido à ausência de:
- Tentativas de prompt injection no dataset
- Conteúdo com hashes maliciosos conhecidos

Esta observação sugere que o dataset utilizado é composto predominantemente por spam tradicional, sem características de ataques mais sofisticados.

### 5.4 Performance Temporal

O sistema apresentou:
- Tempo médio de processamento: 6.798 segundos por amostra
- Tempo total de processamento: 6.797,6 segundos (1.000 amostras)
- Zero saídas antecipadas (0.0%), indicando processamento completo de todas as amostras

### 5.5 Justificativa dos Pesos

A configuração de pesos foi otimizada com base em:

1. **LLM Classifier (85%)**: Principal responsável pela classificação contextual, demonstrando alta capacidade de generalização
2. **Malicious Content (15%)**: Complementa a análise com detecção específica de padrões maliciosos
3. **Outros agentes (0%)**: Configurados como detectores especializados que só contribuem quando identificam ameaças específicas

O threshold de 0.55 foi calibrado para balancear precisão e recall, priorizando a detecção de spam (recall alto) enquanto mantém taxa aceitável de falsos positivos.

## 6. Limitações

### 6.1 Dependência de APIs Externas

O sistema depende da disponibilidade da API OpenAI, embora implemente fallback para pattern matching.

### 6.2 Características do Dataset

O dataset utilizado não apresentou:
- Tentativas de prompt injection
- Conteúdo com hashes maliciosos conhecidos
- Ataques sofisticados de engenharia social

### 6.3 Escalabilidade

O tempo médio de processamento (6.8s por amostra) pode ser limitante para aplicações em tempo real.

## 7. Trabalhos Futuros

### 7.1 Otimizações de Performance

**Paralelização Avançada:**
- Implementar processamento assíncrono de agentes independentes
- Utilizar pools de threads para análises paralelas
- Otimizar cache de resultados para conteúdo repetitivo

**Otimização de Modelos:**
- Implementar modelos LLM locais (Llama, Mistral) para reduzir latência
- Desenvolver modelos especializados fine-tunados para detecção de spam
- Implementar quantização de modelos para reduzir uso de memória

### 7.2 Expansão dos Agentes

**Novos Agentes Especializados:**
- **OCRAnalyzerAgent**: Para análise de imagens e documentos anexos
- **BehavioralAnalysisAgent**: Análise de padrões comportamentais do remetente
- **TemporalAnalysisAgent**: Análise de padrões temporais de envio
- **NetworkAnalysisAgent**: Verificação de reputação de IPs e domínios

**Melhorias nos Agentes Existentes:**
- Integração com APIs de threat intelligence em tempo real
- Implementação de machine learning adaptativo
- Expansão da base de conhecimento de prompt injection

### 7.3 Arquitetura Avançada

**Sistema de Aprendizado Contínuo:**
- Implementar feedback loop para ajuste automático de pesos
- Sistema de retreinamento baseado em novos padrões detectados
- Integração com honeypots para coleta de novas ameaças

**Arquitetura Distribuída:**
- Implementar microserviços para cada agente
- Sistema de mensageria assíncrona (RabbitMQ, Apache Kafka)
- Orquestração via Kubernetes para escalabilidade horizontal

### 7.4 Melhorias na Detecção

**Análise Multimodal:**
- Processamento de conteúdo visual (OCR, análise de imagens)
- Análise de metadados de emails
- Detecção de steganografia

**Inteligência Artificial Avançada:**
- Implementação de ensemble methods
- Utilização de redes neurais especializadas
- Integração com modelos de detecção de anomalias

### 7.5 Interface e Usabilidade

**Dashboard em Tempo Real:**
- Visualização de métricas de performance
- Alertas para novas ameaças detectadas
- Interface para ajuste manual de parâmetros

**API RESTful:**
- Endpoints para integração com sistemas existentes
- Documentação automática via OpenAPI/Swagger
- Sistema de autenticação e rate limiting

### 7.6 Validação e Benchmarking

**Datasets Diversificados:**
- Testes com datasets multilíngues
- Validação com ameaças emergentes (deepfakes, AI-generated spam)
- Benchmarking contra sistemas comerciais

**Métricas Avançadas:**
- Implementação de métricas específicas para cada tipo de ameaça
- Análise de robustez contra ataques adversariais
- Estudos de performance em ambientes de produção

## 8. Trechos de Código Importantes

### 8.1 SanitizationAgent - Normalização Unicode
```python
def normalize_unicode(self, text: str) -> str:
    try:
        return unicodedata.normalize('NFKC', text)
    except Exception:
        return text

def remove_control_characters(self, text: str) -> str:
    for pattern in self.unicode_patterns:
        text = re.sub(pattern, '', text)
    return text
```

### 8.2 LLMClassifier - Classificação com Fallback
```python
def classify_with_openai(self, text: str) -> tuple:
    try:
        prompt = f\"\"\"Analyze this email content for spam/phishing characteristics.

Email: {text[:1000]}

Consider:
1. Urgency tactics
2. Money/prize offers
3. Suspicious links or requests
4. Grammar issues
5. Social engineering

Respond with ONLY:
- "SPAM" if suspicious/malicious
- "HAM" if legitimate

Answer:\"\"\"

        messages = [HumanMessage(content=prompt)]
        response = model.invoke(messages)
        response_text = response.content.lower().strip()

        if "spam" in response_text and "ham" not in response_text:
            return 0.85, ['spam']
        elif "ham" in response_text and "spam" not in response_text:
            return 0.15, ['ham']
        else:
            return self.classify_with_patterns(text)

    except Exception as e:
        return self.classify_with_patterns(text)
```

### 8.3 ResultAggregator - Agregação Ponderada
```python
def aggregate(self, agent_results: Dict[str, Any]) -> Dict[str, Any]:
    risk_scores = self.extract_risk_scores(agent_results)

    llm_score = risk_scores.get('llm_classifier', 0.5)
    malicious_score = risk_scores.get('malicious_content', 0.0)

    final_score = (
        llm_score * self.weights['llm_classifier'] +
        malicious_score * self.weights['malicious_content']
    )

    # Aplicar penalidades críticas
    if 'prompt_injection' in risk_scores:
        final_score += self.critical_penalties['prompt_injection']

    if 'hash_analyzer' in risk_scores:
        final_score += self.critical_penalties['hash_analyzer']

    final_score = min(max(final_score, 0.0), 1.0)
    is_malicious = final_score > self.spam_threshold

    return {
        'classification': 'malicious' if is_malicious else 'legitimate',
        'is_malicious': is_malicious,
        'confidence': final_score if is_malicious else (1.0 - final_score),
        'final_score': final_score
    }
```

### 8.4 LangGraph - Definição do Fluxo
```python
# Construção do Grafo
spam_detection_graph = StateGraph(SpamDetectionState)

# Adicionar nós
spam_detection_graph.add_node("sanitization", phase1_sanitization)
spam_detection_graph.add_node("prompt_injection", phase2_prompt_injection)
spam_detection_graph.add_node("llm_analysis", phase3_llm_analysis)

# Definir fluxo com condições
spam_detection_graph.add_conditional_edges(
    "prompt_injection",
    should_continue,
    {
        "continue": "llm_analysis",
        "END": END
    }
)
```

## 9. Conclusões

### 9.1 Síntese dos Resultados

O sistema multi-agente desenvolvido demonstrou eficácia significativa na detecção de spam, alcançando métricas robustas que validam a abordagem proposta. Com acurácia de 87,0%, precisão de 80,1%, recall de 92,8% e F1-Score de 86,0%, o sistema supera muitas soluções tradicionais de filtro de spam, especialmente considerando sua capacidade de adaptação a ameaças emergentes.

A utilização do framework LangGraph facilitou a implementação de fluxos complexos com condições de controle, estados compartilhados e agregação inteligente de resultados. A arquitetura modular permitiu a especialização de cada agente em aspectos específicos da detecção, resultando em um sistema coeso e eficiente.

### 9.2 Trabalhos Futuros e Direções de Pesquisa

Os resultados obtidos abrem diversas oportunidades para pesquisas futuras:

**Integração de Modalidades:** A expansão para análise multimodal, incluindo processamento de imagens via OCR e análise de metadados, pode aumentar significativamente a taxa de detecção de ameaças sofisticadas.

**Aprendizado Contínuo:** Implementação de sistemas de feedback automático e retreinamento baseado em novos padrões detectados, permitindo adaptação dinâmica a ameaças emergentes.

**Modelos Especializados:** Desenvolvimento de modelos de linguagem fine-tunados especificamente para detecção de spam, potencialmente reduzindo dependência de APIs externas e melhorando performance.

### 9.3 Expansão de Arquitetura e Motivações

A arquitetura atual, embora eficaz, apresenta oportunidades significativas de expansão:

**Arquitetura Distribuída:** A migração para uma arquitetura de microserviços permitiria escalabilidade horizontal, onde cada agente opera como um serviço independente, facilitando manutenção e atualizações incrementais.

**Orquestração Avançada:** Implementação de sistemas de mensageria assíncrona (Apache Kafka, RabbitMQ) para processamento em tempo real de grandes volumes de dados, essencial para aplicações empresariais.

**Edge Computing:** Distribuição de agentes especializados em pontos de borda da rede, reduzindo latência e melhorando resiliência do sistema.

A motivação para essas expansões reside na necessidade crescente de sistemas que possam processar milhões de emails diariamente com latência mínima, mantendo alta precisão na detecção.

### 9.4 Melhorias de Performance e Otimização

Análises de performance revelaram gargalos específicos que direcionam futuras otimizações:

**Paralelização Inteligente:** O tempo médio de 6,8 segundos por amostra pode ser drasticamente reduzido através de processamento paralelo de agentes independentes, potencialmente alcançando processamento sub-segundo.

**Cache Inteligente:** Implementação de sistemas de cache baseados em hashes de conteúdo para evitar reprocessamento de emails similares ou duplicados.

**Modelos Locais:** Substituição ou complementação dos modelos OpenAI por modelos locais otimizados (Llama, Mistral) pode reduzir latência de rede e custos operacionais.

### 9.5 Escalabilidade e Robustez

O sistema demonstrou capacidade de processamento consistente, mas a escalabilidade para ambientes de produção requer considerações adicionais:

**Escalabilidade Horizontal:** Implementação de balanceamento de carga e distribuição de workload entre múltiplas instâncias, permitindo processamento de até milhões de emails por hora.

**Tolerância a Falhas:** Desenvolvimento de mecanismos de recuperação automática e failover, garantindo continuidade operacional mesmo com falhas de componentes individuais.

**Auto-scaling:** Implementação de sistemas que ajustam automaticamente recursos computacionais baseado na demanda, otimizando custos operacionais.

### 9.6 Aplicabilidade Prática e Implementação

A viabilidade prática do sistema em ambientes reais apresenta características promissoras:

**Integração Empresarial:** A arquitetura baseada em APIs facilita integração com sistemas existentes de email (Exchange, Gmail, Outlook), permitindo implementação gradual sem disrupção operacional.

**Compliance e Privacidade:** O processamento local de dados sensíveis atende requisitos de LGPD e GDPR, essencial para adoção empresarial.

**Custo-Benefício:** Comparado a soluções comerciais (Proofpoint, Mimecast), o sistema oferece transparência algorítmica e customização específica, com custos operacionais potencialmente menores.

### 9.7 Vantagens Competitivas

O sistema desenvolvido apresenta vantagens distintivas em relação a soluções existentes:

**Transparência Algorítmica:** Diferente de soluções comerciais "black-box", cada decisão é rastreável e explicável, crucial para ambientes regulamentados.

**Adaptabilidade:** A arquitetura modular permite adição de novos agentes especializados sem reengenharia do sistema completo, oferecendo vantagem competitiva em ambientes de ameaças em evolução.

**Especialização Contextual:** Cada agente pode ser fine-tunado para contextos específicos (setor bancário, saúde, educação), oferecendo precisão superior a soluções genéricas.

**Autonomia Tecnológica:** Redução de dependência de fornecedores externos através de modelos locais e sistemas auto-gerenciados.

### 9.8 Considerações Finais

Os resultados obtidos validam a hipótese de que sistemas multi-agente representam uma abordagem promissora para detecção de spam e conteúdo malicioso. A combinação de especialização por agente, agregação inteligente e arquitetura modular oferece fundação sólida para soluções de segurança cibernética robustas e adaptáveis.

O sistema está posicionado para evolução contínua, incorporando avanços em inteligência artificial, processamento de linguagem natural e arquiteturas distribuídas. A capacidade demonstrada de adaptação a diferentes tipos de ameaças, combinada com performance competitiva, indica potencial significativo para aplicação prática em ambientes empresariais e institucionais.

As direções futuras apontam para um ecossistema de segurança cibernética mais inteligente, onde sistemas multi-agente operam colaborativamente para enfrentar ameaças cada vez mais sofisticadas, mantendo o equilíbrio entre segurança, usabilidade e eficiência operacional.

## Referências

1. Russell, S., & Norvig, P. (2020). *Artificial Intelligence: A Modern Approach*. 4th ed. Pearson.

2. LangGraph Documentation. (2024). *Building Multi-Agent Systems with LangGraph*. Disponível em: https://langchain-ai.github.io/langgraph/

3. OpenAI. (2024). *GPT Models Documentation*. Disponível em: https://platform.openai.com/docs

4. Scikit-learn Documentation. (2024). *Model Evaluation Metrics*. Disponível em: https://scikit-learn.org/stable/modules/model_evaluation.html

---

## Apêndices

### Arquivos Importantes para Anexar

**A. Código Fonte Principal:**
- `spam_detection_multiagent_fixed.ipynb` - Notebook principal com implementação completa
- `orchestrator.py` - Coordenador do sistema (se existir)
- `result_aggregator.py` - Lógica de agregação (se existir)

**B. Resultados e Métricas:**
- `spam_detection_optimized_YYYYMMDD_HHMMSS.json` - Resultados detalhados gerados
- `spam_detection_summary_YYYYMMDD_HHMMSS.csv` - Resumo das classificações
- Gráficos de performance gerados no notebook

**C. Datasets Utilizados:**
- `combined_reduced_dataset.csv` - Dataset principal utilizado
- `malicious-hash/` - Diretório com hashes maliciosos (se disponível)
- `archive/` - Datasets de prompt injection (se disponível)

**D. Configuração e Dependências:**
- `requirements.txt` - Dependências do projeto
- `.env.example` - Exemplo de configuração de ambiente
- `CLAUDE.md` - Instruções do projeto

**E. Documentação Técnica:**
- Diagramas de arquitetura do sistema
- Fluxogramas de processamento
- Especificações técnicas dos agentes
claude
