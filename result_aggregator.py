# agents/result_aggregator.py
from typing import Dict, Any, List

class ResultAggregator:
    """Agregador simples que combina resultados dos 4 agentes especializados"""

    def __init__(self, weights: Dict[str, float] = None):
        # Pesos padrão para cada agente
        self.weights = weights or {
            'prompt_injection': 0.30,  # Alta prioridade para prompt injection
            'hash_analyzer': 0.25,     # Hash de malware tem alta confiabilidade
            'llm_classifier': 0.25,    # LLM para análise contextual
            'malicious_content': 0.20  # URLs e phishing
        }

        # Verificar se pesos somam 1.0
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            # Normalizar pesos
            self.weights = {k: v/total_weight for k, v in self.weights.items()}

    def extract_risk_scores(self, agent_results: Dict[str, Any]) -> Dict[str, float]:
        """Extrai scores de risco normalizados de cada agente"""
        scores = {}

        # Prompt Injection Agent
        if 'prompt_injection' in agent_results:
            pi_result = agent_results['prompt_injection']
            scores['prompt_injection'] = float(pi_result.get('prompt_injection_score', 0.0))

        # Hash Analyzer
        if 'hash_analyzer' in agent_results:
            hash_result = agent_results['hash_analyzer']
            scores['hash_analyzer'] = float(hash_result.get('hash_risk_score', 0.0))

        # LLM Classifier
        if 'llm_classifier' in agent_results:
            llm_result = agent_results['llm_classifier']
            scores['llm_classifier'] = float(llm_result.get('risk_score', 0.0))

        # Malicious Content Agent
        if 'malicious_content' in agent_results:
            mal_result = agent_results['malicious_content']
            scores['malicious_content'] = float(mal_result.get('malicious_risk', 0.0))

        return scores

    def detect_critical_threats(self, agent_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detecta ameaças críticas que devem ter prioridade máxima"""
        critical_threats = []

        # Prompt Injection detectado
        if agent_results.get('prompt_injection', {}).get('is_prompt_injection', False):
            critical_threats.append({
                'agent': 'prompt_injection',
                'threat_type': 'prompt_injection',
                'confidence': agent_results['prompt_injection'].get('prompt_injection_score', 0.0),
                'priority': 'high'
            })

        # Hash malicioso conhecido
        if agent_results.get('hash_analyzer', {}).get('is_known_malicious', False):
            critical_threats.append({
                'agent': 'hash_analyzer',
                'threat_type': 'known_malware',
                'confidence': 1.0,  # Hash conhecido tem confiança máxima
                'priority': 'critical'
            })

        # LLM detectou manipulação
        if agent_results.get('llm_classifier', {}).get('manipulation_detected', False):
            critical_threats.append({
                'agent': 'llm_classifier',
                'threat_type': 'llm_manipulation',
                'confidence': agent_results['llm_classifier'].get('confidence', 0.0),
                'priority': 'high'
            })

        # Conteúdo malicioso detectado
        if agent_results.get('malicious_content', {}).get('is_malicious', False):
            critical_threats.append({
                'agent': 'malicious_content',
                'threat_type': 'malicious_content',
                'confidence': agent_results['malicious_content'].get('malicious_risk', 0.0),
                'priority': 'medium'
            })

        return critical_threats

    def calculate_confidence_score(self, risk_scores: Dict[str, float]) -> float:
        """Calcula confiança baseada na consistência entre agentes"""
        if not risk_scores:
            return 0.0

        scores = list(risk_scores.values())

        # Se todos os scores estão próximos, alta confiança
        if len(scores) > 1:
            mean_score = sum(scores) / len(scores)
            variance = sum((s - mean_score) ** 2 for s in scores) / len(scores)

            # Confiança inversa à variância
            confidence = max(0.1, 1.0 - variance)

            # Boost de confiança se scores são consistentemente altos ou baixos
            if all(s > 0.7 for s in scores) or all(s < 0.3 for s in scores):
                confidence = min(confidence + 0.2, 1.0)

            return confidence
        else:
            # Se apenas um agente, confiança baseada no score
            return min(scores[0] + 0.3, 1.0)

    def aggregate(self, agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Agrega resultados de todos os agentes em classificação final"""

        # Extrair scores de risco
        risk_scores = self.extract_risk_scores(agent_results)

        # Detectar ameaças críticas
        critical_threats = self.detect_critical_threats(agent_results)

        # Se há ameaças críticas, priorizar
        if critical_threats:
            # Pegar a ameaça com maior prioridade
            critical_priorities = {'critical': 3, 'high': 2, 'medium': 1}
            top_threat = max(critical_threats,
                           key=lambda x: critical_priorities.get(x['priority'], 0))

            final_score = max(0.85, top_threat['confidence'])
            is_malicious = True
            classification = 'malicious'

            # Confiança alta para detecções críticas
            confidence = min(top_threat['confidence'] + 0.2, 1.0)

        else:
            # Agregação ponderada normal
            final_score = 0.0
            total_weight = 0.0

            for agent, score in risk_scores.items():
                if agent in self.weights:
                    weight = self.weights[agent]
                    final_score += score * weight
                    total_weight += weight

            # Normalizar se nem todos os agentes estão presentes
            if total_weight > 0:
                final_score = final_score / total_weight

            is_malicious = final_score > 0.5
            classification = 'malicious' if is_malicious else 'legitimate'

            # Calcular confiança
            confidence = self.calculate_confidence_score(risk_scores)

        return {
            'classification': classification,
            'is_malicious': is_malicious,
            'confidence': min(final_score, 1.0),
            'confidence_interval': confidence,
            'final_score': final_score,
            'individual_scores': risk_scores,
            'weights_used': self.weights,
            'critical_threats': critical_threats,
            'agent_count': len(risk_scores),
            'aggregation_method': 'critical_priority' if critical_threats else 'weighted_average'
        }

    def generate_explanation(self, result: Dict[str, Any]) -> str:
        """Gera explicação da decisão de agregação"""
        explanation = []

        if result['is_malicious']:
            explanation.append("🚨 CONTEÚDO CLASSIFICADO COMO MALICIOSO")
        else:
            explanation.append("✅ CONTEÚDO CLASSIFICADO COMO LEGÍTIMO")

        explanation.append(f"Score final: {result['final_score']:.3f}")
        explanation.append(f"Confiança: {result['confidence_interval']:.3f}")
        explanation.append(f"Método: {result['aggregation_method']}")

        # Mostrar scores individuais
        explanation.append("\n📊 Scores por agente:")
        for agent, score in result['individual_scores'].items():
            weight = result['weights_used'].get(agent, 0.0)
            explanation.append(f"  • {agent}: {score:.3f} (peso: {weight:.2f})")

        # Mostrar ameaças críticas
        if result['critical_threats']:
            explanation.append(f"\n⚠️ {len(result['critical_threats'])} ameaça(s) crítica(s):")
            for threat in result['critical_threats']:
                explanation.append(f"  • {threat['threat_type']} ({threat['priority']}) - {threat['confidence']:.3f}")

        return "\n".join(explanation)