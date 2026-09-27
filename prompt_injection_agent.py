# agents/prompt_injection_agent.py
import pandas as pd
import re
import os
from typing import List, Dict, Any

try:
    from guardrails.hub import DetectJailbreak
    from guardrails import Guard
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False

class PromptInjectionAgent:
    """
    Detecta tentativas de prompt injection usando:
    1. Patterns conhecidos de jailbreaking
    2. Dataset de prompts maliciosos
    3. Guardrails DetectJailbreak validator (se disponível)
    """

    def __init__(self):
        self.load_prompt_injection_datasets()
        self.setup_guardrails()
        self.setup_detection_patterns()

    def load_prompt_injection_datasets(self):
        """Carrega datasets de prompt injection dos arquivos CSV"""
        self.jailbreak_prompts = []
        self.malicious_prompts = []

        # Caminhos para os arquivos CSV
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        archive_path = os.path.join(base_path, 'archive')

        # Carregar jailbreak_prompts.csv
        jailbreak_file = os.path.join(archive_path, 'jailbreak_prompts.csv')
        if os.path.exists(jailbreak_file):
            try:
                df = pd.read_csv(jailbreak_file)
                if 'Prompt' in df.columns:
                    self.jailbreak_prompts = df['Prompt'].dropna().tolist()
                    print(f"Loaded {len(self.jailbreak_prompts)} jailbreak prompts")
            except Exception as e:
                print(f"Error loading jailbreak prompts: {e}")

        # Carregar outros arquivos de prompt injection
        for filename in ['forbidden_question_set_df.csv', 'malicous_deepset.csv',
                        'forbidden_question_set_with_prompts.csv', 'predictionguard_df.csv']:
            filepath = os.path.join(archive_path, filename)
            if os.path.exists(filepath):
                try:
                    df = pd.read_csv(filepath)
                    # Tentar encontrar colunas com prompts/questions
                    for col in ['prompt', 'Prompt', 'question', 'Question', 'text', 'Text']:
                        if col in df.columns:
                            prompts = df[col].dropna().tolist()
                            self.malicious_prompts.extend(prompts)
                            print(f"Loaded {len(prompts)} prompts from {filename}")
                            break
                except Exception as e:
                    print(f"Error loading {filename}: {e}")

    def setup_guardrails(self):
        """Configura o Guardrails DetectJailbreak validator"""
        if GUARDRAILS_AVAILABLE:
            try:
                # Setup Guard com threshold mais baixo para maior sensibilidade
                self.guard = Guard().use(
                    DetectJailbreak,
                    threshold=0.7,  # Mais sensível que o padrão (0.9)
                    on_fail="noop"
                )
                self.guardrails_enabled = True
                print("Guardrails DetectJailbreak validator enabled")
            except Exception as e:
                print(f"Error setting up Guardrails: {e}")
                self.guardrails_enabled = False
        else:
            self.guardrails_enabled = False
            print("Guardrails not available. Install with: pip install guardrails-ai")

    def setup_detection_patterns(self):
        """Define patterns para detecção de prompt injection"""
        self.injection_patterns = [
            # Patterns comuns de jailbreaking
            r'(?i)(ignore|forget|disregard).{0,20}(previous|above|earlier|prior).{0,20}(instruction|prompt|rule)',
            r'(?i)(act|behave|pretend|roleplay).{0,20}as.{0,20}(dan|evil|jailbreak|unrestricted)',
            r'(?i)(from\s+now\s+on|starting\s+now).{0,30}(you\s+are|act\s+as|behave\s+as)',
            r'(?i)(bypass|override|disable|turn\s+off).{0,20}(safety|filter|restriction|guardrail)',
            r'(?i)\\x[0-9a-f]{2}|\\u[0-9a-f]{4}',  # Encoded characters
            r'(?i)(developer\s+mode|god\s+mode|admin\s+mode|root\s+access)',
            r'(?i)(tell\s+me\s+how\s+to).{0,50}(hack|exploit|manipulate|deceive)',
            r'(?i)(you\s+must|you\s+have\s+to|you\s+are\s+required).{0,30}(answer|respond|tell)',
            r'(?i)(ignore\s+your|forget\s+your).{0,20}(training|programming|guidelines)',
            r'(?i)repeat\s+after\s+me\s*:',
            r'(?i)(chatgpt|gpt|ai\s+language\s+model).{0,30}(jailbreak|break|hack)',
            r'(?i)\\n\\n\\n+',  # Múltiplas quebras de linha para confundir
            r'(?i)(system\s+prompt|system\s+message).{0,20}(override|change|modify)',
        ]

        # Palavras-chave suspeitas
        self.suspicious_keywords = [
            'jailbreak', 'dan', 'unrestricted', 'unfiltered', 'uncensored',
            'bypass', 'override', 'disable', 'ignore instructions',
            'developer mode', 'admin mode', 'god mode', 'root access',
            'forget previous', 'ignore previous', 'disregard previous',
            'act as if', 'pretend to be', 'roleplay as',
            'you are now', 'from now on you are', 'starting now you',
            'break character', 'out of character', 'stop being',
            'hypothetical scenario', 'thought experiment', 'what if'
        ]

    def detect_pattern_injection(self, text: str) -> Dict[str, Any]:
        """Detecta prompt injection usando patterns regex"""
        text_lower = text.lower()
        detected_patterns = []

        # Verificar patterns regex
        for pattern in self.injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                detected_patterns.append(pattern)

        # Verificar palavras-chave suspeitas
        keyword_count = 0
        detected_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                keyword_count += 1
                detected_keywords.append(keyword)

        # Calcular score baseado em patterns e keywords
        pattern_score = len(detected_patterns) * 0.3
        keyword_score = keyword_count * 0.15

        return {
            'pattern_score': min(pattern_score, 1.0),
            'keyword_score': min(keyword_score, 1.0),
            'detected_patterns': detected_patterns,
            'detected_keywords': detected_keywords,
            'total_patterns': len(detected_patterns),
            'total_keywords': keyword_count
        }

    def detect_similarity_injection(self, text: str) -> Dict[str, Any]:
        """Detecta similaridade com prompts conhecidos de injection"""
        text_lower = text.lower().strip()

        # Verificar similaridade com jailbreak prompts conhecidos
        jailbreak_matches = 0
        malicious_matches = 0

        for prompt in self.jailbreak_prompts:
            if isinstance(prompt, str):
                # Verificar substring match (mais rápido que similarity completa)
                prompt_lower = prompt.lower().strip()
                if len(prompt_lower) > 50:  # Apenas prompts longos
                    # Verificar se há overlap significativo
                    words_prompt = set(prompt_lower.split())
                    words_text = set(text_lower.split())
                    if len(words_prompt) > 0:
                        overlap = len(words_prompt.intersection(words_text)) / len(words_prompt)
                        if overlap > 0.3:  # 30% de overlap
                            jailbreak_matches += 1

        for prompt in self.malicious_prompts:
            if isinstance(prompt, str):
                prompt_lower = prompt.lower().strip()
                if len(prompt_lower) > 50:
                    words_prompt = set(prompt_lower.split())
                    words_text = set(text_lower.split())
                    if len(words_prompt) > 0:
                        overlap = len(words_prompt.intersection(words_text)) / len(words_prompt)
                        if overlap > 0.3:
                            malicious_matches += 1

        similarity_score = min((jailbreak_matches + malicious_matches) * 0.4, 1.0)

        return {
            'similarity_score': similarity_score,
            'jailbreak_matches': jailbreak_matches,
            'malicious_matches': malicious_matches
        }

    def detect_guardrails_injection(self, text: str) -> Dict[str, Any]:
        """Detecta prompt injection usando Guardrails"""
        if not self.guardrails_enabled:
            return {
                'guardrails_score': 0.0,
                'guardrails_detected': False,
                'guardrails_error': 'Not available'
            }

        try:
            result = self.guard.validate(text)
            # Se passou na validação, não é jailbreak
            return {
                'guardrails_score': 0.0,
                'guardrails_detected': False,
                'guardrails_result': 'passed'
            }
        except Exception as e:
            # Se falhou na validação, provavelmente é jailbreak
            return {
                'guardrails_score': 0.8,  # Alto score se Guardrails detectou
                'guardrails_detected': True,
                'guardrails_error': str(e)
            }

    def analyze_text_structure(self, text: str) -> Dict[str, Any]:
        """Analisa estrutura do texto para detectar tentativas de manipulation"""
        structure_score = 0.0
        signals = []

        # Múltiplas quebras de linha (tentativa de confundir)
        if text.count('\n') > text.count(' ') * 0.3:
            structure_score += 0.2
            signals.append('excessive_line_breaks')

        # Caracteres especiais em excesso
        special_chars = len(re.findall(r'[^\w\s]', text))
        if special_chars > len(text) * 0.2:
            structure_score += 0.3
            signals.append('excessive_special_chars')

        # Repetição excessiva de palavras
        words = text.lower().split()
        if len(words) > 0:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.5:  # Muita repetição
                structure_score += 0.2
                signals.append('excessive_repetition')

        # Texto muito longo (possível tentativa de overflow)
        if len(text) > 5000:
            structure_score += 0.1
            signals.append('excessive_length')

        return {
            'structure_score': min(structure_score, 1.0),
            'structure_signals': signals
        }

    def process(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Análise principal de prompt injection"""
        text = email_data.get('cleaned_text', '')

        # Executar todas as detecções
        pattern_result = self.detect_pattern_injection(text)
        similarity_result = self.detect_similarity_injection(text)
        guardrails_result = self.detect_guardrails_injection(text)
        structure_result = self.analyze_text_structure(text)

        # Calcular score final (weighted average)
        final_score = (
            pattern_result['pattern_score'] * 0.3 +
            pattern_result['keyword_score'] * 0.2 +
            similarity_result['similarity_score'] * 0.2 +
            guardrails_result['guardrails_score'] * 0.2 +
            structure_result['structure_score'] * 0.1
        )

        # Determinar se é prompt injection
        is_injection = final_score > 0.5

        # Gerar explicação detalhada
        explanation = self.generate_explanation(
            pattern_result, similarity_result,
            guardrails_result, structure_result,
            final_score, is_injection
        )

        return {
            'prompt_injection_score': min(final_score, 1.0),
            'is_prompt_injection': is_injection,
            'pattern_detection': pattern_result,
            'similarity_detection': similarity_result,
            'guardrails_detection': guardrails_result,
            'structure_analysis': structure_result,
            'explanation': explanation,
            'agent': 'prompt_injection'
        }

    def generate_explanation(self, pattern_result, similarity_result,
                           guardrails_result, structure_result,
                           final_score, is_injection):
        """Gera explicação detalhada da detecção"""
        explanation = []

        if is_injection:
            explanation.append("⚠️ PROMPT INJECTION DETECTADO:")
        else:
            explanation.append("✅ Texto parece seguro:")

        if pattern_result['total_patterns'] > 0:
            explanation.append(f"- {pattern_result['total_patterns']} patterns suspeitos detectados")

        if pattern_result['total_keywords'] > 0:
            explanation.append(f"- {pattern_result['total_keywords']} palavras-chave suspeitas")

        if similarity_result['jailbreak_matches'] > 0:
            explanation.append(f"- {similarity_result['jailbreak_matches']} similaridades com jailbreaks conhecidos")

        if similarity_result['malicious_matches'] > 0:
            explanation.append(f"- {similarity_result['malicious_matches']} similaridades com prompts maliciosos")

        if guardrails_result['guardrails_detected']:
            explanation.append("- Guardrails DetectJailbreak ativado")

        if structure_result['structure_signals']:
            explanation.append(f"- Sinais estruturais: {', '.join(structure_result['structure_signals'])}")

        explanation.append(f"- Score final: {final_score:.3f}")

        if is_injection:
            explanation.append("\n🛡️ GUARDRAILS ATIVADOS:")
            explanation.append("- Ignorando possível tentativa de manipulação")
            explanation.append("- Mantendo comportamento seguro e ético")
            explanation.append("- Processando apenas o contexto legítimo da mensagem")

        return "\n".join(explanation)