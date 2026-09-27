#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para testar o dataset completo combined_reduced.json
Processa todos os samples e gera JSON de resultados limpos
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List
import argparse
import time
import random
from dataclasses import dataclass

# Importar agentes - ajustar caminho para parent directory
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sanitization_agent import SanitizationAgent
from hash_analyzer import HashAnalyzer
from llm_classifier import LLMClassifier
from malicious_content_agent import MaliciousContentAgent
from prompt_injection_agent import PromptInjectionAgent
from result_aggregator import ResultAggregator

@dataclass
class BatchConfig:
    """Configuração para processamento em lotes"""
    batch_size: int = 10
    checkpoint_interval: int = 5
    retry_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    api_rate_limit: float = 0.5  # segundos entre chamadas de API

class FullDatasetProcessor:
    """Processador do dataset completo"""

    def __init__(self, llm_provider: str = None, llm_model: str = None):
        print("Initializing agents...")
        print("LLM Provider: {llm_provider or 'auto'}")
        print("LLM Model: {llm_model or 'default'}")

        self.sanitization = SanitizationAgent()
        self.hash_analyzer = HashAnalyzer()
        self.llm_classifier = LLMClassifier(provider=llm_provider, model=llm_model)
        self.malicious_content = MaliciousContentAgent()
        self.prompt_injection = PromptInjectionAgent()
        self.result_aggregator = ResultAggregator()

        self.results = []
        self.processed_count = 0
        self.errors = []
        self.batch_config = BatchConfig()
        self.last_api_call = 0

        # Definir fluxo dos agentes (inspired by LangGraph)
        self.agent_flow = self._define_agent_flow()

    def _define_agent_flow(self):
        """Define o fluxo de execução dos agentes inspirado no LangGraph"""
        return {
            # Fase 1: Análise inicial e sanitização
            'phase_1': {
                'agents': ['sanitization'],
                'dependencies': [],
                'critical': True,
                'early_exit_conditions': ['has_injection']
            },

            # Fase 2: Detecção de prompt injection (alta prioridade)
            'phase_2': {
                'agents': ['prompt_injection'],
                'dependencies': ['phase_1'],
                'critical': True,
                'early_exit_conditions': ['is_prompt_injection']
            },

            # Fase 3: Análise paralela dos agentes especialistas
            'phase_3': {
                'agents': ['hash_analyzer', 'llm_classifier', 'malicious_content'],
                'dependencies': ['phase_1'],  # Depende apenas da sanitização
                'critical': False,
                'parallel': True  # Podem executar em paralelo
            },

            # Fase 4: Agregação final
            'phase_4': {
                'agents': ['result_aggregator'],
                'dependencies': ['phase_2', 'phase_3'],
                'critical': True
            }
        }

    def _should_early_exit(self, phase_name: str, results: Dict[str, Any]) -> bool:
        """Verifica se deve sair cedo com base nas condições da fase"""
        phase_config = self.agent_flow.get(phase_name, {})
        conditions = phase_config.get('early_exit_conditions', [])

        for condition in conditions:
            if condition == 'has_injection':
                if results.get('sanitization', {}).get('has_injection', False):
                    return True
            elif condition == 'is_prompt_injection':
                if results.get('prompt_injection', {}).get('is_prompt_injection', False):
                    return True

        return False

    def _execute_agent_phase(self, phase_name: str, email_data: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Executa uma fase específica do fluxo de agentes"""
        phase_config = self.agent_flow[phase_name]
        phase_results = {}

        print(f"Executing {phase_name}...")

        for agent_name in phase_config['agents']:
            try:
                if agent_name == 'sanitization':
                    result, error = self._retry_with_backoff(self.sanitization.process, email_data.get('body', ''))

                elif agent_name == 'prompt_injection':
                    cleaned_data = {'cleaned_text': results.get('sanitization', {}).get('cleaned_text', email_data.get('body', ''))}
                    result, error = self._retry_with_backoff(self.prompt_injection.process, cleaned_data)

                elif agent_name == 'hash_analyzer':
                    cleaned_data = self._prepare_cleaned_data(email_data, results)
                    result, error = self._retry_with_backoff(self.hash_analyzer.process, cleaned_data)

                elif agent_name == 'llm_classifier':
                    cleaned_data = self._prepare_cleaned_data(email_data, results)
                    result, error = self._retry_with_backoff(self.llm_classifier.process, cleaned_data)

                elif agent_name == 'malicious_content':
                    cleaned_data = self._prepare_cleaned_data(email_data, results)
                    result, error = self._retry_with_backoff(self.malicious_content.process, cleaned_data)

                elif agent_name == 'result_aggregator':
                    result, error = self._retry_with_backoff(self.result_aggregator.aggregate, results)

                if error:
                    if phase_config.get('critical', False):
                        raise Exception(f"{agent_name} failed: {error}")
                    else:
                        print(f"{agent_name} warning: {error}")
                        result = self._get_default_result(agent_name)

                phase_results[agent_name] = result
                results[agent_name] = result

            except Exception as e:
                if phase_config.get('critical', False):
                    raise e
                else:
                    print(f"Non-critical agent {agent_name} failed: {e}")
                    phase_results[agent_name] = self._get_default_result(agent_name)
                    results[agent_name] = phase_results[agent_name]

        return phase_results

    def _prepare_cleaned_data(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepara dados limpos para os agentes"""
        return {
            'cleaned_text': results.get('sanitization', {}).get('cleaned_text', email_data.get('body', '')),
            'headers': email_data.get('headers', {}),
            'attachments': email_data.get('attachments', [])
        }

    def _get_default_result(self, agent_name: str) -> Dict[str, Any]:
        """Retorna resultado padrão para agente que falhou"""
        defaults = {
            'sanitization': {'has_injection': False, 'cleaned_text': '', 'risk_score': 0.0},
            'prompt_injection': {'is_prompt_injection': False, 'prompt_injection_score': 0.0},
            'hash_analyzer': {'is_known_malicious': False, 'hash_risk_score': 0.0},
            'llm_classifier': {'llm_classification': 'unknown', 'confidence': 0.5, 'risk_score': 0.5},
            'malicious_content': {'is_malicious': False, 'malicious_risk': 0.0},
            'result_aggregator': {'classification': 'unknown', 'confidence': 0.5, 'is_malicious': False}
        }
        return defaults.get(agent_name, {'error': f'{agent_name}_failed'})

    def _wait_for_rate_limit(self):
        """Controla rate limiting para chamadas de API"""
        current_time = time.time()
        time_since_last = current_time - self.last_api_call

        if time_since_last < self.batch_config.api_rate_limit:
            sleep_time = self.batch_config.api_rate_limit - time_since_last
            time.sleep(sleep_time)

        self.last_api_call = time.time()

    def _retry_with_backoff(self, func, *args, **kwargs):
        """Executa função com retry e backoff exponencial"""
        for attempt in range(self.batch_config.retry_attempts):
            try:
                # Rate limiting antes de chamada de API
                if 'llm_classifier' in str(func):
                    self._wait_for_rate_limit()

                result = func(*args, **kwargs)
                return result, None  # Success, no error

            except Exception as e:
                error_msg = str(e).lower()

                # Se for erro de rate limit ou timeout, aumenta delay
                if any(term in error_msg for term in ['rate limit', 'timeout', 'too many requests', '429']):
                    if attempt < self.batch_config.retry_attempts - 1:
                        delay = min(
                            self.batch_config.base_delay * (2 ** attempt) + random.uniform(0, 1),
                            self.batch_config.max_delay
                        )
                        print(f"Rate limit/timeout detected, waiting {delay:.2f}s before retry {attempt + 1}/{self.batch_config.retry_attempts}")
                        time.sleep(delay)
                        continue

                # Se for último tentativa ou erro não relacionado a rate limit
                if attempt == self.batch_config.retry_attempts - 1:
                    return None, f"Failed after {self.batch_config.retry_attempts} attempts: {e}"

                # Para outros erros, tenta mais rápido
                time.sleep(0.5)

        return None, f"Max retries exceeded"

    def process_sample_with_langgraph_flow(self, sample: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Processa um sample usando o fluxo inspirado no LangGraph"""
        try:
            text = sample.get('text', '')
            true_label = sample.get('label', 0)

            # Criar estrutura de email_data
            email_data = {
                'body': text,
                'cleaned_text': text,
                'attachments': [],
                'headers': {}
            }

            results = {}

            # Executar fases sequencialmente
            for phase_name in ['phase_1', 'phase_2', 'phase_3', 'phase_4']:
                if phase_name in self.agent_flow:
                    phase_results = self._execute_agent_phase(phase_name, email_data, results)

                    # Verificar condições de saída antecipada
                    if self._should_early_exit(phase_name, results):
                        print(f"Early exit triggered at {phase_name}")
                        # Executar apenas agregação final se não foi executada
                        if 'result_aggregator' not in results:
                            final_phase_results = self._execute_agent_phase('phase_4', email_data, results)
                        break

            # Extrai os resultados para a estrutura limpa usando o agregador
            aggregated_result = results.get('result_aggregator', {})
            llm_result = results.get('llm_classifier', {})
            hash_result = results.get('hash_analyzer', {})
            prompt_injection_result = results.get('prompt_injection', {})
            malicious_result = results.get('malicious_content', {})
            sanitization_result = results.get('sanitization', {})
            validation_result = results.get('validation', {})

            # Estrutura de resultado limpa usando agregador
            result = {
                'sample_id': index,
                'true_label': true_label,
                'true_label_text': 'malicious' if true_label == 1 else 'legitimate',
                'predicted_label': aggregated_result.get('classification', 'unknown'),
                'predicted_label_numeric': 1 if aggregated_result.get('is_malicious', False) else 0,
                'confidence_score': round(aggregated_result.get('confidence', 0.0), 4),
                'final_risk_score': round(aggregated_result.get('final_score', 0.0), 4),

                # Agente Sanitization
                'sanitization_has_injection': sanitization_result.get('has_injection', False),
                'sanitization_injection_type': sanitization_result.get('injection_type'),
                'sanitization_entropy': round(sanitization_result.get('entropy', 0.0), 4),
                'sanitization_unicode_obfuscation': sanitization_result.get('unicode_obfuscation', False),
                'sanitization_risk_score': round(sanitization_result.get('risk_score', 0.0), 4),

                # Agente Prompt Injection
                'prompt_injection_detected': prompt_injection_result.get('is_prompt_injection', False),
                'prompt_injection_score': round(prompt_injection_result.get('prompt_injection_score', 0.0), 4),
                'prompt_injection_type': prompt_injection_result.get('prompt_injection_type', 'none'),
                'prompt_injection_patterns': prompt_injection_result.get('detected_patterns', []),

                # Agente Hash
                'hash_md5': hash_result.get('content_md5_hash'),
                'hash_sha256': hash_result.get('content_sha256_hash'),
                'hash_is_known_malicious': hash_result.get('is_known_malicious', False),
                'hash_malware_type': hash_result.get('malware_type'),
                'hash_attachment_risk': round(hash_result.get('attachment_risk', 0.0), 4),
                'hash_risk_score': round(hash_result.get('hash_risk_score', 0.0), 4),

                # Agente LLM
                'llm_classification': llm_result.get('llm_classification'),
                'llm_confidence': round(llm_result.get('confidence', 0.0), 4),
                'llm_manipulation_detected': llm_result.get('manipulation_detected', False),
                'llm_manipulation_type': llm_result.get('manipulation_type'),
                'llm_risk_score': round(llm_result.get('risk_score', 0.0), 4),
                'llm_detected_categories': llm_result.get('detected_categories', []),
                'llm_social_engineering_signals': llm_result.get('social_engineering_signals', []),

                # Agente Malicious Content
                'malicious_urls_found': malicious_result.get('urls_found', 0),
                'malicious_suspicious_urls': malicious_result.get('suspicious_urls', 0),
                'malicious_url_risk_score': round(malicious_result.get('url_risk_score', 0.0), 4),
                'malicious_phishing_score': round(malicious_result.get('phishing_score', 0.0), 4),
                'malicious_risk': round(malicious_result.get('malicious_risk', 0.0), 4),
                'malicious_is_malicious': malicious_result.get('is_malicious', False),
                'malicious_suspicious_signals': malicious_result.get('suspicious_signals', []),

                # Agregação Final
                'aggregation_individual_scores': aggregated_result.get('individual_scores', {}),
                'aggregation_weights_used': aggregated_result.get('weights_used', {}),
                'aggregation_critical_threats': aggregated_result.get('critical_threats', []),
                'aggregation_method': 'langgraph_flow'
            }

            return result

        except Exception as e:
            error_msg = f"Error processing sample {index}: {str(e)}"
            print(error_msg)
            self.errors.append(error_msg)
            return None

    def process_dataset_in_batches(self, dataset_path: str, output_path: str, limit: int = None, 
                                   batch_size: int = 10, checkpoint_interval: int = 5) -> Dict[str, Any]:
        """Processa o dataset em lotes com checkpointing"""
        print("Loading dataset from: {dataset_path}")

        try:
            with open(dataset_path, 'r', encoding='utf-8') as f:
                dataset = json.load(f)
        except Exception as e:
            raise Exception(f"Failed to load dataset: {e}")

        total_samples = len(dataset)
        if limit:
            total_samples = min(limit, total_samples)
            dataset = dataset[:limit]

        print("Processing {total_samples} samples in batches of {batch_size}...")

        # Verificar se há um checkpoint existente
        checkpoint_path = output_path.replace('.json', '_checkpoint.json')
        start_index = 0
        
        if os.path.exists(checkpoint_path):
            print("Found checkpoint file: {checkpoint_path}")
            try:
                with open(checkpoint_path, 'r', encoding='utf-8') as f:
                    checkpoint_data = json.load(f)
                    self.results = checkpoint_data.get('results', [])
                    self.errors = checkpoint_data.get('errors', [])
                    start_index = len(self.results)
                    print("Resuming from sample {start_index}")
            except Exception as e:
                print("Failed to load checkpoint: {e}")
                start_index = 0  # Começar do zero se não conseguir carregar checkpoint

        if start_index >= total_samples:
            print("All samples already processed!")
            return self._create_output_data(dataset_path, total_samples, checkpoint_path)

        print("Starting from sample {start_index} of {total_samples} total samples...")

        start_time = datetime.now()

        # Processar em lotes
        current_batch = []
        current_batch_start_index = start_index
        
        for i in range(start_index, total_samples):
            # Adiciona o sample ao lote atual
            current_batch.append((i, dataset[i]))
            
            # Se o lote atingiu o tamanho ou é o último sample, processa
            if len(current_batch) >= batch_size or i == total_samples - 1:
                print("Processing batch: samples {current_batch_start_index} to {i}")
                
                # Processar todos os samples do lote
                for batch_idx, (sample_idx, sample) in enumerate(current_batch):
                    if sample_idx % 100 == 0:
                        print("Processing sample {sample_idx+1}/{total_samples} ({((sample_idx+1)/total_samples*100):.1f}%)")

                    result = self.process_sample_with_langgraph_flow(sample, sample_idx)
                    if result:
                        self.results.append(result)
                        self.processed_count += 1
                    else:
                        # Se der erro no processamento, adiciona um placeholder
                        error_result = {
                            'sample_id': sample_idx,
                            'error': True,
                            'error_message': f"Failed to process sample {sample_idx}"
                        }
                        self.results.append(error_result)
                    
                    # Rate limiting já está implementado no _retry_with_backoff

                # Salvar checkpoint se necessário
                if (len(self.results) // checkpoint_interval) > ((len(self.results) - len(current_batch)) // checkpoint_interval):
                    self._save_checkpoint(checkpoint_path)
                    print("Checkpoint saved at {len(self.results)} samples processed")

                # Limpar o lote atual
                current_batch = []
                current_batch_start_index = i + 1

        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()

        # Após processamento completo, remover checkpoint
        if os.path.exists(checkpoint_path):
            os.remove(checkpoint_path)
            print("Checkpoint file removed after successful completion")

        return self._create_output_data(dataset_path, total_samples, output_path, processing_time)

    def _save_checkpoint(self, checkpoint_path: str):
        """Salva um checkpoint com os resultados parciais"""
        checkpoint_data = {
            'results': self.results,
            'errors': self.errors,
            'processed_count': self.processed_count,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(checkpoint_path, 'w', encoding='utf-8') as f:
            json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)

    def _create_output_data(self, dataset_path: str, total_samples: int, output_path: str, processing_time: float = None):
        """Cria e salva os dados de saída"""
        if processing_time is None:
            # Se o tempo de processamento não for fornecido, calcular a partir dos resultados existentes
            processing_time = 0  # placeholder

        # Calcular estatísticas básicas apenas para os resultados sem erro
        valid_results = [r for r in self.results if 'error' not in r]
        
        if valid_results:
            correct_predictions = sum(1 for r in valid_results
                                    if r['predicted_label_numeric'] == r['true_label'])
            accuracy = correct_predictions / len(valid_results)
        else:
            accuracy = 0.0

        # Metadata do processamento
        metadata = {
            'dataset_info': {
                'source_file': os.path.basename(dataset_path),
                'total_samples': total_samples,
                'processed_samples': len(valid_results),  # Contar apenas os processados com sucesso
                'failed_samples': len(self.results) - len(valid_results),  # Contar os que falharam
                'processing_time_seconds': round(processing_time, 2) if processing_time > 0 else 0,
                'samples_per_second': round(len(valid_results) / processing_time if processing_time > 0 else 0, 2)
            },
            'llm_config': {
                'provider': self.llm_classifier.provider_name,
                'model': self.llm_classifier.model_name
            },
            'basic_metrics': {
                'accuracy': round(accuracy, 4),
                'malicious_samples': sum(1 for r in valid_results if r['true_label'] == 1),
                'legitimate_samples': sum(1 for r in valid_results if r['true_label'] == 0)
            },
            'errors': self.errors,
            'generated_at': datetime.now().isoformat()
        }

        # Salvar resultados
        output_data = {
            'metadata': metadata,
            'results': self.results
        }

        print("Saving results to: {output_path}")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        # Estatísticas finais
        print("=== PROCESSING SUMMARY ===")
        print("Total samples processed: {len(valid_results)}/{total_samples}")
        print("Processing time: {processing_time:.2f} seconds")
        if processing_time > 0:
            print("Speed: {len(valid_results) / processing_time:.2f} samples/second")
        print("Basic accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print("Errors: {len(self.results) - len(valid_results)}")

        if self.errors:
            print("First 5 errors:")
            for error in self.errors[:5]:
                print("  - {error}")

        return output_data

def main():
    parser = argparse.ArgumentParser(description='Process full phishing dataset')
    parser.add_argument('--dataset', '-d', default='./combined_reduced/combined_reduced.json',
                      help='Path to dataset file')
    parser.add_argument('--output', '-o', default='./test_results/full_dataset_results.json',
                      help='Output path for results')
    parser.add_argument('--limit', '-l', type=int, default=None,
                      help='Limit number of samples to process')
    parser.add_argument('--llm-provider', choices=['openai', 'fallback'], default=None,
                      help='LLM provider to use')
    parser.add_argument('--llm-model', default=None,
                      help='LLM model to use (e.g., gpt-3.5-turbo, gpt-4, gpt-5)')
    parser.add_argument('--batch-size', type=int, default=10,
                      help='Number of samples to process in each batch (default: 10)')
    parser.add_argument('--checkpoint-interval', type=int, default=50,
                      help='How often to save checkpoint (in terms of completed samples)')
    parser.add_argument('--retry-attempts', type=int, default=3,
                      help='Number of retry attempts for failed operations (default: 3)')
    parser.add_argument('--api-rate-limit', type=float, default=0.5,
                      help='Minimum seconds between API calls (default: 0.5)')
    parser.add_argument('--max-delay', type=float, default=60.0,
                      help='Maximum delay for backoff retry (default: 60.0)')

    args = parser.parse_args()

    # Criar diretório de output se não existir
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    # Processar dataset
    processor = FullDatasetProcessor(
        llm_provider=args.llm_provider,
        llm_model=args.llm_model
    )

    # Configurar parâmetros de lote
    processor.batch_config.batch_size = args.batch_size
    processor.batch_config.retry_attempts = args.retry_attempts
    processor.batch_config.api_rate_limit = args.api_rate_limit
    processor.batch_config.max_delay = args.max_delay

    try:
        results = processor.process_dataset_in_batches(
            args.dataset, 
            args.output, 
            args.limit, 
            batch_size=args.batch_size,
            checkpoint_interval=args.checkpoint_interval
        )
        print(f"[SUCCESS] Processing completed successfully!")
        print(f"Results saved to: {args.output}")
        return 0
    except Exception as e:
        print(f"[ERROR] Processing failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())