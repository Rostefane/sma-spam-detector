#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script para converter resultados JSON em CSV formatado
Converte os resultados dos agentes para análise com pandas/scikit-learn
"""

import json
import pandas as pd
import numpy as np
import argparse
import sys
import os
from datetime import datetime

class JSONToCSVConverter:
    """Converte resultados JSON para CSV formatado"""

    def __init__(self):
        self.df = None
        self.metadata = None

    def load_json(self, json_path: str):
        """Carrega arquivo JSON de resultados"""
        print(f"Loading JSON from: {json_path}")

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.metadata = data.get('metadata', {})
            results = data.get('results', [])

            if not results:
                raise ValueError("No results found in JSON file")

            print(f"Loaded {len(results)} samples")
            return results

        except Exception as e:
            raise Exception(f"Failed to load JSON: {e}")

    def convert_to_dataframe(self, results: list) -> pd.DataFrame:
        """Converte resultados para DataFrame pandas"""
        print("Converting to DataFrame...")

        # Lista para armazenar todas as linhas
        rows = []

        for result in results:
            # Criar linha base
            row = {
                # Identificação
                'sample_id': result.get('sample_id'),
                'true_label': result.get('true_label'),
                'true_label_text': result.get('true_label_text'),
                'predicted_label': result.get('predicted_label'),
                'predicted_label_numeric': result.get('predicted_label_numeric'),
                'confidence_score': result.get('confidence_score'),
                'confidence_interval': result.get('confidence_interval'),

                # Sanitization Agent
                'sanitization_has_injection': result.get('sanitization_has_injection'),
                'sanitization_injection_type': result.get('sanitization_injection_type'),
                'sanitization_entropy': result.get('sanitization_entropy'),
                'sanitization_unicode_obfuscation': result.get('sanitization_unicode_obfuscation'),
                'sanitization_risk_score': result.get('sanitization_risk_score'),

                # Hash Analyzer
                'hash_md5': result.get('hash_md5'),
                'hash_sha256': result.get('hash_sha256'),
                'hash_is_known_malicious': result.get('hash_is_known_malicious'),
                'hash_malware_type': result.get('hash_malware_type'),
                'hash_attachment_risk': result.get('hash_attachment_risk'),
                'hash_risk_score': result.get('hash_risk_score'),

                # LLM Classifier
                'llm_classification': result.get('llm_classification'),
                'llm_confidence': result.get('llm_confidence'),
                'llm_manipulation_detected': result.get('llm_manipulation_detected'),
                'llm_manipulation_type': result.get('llm_manipulation_type'),
                'llm_risk_score': result.get('llm_risk_score'),
                'llm_detected_categories_count': len(result.get('llm_detected_categories', [])),
                'llm_social_engineering_signals_count': len(result.get('llm_social_engineering_signals', [])),

                # Malicious Content Agent
                'malicious_urls_found': result.get('malicious_urls_found'),
                'malicious_suspicious_urls': result.get('malicious_suspicious_urls'),
                'malicious_url_risk_score': result.get('malicious_url_risk_score'),
                'malicious_phishing_score': result.get('malicious_phishing_score'),
                'malicious_risk': result.get('malicious_risk'),
                'malicious_is_malicious': result.get('malicious_is_malicious'),
                'malicious_suspicious_signals_count': len(result.get('malicious_suspicious_signals', [])),

                # Prompt Injection Agent
                'prompt_injection_detected': result.get('prompt_injection_detected'),
                'prompt_injection_score': result.get('prompt_injection_score'),
                'prompt_injection_type': result.get('prompt_injection_type'),
                'prompt_injection_patterns_count': len(result.get('prompt_injection_patterns', [])),

                # Validation Scores (using aggregation_individual_scores)
                'validation_prompt_injection_score': result.get('aggregation_individual_scores', {}).get('prompt_injection', 0),
                'validation_hash_score': result.get('aggregation_individual_scores', {}).get('hash_analyzer', 0),
                'validation_llm_score': result.get('aggregation_individual_scores', {}).get('llm_classifier', 0),
                'validation_malicious_score': result.get('aggregation_individual_scores', {}).get('malicious_content', 0),

                # Dynamic Weights (using aggregation_weights_used)
                'weight_prompt_injection': result.get('aggregation_weights_used', {}).get('prompt_injection', 0),
                'weight_hash': result.get('aggregation_weights_used', {}).get('hash_analyzer', 0),
                'weight_llm': result.get('aggregation_weights_used', {}).get('llm_classifier', 0),
                'weight_malicious': result.get('aggregation_weights_used', {}).get('malicious_content', 0),

                # Critical Detections
                'critical_detections_count': len(result.get('aggregation_critical_threats', [])),
                'has_critical_detection': len(result.get('aggregation_critical_threats', [])) > 0,

                # Derived Features
                'prediction_correct': result.get('predicted_label_numeric') == result.get('true_label'),
                'high_confidence': result.get('confidence_score', 0) > 0.8,
                'low_confidence': result.get('confidence_score', 0) < 0.3,
                'unanimous_agents': self._check_unanimous_prediction(result),
                'conflicting_agents': self._check_conflicting_predictions(result)
            }

            # Adicionar colunas categóricas expandidas (one-hot encoding)
            self._add_categorical_features(row, result)

            rows.append(row)

        # Criar DataFrame
        df = pd.DataFrame(rows)

        # Converter tipos de dados
        df = self._optimize_dtypes(df)

        print(f"Created DataFrame with {len(df)} rows and {len(df.columns)} columns")
        return df

    def _check_unanimous_prediction(self, result: dict) -> bool:
        """Verifica se todos os agentes concordam na classificação"""
        scores = result.get('aggregation_individual_scores', {})
        if not scores:
            return False

        threshold = 0.5
        predictions = [score > threshold for score in scores.values()]
        return len(set(predictions)) == 1

    def _check_conflicting_predictions(self, result: dict) -> bool:
        """Verifica se há conflito significativo entre agentes"""
        scores = result.get('aggregation_individual_scores', {})
        if not scores:
            return False

        score_values = list(scores.values())
        return max(score_values) - min(score_values) > 0.6

    def _add_categorical_features(self, row: dict, result: dict):
        """Adiciona features categóricas expandidas"""
        # LLM Categories
        llm_categories = result.get('llm_detected_categories', [])
        common_categories = ['urgency', 'money', 'action', 'threat', 'deception', 'phishing', 'spam']

        for cat in common_categories:
            row[f'llm_category_{cat}'] = cat in llm_categories

        # Social Engineering Signals
        social_signals = result.get('llm_social_engineering_signals', [])
        common_signals = ['urgency_pressure', 'authority_appeal', 'curiosity_appeal']

        for signal in common_signals:
            row[f'social_eng_{signal}'] = signal in social_signals

        # Malicious Signals
        malicious_signals = result.get('malicious_suspicious_signals', [])
        common_malicious = ['excessive_spacing', 'excessive_line_breaks', 'unicode_direction_override']

        for signal in common_malicious:
            row[f'malicious_signal_{signal}'] = signal in malicious_signals

        # Injection Types
        injection_types = ['high_entropy', 'unicode_obfuscation', 'role_playing_attempt', 'context_escape']
        injection_type = result.get('sanitization_injection_type')

        for inj_type in injection_types:
            row[f'injection_{inj_type}'] = injection_type == inj_type

    def _optimize_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Otimiza tipos de dados do DataFrame"""
        print("Optimizing data types...")

        # Boolean columns
        bool_columns = [col for col in df.columns if col.startswith(('has_', 'is_', 'prediction_', 'high_', 'low_', 'unanimous_', 'conflicting_', 'llm_category_', 'social_eng_', 'malicious_signal_', 'injection_'))]
        for col in bool_columns:
            if col in df.columns:
                df[col] = df[col].astype('bool')

        # Integer columns
        int_columns = ['sample_id', 'true_label', 'predicted_label_numeric', 'malicious_urls_found',
                      'malicious_suspicious_urls', 'llm_detected_categories_count',
                      'llm_social_engineering_signals_count', 'malicious_suspicious_signals_count',
                      'critical_detections_count', 'prompt_injection_patterns_count']
        for col in int_columns:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')

        # Float columns - manter precisão
        float_columns = [col for col in df.columns if 'score' in col or 'confidence' in col or 'weight' in col or 'entropy' in col or 'risk' in col]
        for col in float_columns:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('float64')

        # Category columns
        category_columns = ['true_label_text', 'predicted_label', 'llm_classification',
                           'sanitization_injection_type', 'hash_malware_type', 'llm_manipulation_type',
                           'prompt_injection_type']
        for col in category_columns:
            if col in df.columns:
                df[col] = df[col].astype('category')

        return df

    def generate_summary_stats(self, df: pd.DataFrame) -> dict:
        """Gera estatísticas resumidas do dataset"""
        print("Generating summary statistics...")

        stats = {
            'dataset_shape': df.shape,
            'class_distribution': df['true_label'].value_counts().to_dict(),
            'prediction_accuracy': (df['prediction_correct'].sum() / len(df)) if len(df) > 0 else 0,

            'confidence_stats': {
                'mean': df['confidence_score'].mean(),
                'std': df['confidence_score'].std(),
                'min': df['confidence_score'].min(),
                'max': df['confidence_score'].max(),
                'high_confidence_rate': (df['high_confidence'].sum() / len(df)) if len(df) > 0 else 0,
                'low_confidence_rate': (df['low_confidence'].sum() / len(df)) if len(df) > 0 else 0,
            },

            'agent_performance': {
                'unanimous_predictions': (df['unanimous_agents'].sum() / len(df)) if len(df) > 0 else 0,
                'conflicting_predictions': (df['conflicting_agents'].sum() / len(df)) if len(df) > 0 else 0,
                'critical_detections_rate': (df['has_critical_detection'].sum() / len(df)) if len(df) > 0 else 0,
            },

            'feature_stats': {
                'sanitization_injection_rate': (df['sanitization_has_injection'].sum() / len(df)) if len(df) > 0 else 0,
                'prompt_injection_rate': (df['prompt_injection_detected'].sum() / len(df)) if len(df) > 0 else 0,
                'known_malware_rate': (df['hash_is_known_malicious'].sum() / len(df)) if len(df) > 0 else 0,
                'llm_manipulation_rate': (df['llm_manipulation_detected'].sum() / len(df)) if len(df) > 0 else 0,
                'avg_urls_per_sample': df['malicious_urls_found'].mean(),
            }
        }

        return stats

    def save_csv(self, df: pd.DataFrame, csv_path: str, stats: dict = None):
        """Salva DataFrame como CSV"""
        print(f"Saving CSV to: {csv_path}")

        # Criar diretório se não existir
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        # Salvar CSV principal
        df.to_csv(csv_path, index=False, encoding='utf-8')

        # Salvar estatísticas separadamente
        if stats:
            stats_path = csv_path.replace('.csv', '_stats.json')

            def convert_numpy_and_keys(obj):
                """Convert numpy objects and dict keys to Python native types"""
                if isinstance(obj, dict):
                    # Convert dict keys to strings and values recursively
                    return {str(k): convert_numpy_and_keys(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_numpy_and_keys(item) for item in obj]
                elif isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, np.ndarray):
                    return obj.tolist()
                elif pd.isna(obj):
                    return None
                return obj

            # Convert the entire stats object
            converted_stats = convert_numpy_and_keys(stats)

            with open(stats_path, 'w', encoding='utf-8') as f:
                json.dump(converted_stats, f, indent=2, ensure_ascii=False, default=str)
            print(f"Statistics saved to: {stats_path}")

        # Salvar info sobre colunas
        info_path = csv_path.replace('.csv', '_columns_info.txt')
        with open(info_path, 'w', encoding='utf-8') as f:
            f.write("COLUMN DESCRIPTIONS\n")
            f.write("==================\n\n")
            f.write("IDENTIFICATION\n")
            f.write("- sample_id: Unique identifier for each sample\n")
            f.write("- true_label: Ground truth (0=legitimate, 1=malicious)\n")
            f.write("- predicted_label: Agent prediction (legitimate/malicious)\n")
            f.write("- prediction_correct: Boolean indicating correct prediction\n\n")

            f.write("CONFIDENCE METRICS\n")
            f.write("- confidence_score: Final confidence score (0-1)\n")
            f.write("- confidence_interval: Confidence interval measure\n")
            f.write("- high_confidence: Boolean for scores > 0.8\n")
            f.write("- low_confidence: Boolean for scores < 0.3\n\n")

            f.write("AGENT OUTPUTS\n")
            f.write("- sanitization_*: Sanitization agent outputs\n")
            f.write("- hash_*: Hash analyzer outputs\n")
            f.write("- llm_*: LLM classifier outputs\n")
            f.write("- malicious_*: Malicious content agent outputs\n")
            f.write("- validation_*: Final validation scores\n")
            f.write("- weight_*: Dynamic weights used in final decision\n\n")

            f.write("DERIVED FEATURES\n")
            f.write("- unanimous_agents: All agents agree on classification\n")
            f.write("- conflicting_agents: Significant disagreement between agents\n")
            f.write("- has_critical_detection: Any critical threat detected\n")
            f.write("- *_category_*: One-hot encoded categorical features\n")

        print(f"Column information saved to: {info_path}")

    def convert(self, json_path: str, csv_path: str):
        """Processo completo de conversão"""
        try:
            # Carregar JSON
            results = self.load_json(json_path)

            # Converter para DataFrame
            df = self.convert_to_dataframe(results)
            self.df = df

            # Gerar estatísticas
            stats = self.generate_summary_stats(df)

            # Adicionar metadata original (convert to serializable format)
            try:
                stats['original_metadata'] = self.metadata
            except:
                stats['original_metadata'] = str(self.metadata)
            stats['conversion_timestamp'] = datetime.now().isoformat()

            # Salvar CSV e estatísticas
            self.save_csv(df, csv_path, stats)

            print(f"\n=== CONVERSION SUMMARY ===")
            print(f"Input JSON: {json_path}")
            print(f"Output CSV: {csv_path}")
            print(f"Samples: {len(df)}")
            print(f"Features: {len(df.columns)}")
            print(f"Accuracy: {stats['prediction_accuracy']:.4f}")
            print(f"Class distribution: {stats['class_distribution']}")

            return df, stats

        except Exception as e:
            print(f"[ERROR] Conversion failed: {e}")
            raise

def main():
    parser = argparse.ArgumentParser(description='Convert JSON results to CSV format')
    parser.add_argument('--input', '-i', required=True,
                      help='Path to JSON results file')
    parser.add_argument('--output', '-o', required=True,
                      help='Output path for CSV file')

    args = parser.parse_args()

    converter = JSONToCSVConverter()

    try:
        df, stats = converter.convert(args.input, args.output)
        print(f"\n[SUCCESS] Conversion completed successfully!")
        return 0
    except Exception as e:
        print(f"\n[ERROR] Conversion failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())