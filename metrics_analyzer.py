#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema de análise de métricas usando pandas e scikit-learn
Analisa resultados dos agentes e gera relatórios detalhados
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score
)
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import mutual_info_classif
import argparse
import sys
import os
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class MetricsAnalyzer:
    """Analisador de métricas detalhado"""

    def __init__(self):
        self.df = None
        self.metrics = {}
        self.figures = []

    def load_csv(self, csv_path: str):
        """Carrega arquivo CSV"""
        print(f"Loading CSV from: {csv_path}")

        try:
            self.df = pd.read_csv(csv_path)
            print(f"Loaded {len(self.df)} samples with {len(self.df.columns)} features")

            # Verificar colunas essenciais
            required_cols = ['true_label', 'predicted_label_numeric', 'confidence_score']
            missing_cols = [col for col in required_cols if col not in self.df.columns]
            if missing_cols:
                raise ValueError(f"Missing required columns: {missing_cols}")

            return self.df

        except Exception as e:
            raise Exception(f"Failed to load CSV: {e}")

    def calculate_classification_metrics(self):
        """Calcula métricas de classificação"""
        print("Calculating classification metrics...")

        y_true = self.df['true_label']
        y_pred = self.df['predicted_label_numeric']
        y_prob = self.df['confidence_score']

        # Métricas básicas
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='binary')
        recall = recall_score(y_true, y_pred, average='binary')
        f1 = f1_score(y_true, y_pred, average='binary')

        # Métricas por classe
        precision_per_class = precision_score(y_true, y_pred, average=None)
        recall_per_class = recall_score(y_true, y_pred, average=None)
        f1_per_class = f1_score(y_true, y_pred, average=None)

        # AUC e outras métricas de probabilidade
        try:
            auc_roc = roc_auc_score(y_true, y_prob)
            avg_precision = average_precision_score(y_true, y_prob)
        except:
            auc_roc = np.nan
            avg_precision = np.nan

        # Matriz de confusão
        cm = confusion_matrix(y_true, y_pred)

        # Relatório detalhado
        class_report = classification_report(y_true, y_pred, output_dict=True)

        self.metrics['classification'] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'precision_per_class': precision_per_class.tolist(),
            'recall_per_class': recall_per_class.tolist(),
            'f1_per_class': f1_per_class.tolist(),
            'auc_roc': auc_roc,
            'average_precision': avg_precision,
            'confusion_matrix': cm.tolist(),
            'classification_report': class_report
        }

        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall: {recall:.4f}")
        print(f"  F1-Score: {f1:.4f}")
        print(f"  AUC-ROC: {auc_roc:.4f}")

    def analyze_agent_performance(self):
        """Analisa performance individual dos agentes e colaboração"""
        print("Analyzing agent performance and collaboration...")

        # Mapear agentes para colunas de score correspondentes
        agent_mapping = {
            'prompt_injection': 'validation_prompt_injection_score',
            'hash_analyzer': 'validation_hash_score',
            'llm_classifier': 'validation_llm_score',
            'malicious_content': 'validation_malicious_score'
        }

        agent_metrics = {}
        agent_contributions = {}

        for agent, score_col in agent_mapping.items():
            if score_col not in self.df.columns:
                print(f"  Warning: {score_col} not found in data")
                continue

            agent_scores = self.df[score_col].fillna(0)

            # Métricas de contribuição do agente
            active_detections = (agent_scores > 0.1).sum()  # Detecções ativas
            high_confidence_detections = (agent_scores > 0.7).sum()  # Alta confiança
            contribution_rate = active_detections / len(self.df)

            agent_contributions[agent] = {
                'active_detections': active_detections,
                'high_confidence_detections': high_confidence_detections,
                'contribution_rate': contribution_rate,
                'mean_score': agent_scores.mean(),
                'std_score': agent_scores.std(),
                'activation_threshold_01': (agent_scores > 0.1).mean(),
                'activation_threshold_05': (agent_scores > 0.5).mean(),
                'activation_threshold_07': (agent_scores > 0.7).mean()
            }

            # Análise de correlação com decisão final
            final_decision = self.df['predicted_label_numeric']
            correlation_with_final = agent_scores.corr(final_decision)

            agent_contributions[agent]['correlation_with_final_decision'] = correlation_with_final

            print(f"  {agent.upper()}: Active={active_detections}, High_Conf={high_confidence_detections}, Contrib={contribution_rate:.2%}, Corr={correlation_with_final:.3f}")

        # Análise de colaboração entre agentes
        collaboration_metrics = self._analyze_agent_collaboration()

        self.metrics['agent_contributions'] = agent_contributions
        self.metrics['agent_collaboration'] = collaboration_metrics

    def _analyze_agent_collaboration(self):
        """Analisa colaboração e comunicação entre agentes"""
        collaboration = {}

        # Coletar scores dos agentes
        agent_scores = {}
        for agent in ['prompt_injection', 'hash_analyzer', 'llm_classifier', 'malicious_content']:
            score_col = f'validation_{agent}_score'
            if score_col in self.df.columns:
                agent_scores[agent] = self.df[score_col].fillna(0)

        if len(agent_scores) < 2:
            return collaboration

        # Correlações entre agentes
        correlations = {}
        for agent1 in agent_scores:
            for agent2 in agent_scores:
                if agent1 != agent2:
                    corr = agent_scores[agent1].corr(agent_scores[agent2])
                    correlations[f"{agent1}_vs_{agent2}"] = corr

        collaboration['inter_agent_correlations'] = correlations

        # Análise de consenso vs conflito
        all_scores = pd.DataFrame(agent_scores)

        # Casos onde agentes concordam (todos altos ou todos baixos)
        high_threshold = 0.7
        low_threshold = 0.3

        all_high = (all_scores > high_threshold).all(axis=1).sum()
        all_low = (all_scores < low_threshold).all(axis=1).sum()
        mixed_responses = len(all_scores) - all_high - all_low

        collaboration['consensus_analysis'] = {
            'all_agents_high_confidence': all_high,
            'all_agents_low_confidence': all_low,
            'mixed_agent_responses': mixed_responses,
            'consensus_rate': (all_high + all_low) / len(all_scores),
            'conflict_rate': mixed_responses / len(all_scores)
        }

        # Análise de complementaridade - agentes detectando coisas diferentes
        complementarity = {}
        for agent in agent_scores:
            agent_active = agent_scores[agent] > 0.5
            others_inactive = True
            for other_agent in agent_scores:
                if other_agent != agent:
                    others_inactive &= (agent_scores[other_agent] <= 0.5)

            unique_detections = (agent_active & others_inactive).sum()
            complementarity[f"{agent}_unique_detections"] = unique_detections

        collaboration['complementarity'] = complementarity

        # Análise de pesos dinâmicos
        if 'weight_prompt_injection' in self.df.columns:
            weight_analysis = {}
            weight_cols = ['weight_prompt_injection', 'weight_hash', 'weight_llm', 'weight_malicious']
            for col in weight_cols:
                if col in self.df.columns:
                    weights = self.df[col].fillna(0)
                    weight_analysis[col] = {
                        'mean': weights.mean(),
                        'std': weights.std(),
                        'dominant_cases': (weights > 0.4).sum(),  # Casos onde este peso é dominante
                    }
            collaboration['dynamic_weights'] = weight_analysis

        return collaboration

    def analyze_confidence_distribution(self):
        """Analisa distribuição de confiança"""
        print("Analyzing confidence distribution...")

        confidence_stats = {
            'mean': self.df['confidence_score'].mean(),
            'std': self.df['confidence_score'].std(),
            'median': self.df['confidence_score'].median(),
            'min': self.df['confidence_score'].min(),
            'max': self.df['confidence_score'].max(),
            'quartiles': self.df['confidence_score'].quantile([0.25, 0.5, 0.75]).tolist()
        }

        # Análise por classe
        confidence_by_class = {}
        for label in [0, 1]:
            mask = self.df['true_label'] == label
            class_name = 'legitimate' if label == 0 else 'malicious'
            confidence_by_class[class_name] = {
                'mean': self.df[mask]['confidence_score'].mean(),
                'std': self.df[mask]['confidence_score'].std(),
                'count': mask.sum()
            }

        # Análise de casos de baixa e alta confiança
        high_conf_mask = self.df['confidence_score'] > 0.8
        low_conf_mask = self.df['confidence_score'] < 0.3

        confidence_analysis = {
            'overall_stats': confidence_stats,
            'by_class': confidence_by_class,
            'high_confidence': {
                'count': high_conf_mask.sum(),
                'accuracy': (self.df[high_conf_mask]['prediction_correct']).mean() if high_conf_mask.any() else 0
            },
            'low_confidence': {
                'count': low_conf_mask.sum(),
                'accuracy': (self.df[low_conf_mask]['prediction_correct']).mean() if low_conf_mask.any() else 0
            }
        }

        self.metrics['confidence_analysis'] = confidence_analysis

    def analyze_feature_importance(self):
        """Analisa importância das features"""
        print("Analyzing feature importance...")

        # Selecionar features numéricas
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns
        feature_cols = [col for col in numeric_cols if col not in ['sample_id', 'true_label', 'predicted_label_numeric']]

        if len(feature_cols) == 0:
            print("  No numeric features found for importance analysis")
            return

        X = self.df[feature_cols].fillna(0)
        y = self.df['true_label']

        # Mutual Information
        try:
            mi_scores = mutual_info_classif(X, y, random_state=42)
            mi_importance = dict(zip(feature_cols, mi_scores))
            mi_importance = dict(sorted(mi_importance.items(), key=lambda x: x[1], reverse=True))
        except:
            mi_importance = {}

        # Random Forest Feature Importance
        try:
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X, y)
            rf_importance = dict(zip(feature_cols, rf.feature_importances_))
            rf_importance = dict(sorted(rf_importance.items(), key=lambda x: x[1], reverse=True))
        except:
            rf_importance = {}

        self.metrics['feature_importance'] = {
            'mutual_information': mi_importance,
            'random_forest': rf_importance,
            'top_10_features_mi': list(mi_importance.keys())[:10],
            'top_10_features_rf': list(rf_importance.keys())[:10]
        }

        print(f"  Top 5 features (MI): {list(mi_importance.keys())[:5]}")
        print(f"  Top 5 features (RF): {list(rf_importance.keys())[:5]}")

    def analyze_error_cases(self):
        """Analisa casos de erro"""
        print("Analyzing error cases...")

        # Casos de erro
        error_mask = ~self.df['prediction_correct']
        error_cases = self.df[error_mask]

        if len(error_cases) == 0:
            print("  No error cases found!")
            return

        # Análise por tipo de erro
        false_positives = error_cases[error_cases['true_label'] == 0]  # Legitimate classified as malicious
        false_negatives = error_cases[error_cases['true_label'] == 1]  # Malicious classified as legitimate

        error_analysis = {
            'total_errors': len(error_cases),
            'error_rate': len(error_cases) / len(self.df),
            'false_positives': len(false_positives),
            'false_negatives': len(false_negatives),
            'fp_rate': len(false_positives) / len(self.df[self.df['true_label'] == 0]) if len(self.df[self.df['true_label'] == 0]) > 0 else 0,
            'fn_rate': len(false_negatives) / len(self.df[self.df['true_label'] == 1]) if len(self.df[self.df['true_label'] == 1]) > 0 else 0
        }

        # Características dos erros
        if len(error_cases) > 0:
            error_chars = {
                'avg_confidence': error_cases['confidence_score'].mean(),
                'high_conf_errors': (error_cases['confidence_score'] > 0.8).sum(),
                'low_conf_errors': (error_cases['confidence_score'] < 0.3).sum(),
                'unanimous_errors': error_cases['unanimous_agents'].sum() if 'unanimous_agents' in error_cases.columns else 0,
                'conflicting_errors': error_cases['conflicting_agents'].sum() if 'conflicting_agents' in error_cases.columns else 0,
                'critical_detection_errors': error_cases['has_critical_detection'].sum() if 'has_critical_detection' in error_cases.columns else 0
            }
            error_analysis['error_characteristics'] = error_chars

        self.metrics['error_analysis'] = error_analysis

        print(f"  Total errors: {len(error_cases)} ({error_analysis['error_rate']:.2%})")
        print(f"  False Positives: {len(false_positives)}")
        print(f"  False Negatives: {len(false_negatives)}")

    def analyze_multi_agent_effectiveness(self):
        """Analisa efetividade específica do sistema multi-agente"""
        print("Analyzing multi-agent system effectiveness...")

        effectiveness = {}

        # 1. Análise de Critical Threats Detection
        if 'has_critical_detection' in self.df.columns:
            critical_detections = self.df['has_critical_detection'].sum()
            critical_rate = critical_detections / len(self.df)

            # Verificar se critical detections correlacionam com malicious labels
            if critical_detections > 0:
                critical_mask = self.df['has_critical_detection']
                malicious_in_critical = self.df[critical_mask]['true_label'].sum()
                critical_precision = malicious_in_critical / critical_detections if critical_detections > 0 else 0

                effectiveness['critical_threats'] = {
                    'total_critical_detections': critical_detections,
                    'critical_detection_rate': critical_rate,
                    'critical_detection_precision': critical_precision,
                    'critical_among_malicious': malicious_in_critical / self.df['true_label'].sum() if self.df['true_label'].sum() > 0 else 0
                }

        # 2. Análise de LLM Manipulation Detection (especialidade do seu sistema)
        if 'llm_manipulation_detected' in self.df.columns:
            llm_manipulations = self.df['llm_manipulation_detected'].sum()
            effectiveness['llm_manipulation'] = {
                'total_manipulations_detected': llm_manipulations,
                'manipulation_detection_rate': llm_manipulations / len(self.df),
                'manipulation_types': self.df['llm_manipulation_type'].value_counts().to_dict() if 'llm_manipulation_type' in self.df.columns else {}
            }

        # 3. Análise de High Confidence vs Low Confidence Performance
        if 'confidence_score' in self.df.columns:
            high_conf_mask = self.df['confidence_score'] > 0.8
            low_conf_mask = self.df['confidence_score'] < 0.3

            high_conf_accuracy = self.df[high_conf_mask]['prediction_correct'].mean() if high_conf_mask.any() else 0
            low_conf_accuracy = self.df[low_conf_mask]['prediction_correct'].mean() if low_conf_mask.any() else 0

            effectiveness['confidence_reliability'] = {
                'high_confidence_samples': high_conf_mask.sum(),
                'low_confidence_samples': low_conf_mask.sum(),
                'high_confidence_accuracy': high_conf_accuracy,
                'low_confidence_accuracy': low_conf_accuracy,
                'confidence_differentiation': high_conf_accuracy - low_conf_accuracy
            }

        # 4. Análise de System vs Ground Truth Disagreement (pode indicar detecção superior)
        system_malicious = self.df['predicted_label_numeric'] == 1
        ground_truth_malicious = self.df['true_label'] == 1

        # Sistema detectou como malicioso mas ground truth disse legítimo (possíveis novas detecções)
        system_only_detections = system_malicious & ~ground_truth_malicious
        # Ground truth malicioso mas sistema disse legítimo (perdas)
        missed_by_system = ground_truth_malicious & ~system_malicious

        effectiveness['detection_comparison'] = {
            'system_unique_detections': system_only_detections.sum(),
            'system_missed_detections': missed_by_system.sum(),
            'system_vs_ground_truth_agreement': (self.df['predicted_label_numeric'] == self.df['true_label']).mean()
        }

        # 5. Análise de Agent Specialization Effectiveness
        specialization = {}

        # LLM Classifier - Especialista em detecção contextual
        if 'validation_llm_score' in self.df.columns:
            llm_active_mask = self.df['validation_llm_score'] > 0.5
            llm_detections = llm_active_mask.sum()
            llm_correct = (self.df[llm_active_mask]['predicted_label_numeric'] == self.df[llm_active_mask]['true_label']).sum() if llm_detections > 0 else 0

            specialization['llm_classifier'] = {
                'active_detections': llm_detections,
                'accuracy_when_active': llm_correct / llm_detections if llm_detections > 0 else 0,
                'contribution_to_correct_predictions': llm_correct
            }

        # Hash Analyzer - Especialista em conteúdo conhecido
        if 'hash_is_known_malicious' in self.df.columns:
            known_malicious = self.df['hash_is_known_malicious'].sum()
            specialization['hash_analyzer'] = {
                'known_malicious_detected': known_malicious,
                'known_malicious_rate': known_malicious / len(self.df)
            }

        effectiveness['agent_specialization'] = specialization

        self.metrics['multi_agent_effectiveness'] = effectiveness

        # Print key insights
        if 'critical_threats' in effectiveness:
            print(f"  Critical Threats: {effectiveness['critical_threats']['total_critical_detections']} ({effectiveness['critical_threats']['critical_detection_rate']:.2%})")

        if 'llm_manipulation' in effectiveness:
            print(f"  LLM Manipulations: {effectiveness['llm_manipulation']['total_manipulations_detected']} ({effectiveness['llm_manipulation']['manipulation_detection_rate']:.2%})")

        if 'confidence_reliability' in effectiveness:
            print(f"  High Confidence Accuracy: {effectiveness['confidence_reliability']['high_confidence_accuracy']:.3f}")

        if 'detection_comparison' in effectiveness:
            print(f"  System Unique Detections: {effectiveness['detection_comparison']['system_unique_detections']}")
            print(f"  System vs Ground Truth Agreement: {effectiveness['detection_comparison']['system_vs_ground_truth_agreement']:.3f}")

    def generate_visualizations(self, output_dir: str):
        """Gera visualizações"""
        print("Generating visualizations...")

        plt.style.use('default')
        fig_paths = []

        # 1. Confusion Matrix
        if 'classification' in self.metrics:
            fig, ax = plt.subplots(1, 1, figsize=(8, 6))
            cm = np.array(self.metrics['classification']['confusion_matrix'])
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                       xticklabels=['Legitimate', 'Malicious'],
                       yticklabels=['Legitimate', 'Malicious'], ax=ax)
            ax.set_title('Confusion Matrix')
            ax.set_xlabel('Predicted Label')
            ax.set_ylabel('True Label')

            fig_path = os.path.join(output_dir, 'confusion_matrix.png')
            plt.savefig(fig_path, dpi=300, bbox_inches='tight')
            fig_paths.append(fig_path)
            plt.close()

        # 2. Confidence Distribution
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # Histogram
        ax1.hist(self.df['confidence_score'], bins=50, alpha=0.7, color='skyblue', edgecolor='black')
        ax1.set_title('Confidence Score Distribution')
        ax1.set_xlabel('Confidence Score')
        ax1.set_ylabel('Frequency')
        ax1.axvline(self.df['confidence_score'].mean(), color='red', linestyle='--', label='Mean')
        ax1.legend()

        # Box plot by class
        data_for_box = [self.df[self.df['true_label'] == 0]['confidence_score'].dropna(),
                       self.df[self.df['true_label'] == 1]['confidence_score'].dropna()]
        ax2.boxplot(data_for_box, labels=['Legitimate', 'Malicious'])
        ax2.set_title('Confidence by True Label')
        ax2.set_ylabel('Confidence Score')

        fig_path = os.path.join(output_dir, 'confidence_analysis.png')
        plt.savefig(fig_path, dpi=300, bbox_inches='tight')
        fig_paths.append(fig_path)
        plt.close()

        # 3. Agent Performance Comparison
        if 'agent_performance' in self.metrics:
            agents = list(self.metrics['agent_performance'].keys())
            metrics_names = ['accuracy', 'precision', 'recall', 'f1_score']

            fig, ax = plt.subplots(1, 1, figsize=(12, 8))

            x = np.arange(len(agents))
            width = 0.2

            for i, metric in enumerate(metrics_names):
                values = [self.metrics['agent_performance'][agent][metric] for agent in agents]
                ax.bar(x + i*width, values, width, label=metric.capitalize(), alpha=0.8)

            ax.set_title('Agent Performance Comparison')
            ax.set_xlabel('Agents')
            ax.set_ylabel('Score')
            ax.set_xticks(x + width * 1.5)
            # Clean up agent names for display
            display_names = [agent.replace('_', ' ').title() for agent in agents]
            ax.set_xticklabels(display_names, rotation=45, ha='right')
            ax.legend()
            ax.grid(True, alpha=0.3)

            fig_path = os.path.join(output_dir, 'agent_performance.png')
            plt.savefig(fig_path, dpi=300, bbox_inches='tight')
            fig_paths.append(fig_path)
            plt.close()

        # 4. Feature Importance (Top 15)
        if 'feature_importance' in self.metrics and self.metrics['feature_importance']['random_forest']:
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 12))

            # Random Forest
            rf_imp = self.metrics['feature_importance']['random_forest']
            features = list(rf_imp.keys())[:15]
            values = [rf_imp[f] for f in features]

            ax1.barh(range(len(features)), values, color='lightcoral')
            ax1.set_yticks(range(len(features)))
            ax1.set_yticklabels(features)
            ax1.set_title('Feature Importance (Random Forest)')
            ax1.set_xlabel('Importance Score')

            # Mutual Information
            mi_imp = self.metrics['feature_importance']['mutual_information']
            if mi_imp:
                features_mi = list(mi_imp.keys())[:15]
                values_mi = [mi_imp[f] for f in features_mi]

                ax2.barh(range(len(features_mi)), values_mi, color='lightgreen')
                ax2.set_yticks(range(len(features_mi)))
                ax2.set_yticklabels(features_mi)
                ax2.set_title('Feature Importance (Mutual Information)')
                ax2.set_xlabel('MI Score')

            fig_path = os.path.join(output_dir, 'feature_importance.png')
            plt.savefig(fig_path, dpi=300, bbox_inches='tight')
            fig_paths.append(fig_path)
            plt.close()

        # 5. ROC Curve
        if not np.isnan(self.metrics['classification']['auc_roc']):
            y_true = self.df['true_label']
            y_prob = self.df['confidence_score']

            fpr, tpr, _ = roc_curve(y_true, y_prob)

            fig, ax = plt.subplots(1, 1, figsize=(8, 8))
            ax.plot(fpr, tpr, label=f'ROC Curve (AUC = {self.metrics["classification"]["auc_roc"]:.3f})')
            ax.plot([0, 1], [0, 1], 'k--', label='Random')
            ax.set_xlabel('False Positive Rate')
            ax.set_ylabel('True Positive Rate')
            ax.set_title('ROC Curve')
            ax.legend()
            ax.grid(True, alpha=0.3)

            fig_path = os.path.join(output_dir, 'roc_curve.png')
            plt.savefig(fig_path, dpi=300, bbox_inches='tight')
            fig_paths.append(fig_path)
            plt.close()

        return fig_paths

    def generate_report(self, output_dir: str):
        """Gera relatório completo"""
        print("Generating comprehensive report...")

        # Criar diretório
        os.makedirs(output_dir, exist_ok=True)

        # Executar todas as análises
        self.calculate_classification_metrics()
        self.analyze_agent_performance()
        self.analyze_confidence_distribution()
        self.analyze_feature_importance()
        self.analyze_error_cases()
        self.analyze_multi_agent_effectiveness()

        # Gerar visualizações
        fig_paths = self.generate_visualizations(output_dir)

        # Salvar métricas detalhadas
        metrics_path = os.path.join(output_dir, 'detailed_metrics.json')
        self.metrics['generation_info'] = {
            'timestamp': datetime.now().isoformat(),
            'dataset_size': len(self.df),
            'feature_count': len(self.df.columns)
        }

        with open(metrics_path, 'w', encoding='utf-8') as f:
            json.dump(self.metrics, f, indent=2, ensure_ascii=False, default=str)

        # Gerar relatório em texto
        self.generate_text_report(output_dir)

        return metrics_path, fig_paths

    def generate_text_report(self, output_dir: str):
        """Gera relatório em texto"""
        report_path = os.path.join(output_dir, 'analysis_report.txt')

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=== SMA SPAM DETECTOR - ANALYSIS REPORT ===\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Dataset Size: {len(self.df)} samples\n")
            f.write(f"Feature Count: {len(self.df.columns)} features\n\n")

            # Classification Results
            if 'classification' in self.metrics:
                f.write("CLASSIFICATION PERFORMANCE\n")
                f.write("-" * 30 + "\n")
                cls = self.metrics['classification']
                f.write(f"Accuracy:     {cls['accuracy']:.4f}\n")
                f.write(f"Precision:    {cls['precision']:.4f}\n")
                f.write(f"Recall:       {cls['recall']:.4f}\n")
                f.write(f"F1-Score:     {cls['f1_score']:.4f}\n")
                f.write(f"AUC-ROC:      {cls['auc_roc']:.4f}\n")
                f.write(f"Avg Precision: {cls['average_precision']:.4f}\n\n")

            # Agent Performance
            if 'agent_performance' in self.metrics:
                f.write("INDIVIDUAL AGENT PERFORMANCE\n")
                f.write("-" * 35 + "\n")
                for agent, perf in self.metrics['agent_performance'].items():
                    f.write(f"{agent.upper()}:\n")
                    f.write(f"  Accuracy:  {perf['accuracy']:.4f}\n")
                    f.write(f"  Precision: {perf['precision']:.4f}\n")
                    f.write(f"  Recall:    {perf['recall']:.4f}\n")
                    f.write(f"  F1-Score:  {perf['f1_score']:.4f}\n")
                    f.write(f"  AUC-ROC:   {perf['auc_roc']:.4f}\n\n")

            # Error Analysis
            if 'error_analysis' in self.metrics:
                f.write("ERROR ANALYSIS\n")
                f.write("-" * 15 + "\n")
                err = self.metrics['error_analysis']
                f.write(f"Total Errors:     {err['total_errors']} ({err['error_rate']:.2%})\n")
                f.write(f"False Positives:  {err['false_positives']}\n")
                f.write(f"False Negatives:  {err['false_negatives']}\n")
                f.write(f"FP Rate:          {err['fp_rate']:.4f}\n")
                f.write(f"FN Rate:          {err['fn_rate']:.4f}\n\n")

            # Top Features
            if 'feature_importance' in self.metrics:
                f.write("TOP 10 MOST IMPORTANT FEATURES\n")
                f.write("-" * 35 + "\n")
                top_features = self.metrics['feature_importance']['top_10_features_rf']
                for i, feature in enumerate(top_features, 1):
                    f.write(f"{i:2d}. {feature}\n")

        return report_path

def main():
    parser = argparse.ArgumentParser(description='Analyze metrics from JSON/CSV results')
    parser.add_argument('--input', '-i', required=True,
                      help='Path to JSON or CSV results file')
    parser.add_argument('--output', '-o', default='./analysis_results',
                      help='Output directory for analysis results')
    parser.add_argument('--skip-conversion', action='store_true',
                      help='Skip JSON to CSV conversion (input is already CSV)')

    args = parser.parse_args()

    analyzer = MetricsAnalyzer()

    try:
        input_path = args.input

        # Check if we need to convert JSON to CSV first
        if not args.skip_conversion and input_path.endswith('.json'):
            print("Converting JSON to CSV first...")

            from json_to_csv_converter import JSONToCSVConverter

            converter = JSONToCSVConverter()

            # Generate CSV path
            csv_path = input_path.replace('.json', '.csv')

            # Convert
            df, stats = converter.convert(input_path, csv_path)

            print(f"JSON converted to CSV: {csv_path}")
            input_path = csv_path

        # Carregar dados (agora sempre CSV)
        analyzer.load_csv(input_path)

        # Gerar relatório completo
        metrics_path, fig_paths = analyzer.generate_report(args.output)

        print(f"\n[SUCCESS] Analysis completed successfully!")
        print(f"Results saved to: {args.output}")
        print(f"Metrics file: {metrics_path}")
        print(f"Generated {len(fig_paths)} visualizations")

        return 0

    except Exception as e:
        print(f"\n[ERROR] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())