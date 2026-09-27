# agents/hash_analyzer.py
import hashlib
import json
import os
from typing import Dict, List, Any, Set

class HashAnalyzer:
    """Agente que verifica hashes de anexos e conteúdo contra base de malware conhecida"""

    def __init__(self):
        self.known_malicious_hashes = self.load_malicious_hashes()
        self.suspicious_patterns = [
            '.exe', '.bat', '.cmd', '.scr', '.vbs', '.zip', '.rar', '.js', '.hta',
            '.jar', '.com', '.pif', '.msi', '.dll', '.bin', '.deb', '.rpm'
        ]

    def load_malicious_hashes(self) -> Dict[str, str]:
        """Carrega base de hashes maliciosos dos arquivos txt da pasta malicious-hash"""
        malicious_hashes = {}

        # Base path para os arquivos de hash
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        hash_path = os.path.join(base_path, 'malicious-hash')

        # Carregar hashes MD5
        md5_file = os.path.join(hash_path, 'full-hash-md5-aa.txt')
        md5_hashes = self.load_hash_file(md5_file, 'MD5')
        malicious_hashes.update(md5_hashes)
        print(f"Loaded {len(md5_hashes)} MD5 malicious hashes")

        # Carregar hashes SHA1
        sha1_file = os.path.join(hash_path, 'full-hash-sha1-aa.txt')
        sha1_hashes = self.load_hash_file(sha1_file, 'SHA1')
        malicious_hashes.update(sha1_hashes)
        print(f"Loaded {len(sha1_hashes)} SHA1 malicious hashes")

        # Carregar hashes SHA256
        sha256_file = os.path.join(hash_path, 'full-hash-sha256-aa.txt')
        sha256_hashes = self.load_hash_file(sha256_file, 'SHA256')
        malicious_hashes.update(sha256_hashes)
        print(f"Loaded {len(sha256_hashes)} SHA256 malicious hashes")

        print(f"Total malicious hashes loaded: {len(malicious_hashes)}")
        return malicious_hashes

    def load_hash_file(self, filepath: str, hash_type: str) -> Dict[str, str]:
        """Carrega hashes de um arquivo txt específico"""
        hashes = {}
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        hash_value = line.strip()
                        if hash_value and len(hash_value) > 10:  # Validação básica
                            hashes[hash_value.lower()] = f'{hash_type}_malware_{line_num}'
            except Exception as e:
                print(f"Error loading {filepath}: {e}")
        else:
            print(f"Hash file not found: {filepath}")
        return hashes
    
    def calculate_md5_hash(self, content: Any) -> str:
        """Calcula MD5 hash do conteúdo"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.md5(content).hexdigest().lower()

    def calculate_sha1_hash(self, content: Any) -> str:
        """Calcula SHA1 hash do conteúdo"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha1(content).hexdigest().lower()

    def calculate_sha256_hash(self, content: Any) -> str:
        """Calcula SHA256 hash do conteúdo"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest().lower()

    def calculate_sha512_hash(self, content: Any) -> str:
        """Calcula SHA512 hash do conteúdo"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha512(content).hexdigest().lower()

    def calculate_all_hashes(self, content: Any) -> Dict[str, str]:
        """Calcula todos os tipos de hash suportados"""
        return {
            'md5': self.calculate_md5_hash(content),
            'sha1': self.calculate_sha1_hash(content),
            'sha256': self.calculate_sha256_hash(content),
            'sha512': self.calculate_sha512_hash(content)
        }
    
    def check_content_against_malicious_db(self, content: Any) -> Dict[str, Any]:
        """Verifica todos os hashes do conteúdo contra a base de malware"""
        hashes = self.calculate_all_hashes(content)

        detected_malware = {}
        highest_risk = 0.0

        for hash_type, hash_value in hashes.items():
            if hash_value in self.known_malicious_hashes:
                malware_info = self.known_malicious_hashes[hash_value]
                detected_malware[hash_type] = {
                    'hash': hash_value,
                    'malware_type': malware_info,
                    'risk_score': 1.0
                }
                highest_risk = 1.0

        return {
            'is_malicious': len(detected_malware) > 0,
            'detected_malware': detected_malware,
            'risk_score': highest_risk,
            'all_hashes': hashes
        }

    def check_attachments(self, text: str, attachments: List[Dict] = None) -> Dict[str, Any]:
        """Verifica menções a anexos suspeitos e anexos reais"""
        text_lower = text.lower()
        risk_score = 0.0
        attachment_details = []

        # Verificar padrões de texto
        suspicious_mentions = 0
        for pattern in self.suspicious_patterns:
            if pattern in text_lower:
                suspicious_mentions += 1
                risk_score += 0.2

        # Verificar menções de anexos
        attachment_keywords = ['attachment', 'attached', 'anexo', 'anexado', 'download', 'file']
        for keyword in attachment_keywords:
            if keyword in text_lower:
                risk_score += 0.15
                break

        # Verificar anexos reais se fornecidos
        if attachments:
            for i, attachment in enumerate(attachments):
                attachment_risk = 0.0
                attachment_info = {'index': i}

                # Verificar nome do arquivo
                filename = attachment.get('filename', '').lower()
                attachment_info['filename'] = filename

                for pattern in self.suspicious_patterns:
                    if pattern in filename:
                        attachment_risk += 0.6
                        attachment_info['suspicious_extension'] = pattern
                        break

                # Verificar conteúdo do anexo se disponível
                if 'content' in attachment:
                    malware_check = self.check_content_against_malicious_db(attachment['content'])
                    attachment_info['malware_check'] = malware_check

                    if malware_check['is_malicious']:
                        attachment_risk = 1.0  # Máximo risco para malware conhecido
                        attachment_info['malware_detected'] = True

                attachment_info['risk_score'] = attachment_risk
                attachment_details.append(attachment_info)
                risk_score = max(risk_score, attachment_risk)

        return {
            'risk_score': min(risk_score, 1.0),
            'suspicious_mentions': suspicious_mentions,
            'attachment_details': attachment_details
        }
    
    def process(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Processa análise de hash e anexos"""
        text = email_data.get('cleaned_text', '')
        attachments = email_data.get('attachments', [])

        # Calcular todos os hashes do conteúdo
        content_hashes = self.calculate_all_hashes(text)

        # Verificar se o conteúdo é malicioso
        malware_check = self.check_content_against_malicious_db(text)

        # Verificar anexos
        attachment_analysis = self.check_attachments(text, attachments)

        # Calcular score final
        content_risk = malware_check['risk_score']
        attachment_risk = attachment_analysis['risk_score']

        # O maior risco determina o score final
        final_risk = max(content_risk, attachment_risk * 0.8)

        # Determinar se é malicioso
        is_malicious = final_risk > 0.7 or malware_check['is_malicious']

        # Gerar explicação detalhada
        explanation = self.generate_explanation(
            malware_check, attachment_analysis, final_risk, is_malicious
        )

        return {
            'content_hashes': content_hashes,
            'malware_detection': malware_check,
            'attachment_analysis': attachment_analysis,
            'is_known_malicious': malware_check['is_malicious'],
            'is_malicious_content': is_malicious,
            'hash_risk_score': final_risk,
            'explanation': explanation,
            'total_malicious_hashes_in_db': len(self.known_malicious_hashes),
            'agent': 'hash_analyzer'
        }

    def generate_explanation(self, malware_check: Dict, attachment_analysis: Dict,
                           final_risk: float, is_malicious: bool) -> str:
        """Gera explicação detalhada da análise"""
        explanation = []

        if is_malicious:
            explanation.append("🚨 CONTEÚDO MALICIOSO DETECTADO:")
        else:
            explanation.append("✅ Conteúdo parece seguro:")

        # Malware detection
        if malware_check['is_malicious']:
            explanation.append(f"- {len(malware_check['detected_malware'])} hash(es) malicioso(s) detectado(s)")
            for hash_type, info in malware_check['detected_malware'].items():
                explanation.append(f"  * {hash_type.upper()}: {info['malware_type']}")
        else:
            explanation.append("- Nenhum hash malicioso conhecido detectado")

        # Attachment analysis
        if attachment_analysis['suspicious_mentions'] > 0:
            explanation.append(f"- {attachment_analysis['suspicious_mentions']} menções suspeitas de arquivos")

        if attachment_analysis['attachment_details']:
            explanation.append(f"- {len(attachment_analysis['attachment_details'])} anexo(s) analisado(s)")
            for detail in attachment_analysis['attachment_details']:
                if detail.get('malware_detected'):
                    explanation.append(f"  * MALWARE em anexo: {detail['filename']}")
                elif detail.get('suspicious_extension'):
                    explanation.append(f"  * Extensão suspeita: {detail['filename']}")

        explanation.append(f"- Score de risco: {final_risk:.3f}")
        explanation.append(f"- Base de dados: {len(self.known_malicious_hashes):,} hashes maliciosos")

        return "\n".join(explanation)