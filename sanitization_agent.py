# agents/sanitization_agent.py
import re
import unicodedata
from typing import Dict, Any

class SanitizationAgent:
    """Agente responsável apenas por limpeza e normalização de texto"""

    def __init__(self):
        # Padrões Unicode problemáticos para limpeza
        self.unicode_patterns = [
            r'[\u202e\u202d\u202c]',  # Direção de texto
            r'[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]',  # Caracteres de controle
            r'[\u2000-\u200F\u2028-\u202F\u205F-\u206F]',  # Separadores e formatação
            r'[\ufeff]',  # BOM (Byte Order Mark)
        ]
    
    def normalize_unicode(self, text: str) -> str:
        """Normaliza caracteres Unicode usando NFKC"""
        try:
            return unicodedata.normalize('NFKC', text)
        except Exception:
            return text

    def remove_control_characters(self, text: str) -> str:
        """Remove caracteres de controle problemáticos"""
        for pattern in self.unicode_patterns:
            text = re.sub(pattern, '', text)
        return text

    def clean_whitespace(self, text: str) -> str:
        """Normaliza espaços em branco"""
        # Normalizar diferentes tipos de espaços para espaço comum
        text = re.sub(r'[\u2000-\u200F\u2028-\u202F\u205F-\u206F]', ' ', text)
        # Remover espaços múltiplos
        text = re.sub(r'\s+', ' ', text)
        # Remover espaços no início e fim
        return text.strip()

    def remove_html_tags(self, text: str) -> str:
        """Remove tags HTML básicas"""
        # Remover tags HTML comuns
        text = re.sub(r'<[^>]+>', '', text)
        # Decodificar entidades HTML básicas
        html_entities = {
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#39;': "'",
            '&nbsp;': ' '
        }
        for entity, char in html_entities.items():
            text = text.replace(entity, char)
        return text

    def process(self, email_text: str) -> Dict[str, Any]:
        """Processa e limpa o texto do email"""
        if not isinstance(email_text, str):
            email_text = str(email_text)

        original_length = len(email_text)

        # Pipeline de limpeza
        cleaned = email_text

        # 1. Normalizar Unicode
        cleaned = self.normalize_unicode(cleaned)

        # 2. Remover caracteres de controle
        cleaned = self.remove_control_characters(cleaned)

        # 3. Remover tags HTML
        cleaned = self.remove_html_tags(cleaned)

        # 4. Normalizar espaços em branco
        cleaned = self.clean_whitespace(cleaned)

        # Calcular estatísticas da limpeza
        cleaned_length = len(cleaned)
        chars_removed = original_length - cleaned_length
        cleanup_ratio = chars_removed / original_length if original_length > 0 else 0

        return {
            'cleaned_text': cleaned,
            'original_length': original_length,
            'cleaned_length': cleaned_length,
            'chars_removed': chars_removed,
            'cleanup_ratio': cleanup_ratio,
            'agent': 'sanitization'
        }