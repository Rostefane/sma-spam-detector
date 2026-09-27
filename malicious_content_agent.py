# agents/malicious_content_agent.py
import re
from urllib.parse import urlparse

class MaliciousContentAgent:
    """Detecta phishing, malware e conteúdos maliciosos"""
    
    def __init__(self):
        self.phishing_keywords = [
            'urgent', 'verify account', 'suspended', 'click here',
            'limited time', 'act now', 'confirm identity', 'update payment',
            'congratulations', 'winner', 'prize', 'claim now',
            'account locked', 'security alert', 'unauthorized access',
            'password reset', 'suspicious activity'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl', 'shorturl', 'ow.ly', 'goo.gl'
        ]
        
        # Lista expandida de typosquatting
        self.typosquatting_patterns = [
            'payp4l', 'arnazon', 'gooogle', 'facebok', 'twiter',
            'instagrm', 'linkedln', 'eb4y', 'amaz0n', 'micros0ft'
        ]
        
        # Lista simulada de domínios com reputação ruim
        self.known_malicious_domains = {
            'malicious-site.com': 1.0,
            'phishing-example.org': 0.9,
            'fake-bank.net': 0.95
        }
    
    def extract_urls(self, text):
        """Extrai URLs do texto"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    def check_domain_reputation(self, domain):
        """Verifica a reputação de um domínio (simulação)"""
        domain_lower = domain.lower()
        
        # Verificar domínios conhecidos maliciosos
        if domain_lower in self.known_malicious_domains:
            return self.known_malicious_domains[domain_lower]
        
        # Verificar padrões suspeitos
        if any(susp in domain_lower for susp in self.suspicious_domains):
            return 0.7
            
        # Verificar typosquatting
        if any(fake in domain_lower for fake in self.typosquatting_patterns):
            return 0.8
            
        return 0.0  # Reputação neutra
    
    def analyze_urls(self, urls):
        """Analisa URLs suspeitas"""
        suspicious_count = 0
        risk_score = 0
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Verificar reputação do domínio
                domain_risk = self.check_domain_reputation(domain)
                if domain_risk > 0:
                    suspicious_count += 1
                    risk_score += domain_risk
                
                # Detectar URLs com IPs ao invés de domínios
                if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                    suspicious_count += 1
                    risk_score += 0.6
                    
            except:
                suspicious_count += 1  # URL mal formada é suspeita
                risk_score += 0.5
                
        return suspicious_count, min(risk_score, 1.0)
    
    def calculate_phishing_score(self, text):
        """Calcula score de phishing"""
        text_lower = text.lower()
        score = 0
        
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                score += 0.15
        
        if text_lower.count('!') > 3:
            score += 0.2
        
        if 'urgent' in text_lower and 'click' in text_lower:
            score += 0.3
            
        # Verificar padrões de engenharia social
        social_patterns = [
            r'account.*compromised',
            r'immediate.*action.*required',
            r'verify.*within.*\d+.*hours'
        ]
        
        for pattern in social_patterns:
            if re.search(pattern, text_lower):
                score += 0.25
            
        return min(score, 1.0)
    
    def detect_suspicious_content(self, text):
        """Detecta outros conteúdos suspeitos"""
        text_lower = text.lower()
        suspicious_signals = []
        
        # Múltiplos espaços ou tabs (pode indicar tentativa de ocultar conteúdo)
        if re.search(r'\s{10,}', text):
            suspicious_signals.append('excessive_spacing')
            
        # Muitas quebras de linha
        if text.count('\n') > 20:
            suspicious_signals.append('excessive_line_breaks')
            
        # Uso de caracteres Unicode suspeitos
        if re.search(r'[\u202e\u202d\u202c]', text):
            suspicious_signals.append('unicode_direction_override')
            
        return suspicious_signals
    
    def process(self, email_data):
        """Análise principal"""
        text = email_data.get('cleaned_text', '')
        
        urls = self.extract_urls(text)
        url_count, url_risk = self.analyze_urls(urls)
        phishing_score = self.calculate_phishing_score(text)
        suspicious_signals = self.detect_suspicious_content(text)
        
        # Calcular risco final
        final_risk = (
            (phishing_score * 0.5) + 
            (url_risk * 0.3) + 
            (len(suspicious_signals) * 0.05)
        )
        
        return {
            'urls_found': len(urls),
            'suspicious_urls': url_count,
            'url_risk_score': url_risk,
            'phishing_score': phishing_score,
            'malicious_risk': min(final_risk, 1.0),
            'is_malicious': final_risk > 0.5,
            'suspicious_signals': suspicious_signals,
            'agent': 'malicious_content'
        }