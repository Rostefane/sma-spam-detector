> *Note: this reference document is kept in the original Portuguese (thesis language). See the main [README](../README.md) for an English overview.*

# Exemplos do Dataset Combined Reduced (Phishing Dataset)

## Tabela de Amostras Representativas

| Tipo | Classificação | Exemplo | Rótulo |
|------|---------------|---------|--------|
| **Email** | Legítimo | "re: 6.1100, disc: uniformitarianism, re: 1086; sex/lang Dick Hudson's observations on US use of 'son' but not 'daughter' as a vocative are very thought-provoking, but I am not sure that it is fair to attribute this to 'sons' being 'treated like senior relatives'..." | 0 |
| **Email** | Malicioso | "Hello I am your hot lil horny toy. I am the one you dream About, I am a very open minded person, Love to talk about any subject. Fantasy is my way of life, Ultimate in sex play. Ummmmmmmmmmmmmm I am Wet and ready for you. Hurry Up! call me let me Cummmmm for you... TOLL-FREE: 1-877-451-TEEN" | 1 |
| **SMS** | Legítimo | "Rose needs water, season needs change, poet needs imagination.. My phone needs ur sms and i need ur lovely frndship forever...." | 0 |
| **SMS** | Malicioso | "Sex up ur mobile with a FREE sexy pic of Jordan! Just text BABE to 88600. Then every wk get a sexy celeb! PocketBabe.co.uk 4 more pics. 16 £3/wk 087016248" | 1 |
| **URL** | Legítima | `https://www.revistaespacios.com/a18v39n27/18392714.html` | 0 |
| **URL** | Maliciosa | `https://rarkuntem.co.jp.fpjiehk.cn/index1.php` | 1 |
| **Website (HTML)** | Legítimo | `<!doctype html><html lang=en><title>Clipper Servicing and Repair - Clippersharp Ltd</title><meta content="We service and repair main brand horse, cattle and dog clippers..." name=description>` (Website completo de serviços de reparação) | 0 |
| **Website (HTML)** | Malicioso | `<html lang=en><meta charset=utf-8><meta content="Facebook Verification" name=description><meta content="Facebook Verification" property=og:title>` (Página falsa de verificação do Facebook) | 1 |

---

## Exemplos Detalhados por Categoria

### 1. Emails Legítimos (label = 0)

#### Exemplo 1.1 - Email Profissional
```
Tipo: Email corporativo
Conteúdo: "At 3:39 PM -0500 8/21/02, Rice, MA Mark (6750) wrote:
>I get hit with these probes or 'Rumplestiltskin attacks' too.
>Justin, could you explain what a..."
Rótulo: 0 (Legítimo)
Características: Linguagem formal, contexto técnico, formato de email thread
```

#### Exemplo 1.2 - Email de Discussão Acadêmica
```
Tipo: Email de lista de discussão
Conteúdo: "re: 6.1100, disc: uniformitarianism, re: 1086; sex/lang
dick hudson's observations on us use of 'son' but not 'daughter'
as a vocative are very thought-provoking, but i am not sure that
it is fair to attribute this to 'sons' being 'treated like senior relatives'..."
Rótulo: 0 (Legítimo)
Características: Discussão acadêmica, linguística, sem call-to-action suspeito
```

#### Exemplo 1.3 - Comunicação Corporativa (Enron)
```
Tipo: Email interno corporativo
Conteúdo: "cornhusker contact information lone star pipeline
lisa mcauliff (contracts) wilma easter (scheduling)
phone: 214-875-5224..."
Rótulo: 0 (Legítimo)
Características: Informações de contato corporativas, estrutura organizada
```

---

### 2. URLs Legítimas (label = 0)

#### Exemplo 2.1 - Website Educacional
```
URL: en.wikipedia.org/wiki/Musician
Rótulo: 0 (Legítimo)
Características: Domínio confiável (Wikipedia), HTTPS, estrutura de URL clara
```

#### Exemplo 2.2 - Portal de Notícias
```
URL: metronews.ca/webapp/Login.aspx?logout=true&rurl=/toronto/sports/article/1022417
Rótulo: 0 (Legítimo)
Características: Domínio de mídia estabelecido, estrutura de URL válida
```

#### Exemplo 2.3 - Site Comercial
```
URL: billsportsmaps.com/?p=1206
Rótulo: 0 (Legítimo)
Características: Domínio .com legítimo, parâmetro de página simples
```

---

### 3. HTML de Sites Legítimos (label = 0)

#### Exemplo 3.1 - Website Institucional
```
Tipo: HTML completo
Conteúdo: <!doctype html><html prefix="og: http://ogp.me/ns#">
Site: Autism Speaks (www.autismspeaks.org)
Rótulo: 0 (Legítimo)
Características:
- Estrutura HTML válida e completa
- Meta tags apropriadas (OpenGraph, Twitter Cards)
- Scripts legítimos (Google Analytics, cookieconsent)
- Certificado SSL válido
- Conteúdo educacional sobre autismo
```

#### Exemplo 3.2 - Portal de Serviços
```
Tipo: HTML
Conteúdo: <!doctype html><html lang=en>
<title>Photographs of Mouse Poop - Images of Feces and Droppings</title>
Rótulo: 0 (Legítimo)
Características: Conteúdo educacional, estrutura válida, sem elementos maliciosos
```

---

### 4. URLs de Phishing (label = 1)

#### Exemplo 4.1 - Phishing Bancário
```
URL: http://webmail-brinkster.com/ex/?email=%20%0%
Rótulo: 1 (Phishing)
Indicadores de Phishing:
- Subdomínio suspeito "webmail-brinkster"
- Parâmetro codificado estranho (%20%0%)
- Tentativa de imitar serviço de webmail
- Sem HTTPS
```

#### Exemplo 4.2 - Phishing com Redirecionamento
```
URL: https://www.baby2sleep.co.uk/home/chas3-us-en-login/signin.php
Rótulo: 1 (Phishing)
Indicadores de Phishing:
- Domínio legítimo comprometido (baby2sleep.co.uk)
- Estrutura de diretório suspeita (chas3-us-en-login)
- Página de login em site não relacionado
- Possível phishing de Chase Bank (chas3)
```

#### Exemplo 4.3 - URL Dinâmica Suspeita
```
URL: https://fdwknksrkt.duckdns.org/
Rótulo: 1 (Phishing)
Indicadores de Phishing:
- Domínio DuckDNS (serviço de DNS dinâmico gratuito)
- Nome de domínio aleatório (fdwknksrkt)
- Comumente usado para phishing temporário
```

#### Exemplo 4.4 - Typosquatting
```
URL: https://rarkuntem.co.jp.fpjiehk.cn/index1.php
Rótulo: 1 (Phishing)
Indicadores de Phishing:
- Aparência de domínio japonês (.co.jp) mas redirecionado para .cn
- Estrutura enganosa (co.jp.fpjiehk.cn)
- Domínio chinês suspeito
```

---

### 5. Spam via SMS (label = 1)

#### Exemplo 5.1 - Spam Sexual
```
Tipo: SMS
Conteúdo: "Sex up ur mobile with a FREE sexy pic of Jordan!
Just text BABE to 88600. Then every wk get a sexy celeb!
PocketBabe.co.uk 4 more pics. 16 £3/wk 087016248"
Rótulo: 1 (Spam)
Indicadores de Spam:
- Conteúdo sexual explícito
- Call-to-action urgente (text BABE)
- Cobrança recorrente oculta (£3/semana)
- Abreviações típicas de SMS (ur, wk)
- Número premium rate
```

#### Exemplo 5.2 - Spam de Empréstimos
```
Tipo: SMS/Email curto
Conteúdo: "52 - quick loan application hey would you refinance
if you knew you'd save thousands? We'll get you interest as low as 2.94%.
Don't believe..."
Rótulo: 1 (Spam)
Indicadores de Spam:
- Oferta financeira não solicitada
- Taxa de juros irrealista (2.94%)
- Promessa de economia ("save thousands")
- Falta de identificação legítima da instituição
```

---

### 6. Spam de Medicamentos (label = 1)

#### Exemplo 6.1 - Farmácia Ilegal
```
Tipo: Email
Conteúdo: "get discount drugs without prescription
discount generic drugs. save over 70%
todays specials, viagra, retails for $15, we sell for 3!!!
proz..."
Rótulo: 1 (Spam)
Indicadores de Spam:
- Venda de medicamentos sem prescrição
- Preços irrealistas (70% desconto)
- Múltiplos pontos de exclamação
- Ortografia intencional incorreta (proz = Prozac)
- Viagra sem prescrição médica
```

---

### 7. Spam de Conteúdo Adulto (label = 1)

#### Exemplo 7.1 - Linha Premium
```
Tipo: Email
Conteúdo: "Hello I am your hot lil horny toy.
I am the one you dream About,
I am a very open minded person,
Love to talk about and any subject.
Fantasy is my way of life,
Ultimate in sex play. Ummmmmmmmmmmmmm
I am Wet and ready for you.
Hurry Up! call me let me Cummmmm for you..........................
TOLL-FREE: 1-877-451-TEEN (1-877-451-8336)"
Rótulo: 1 (Spam)
Indicadores de Spam:
- Conteúdo sexual explícito
- Call-to-action para linha telefônica
- Repetições exageradas (Cummmmm)
- Número toll-free suspeito
```

---

### 8. Domínios Suspeitos (label = 1)

#### Exemplo 8.1 - Domínio Malicioso
```
Tipo: URL
Conteúdo: pusgionsers.net
Rótulo: 1 (Phishing)
Indicadores:
- Nome de domínio sem sentido
- Possível typosquatting
- Sem contexto legítimo
```

#### Exemplo 8.2 - Hospedagem Gratuita Suspeita
```
Tipo: URL
Conteúdo: geomagnetic-tacks.000webhostapp.com
Rótulo: 1 (Phishing)
Indicadores:
- Hospedagem gratuita (000webhost)
- Nome de domínio aleatório
- Comumente usado para phishing temporário
```

---

## Estatísticas do Dataset

| Métrica | Valor |
|---------|-------|
| **Total de amostras** | 77.677 |
| **Amostras legítimas (0)** | ~50% |
| **Amostras maliciosas (1)** | ~50% |
| **Tipos de conteúdo** | Email, SMS, URL, HTML |
| **Balanceamento** | Dataset balanceado |

---

## Características Distintivas

### Conteúdo Legítimo (label = 0):
- ✅ Linguagem formal e gramaticalmente correta
- ✅ Domínios estabelecidos e confiáveis
- ✅ Estrutura HTML válida
- ✅ Contexto corporativo ou educacional
- ✅ Sem pressão ou urgência artificial
- ✅ Informações de contato legítimas

### Conteúdo Malicioso (label = 1):
- ⚠️ Promessas irrealistas (descontos, prêmios)
- ⚠️ URLs com caracteres codificados suspeitos
- ⚠️ Domínios DuckDNS, hospedagem gratuita
- ⚠️ Conteúdo sexual ou farmacêutico não solicitado
- ⚠️ Erros ortográficos intencionais
- ⚠️ Call-to-action agressivo
- ⚠️ Números premium rate ocultos
- ⚠️ Typosquatting de marcas conhecidas
- ⚠️ Solicitação de informações financeiras

---

## Referência do Dataset

```
ALVARADO, E. Phishing Dataset: Email Classification for Spam Detection.
Hugging Face Datasets, 2024.
Disponível em: https://huggingface.co/datasets/ealvaradob/phishing-dataset
Versão utilizada: combined_reduced (77.677 amostras)
Acesso em: 10 set 2025.
```
