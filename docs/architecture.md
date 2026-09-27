# Architecture

## Overview

The system implements a **defense-in-depth** architecture: instead of a single classifier, six specialized agents each analyze one dimension of a message, and a final aggregator combines their outputs into one decision. This is coordinated as a state graph using **LangGraph**, with a shared state object (`SpamDetectionState`) passed between nodes:

```python
class SpamDetectionState(TypedDict):
    # Input
    original_text: str
    sample_id: Optional[int]

    # Per-agent results
    sanitization_result: Optional[Dict[str, Any]]
    prompt_injection_result: Optional[Dict[str, Any]]
    llm_classifier_result: Optional[Dict[str, Any]]
    hash_analyzer_result: Optional[Dict[str, Any]]
    malicious_content_result: Optional[Dict[str, Any]]
    aggregation_result: Optional[Dict[str, Any]]

    # Flow control
    early_exit: Optional[bool]
    exit_reason: Optional[str]
    processing_time: Optional[float]
    final_classification: Optional[str]
    confidence_score: Optional[float]
```

## Agents

| Agent | Input | Processing | Output | Activation |
|---|---|---|---|---|
| **SanitizationAgent** | Raw text | Unicode normalization (NFKC), control-character stripping, HTML tag removal | Cleaned text + cleaning metrics | Always |
| **PromptInjectionAgent** | Sanitized text | Semantic analysis + lookup against known jailbreak/injection patterns | Risk score + detected patterns | Always |
| **LLMClassifier** | Sanitized text | Contextual classification via OpenAI GPT | Classification + confidence score | Always |
| **HashAnalyzer** | Sanitized text/attachments | MD5/SHA1/SHA256 hashing + lookup against a known-malware hash database | Boolean match + hash type | Always |
| **MaliciousContentAgent** | Sanitized text | URL extraction, domain analysis, phishing keyword detection | Maliciousness score + suspicious URL list | Always |
| **ResultAggregator** | All of the above | Weighted combination + penalty rules | Final classification + confidence | After all other agents complete |

`MaliciousContentAgent`'s detection categories:

| Category | Techniques | Examples |
|---|---|---|
| Malicious URLs | Pattern extraction + domain verification | Typosquatting, shorteners, direct IPs |
| Phishing keywords | 14 specialized terms | "urgent", "verify account", "suspended" |
| Social engineering signals | Pressure-pattern detection | Account compromise, immediate action required |
| Structural anomalies | Formatting analysis | Excessive whitespace, unusual line breaks |

## Early-exit (circuit breaker) rules

To reduce processing time and respond immediately to flagrant threats, the pipeline can short-circuit before running every agent:

| Condition | Responsible agent | Threshold | Action |
|---|---|---|---|
| Critical prompt injection | `PromptInjectionAgent` | score > 0.9 | Immediately classify as malicious |
| Known malicious hash | `HashAnalyzer` | exact match | Immediately classify as malicious, escalate |
| Multiple threats detected | `ResultAggregator` | count ≥ 3 | Escalate confidence |

## Weighting and priority system

Not all agents are treated equally at aggregation time — each has a base weight reflecting its reliability and specialization:

- **`LLMClassifier` — 0.85 (dominant).** The primary contextual/semantic classifier; captures subtle spam patterns other methods miss.
- **`MaliciousContentAgent` — 0.15.** Secondary technical validator for URLs/domains/phishing indicators.
- **`PromptInjectionAgent` / `HashAnalyzer` — 0.0 base, conditional.** Silent when nothing is detected, but jump to an effective weight of 0.35 / 0.45 respectively the moment they flag a known threat — acting as an immediate penalty that forces the aggregator to treat the sample as high priority regardless of the LLM's opinion.
- **`SanitizationAgent` — 0.0.** Pure pre-processor; its job is input quality, not classification.

This creates a hybrid system: under normal conditions, the decision hinges on `LLMClassifier` + `MaliciousContentAgent`; the moment `PromptInjectionAgent` or `HashAnalyzer` fires, the weighting shifts to prioritize that signal — balancing semantic efficiency with immediate response to known/critical threats.

## Fault tolerance

- **Hierarchical fallback:** if the OpenAI API is unavailable, `LLMClassifier` automatically falls back to pattern matching. Less semantically sophisticated, but keeps the pipeline running instead of failing outright.
- **Isolated agent failure:** if one agent fails, its result is replaced with a neutral default score rather than aborting the whole request — the rest of the pipeline and the aggregation step continue normally.
- **Adaptive timeouts:** each agent has its own configurable execution time limit, calibrated to its expected analysis complexity, so one slow agent can't stall the whole system.
- **Retry with backoff:** calls to external resources (APIs, hash databases) use exponential backoff with jitter, retrying on failure instead of giving up immediately.

## Libraries

| Category | Library | Purpose |
|---|---|---|
| Orchestration | LangGraph | Agent graph construction and flow coordination |
| Orchestration | LangChain Core | LLM integration foundation, message management |
| Orchestration | LangChain OpenAI | OpenAI GPT client integration |
| Data | Pandas | Dataset manipulation and analysis |
| Data | NumPy | Numerical/statistical operations |
| Data | scikit-learn | Evaluation metrics (accuracy, precision, recall, F1) |
| Security | hashlib | MD5/SHA1/SHA256 hashing for malicious-content detection |
| Security | re (regex) | Prompt-injection patterns, obfuscated URLs, suspicious text features |
| Security | urllib.parse | URL decomposition/validation, obfuscation detection |
| Visualization | Matplotlib, Seaborn | Confusion matrix, confidence-score distributions, metric charts |
| Visualization | tqdm | Progress bars for batch processing |
| Config | python-dotenv | Secure API key/credential management via environment variables |
