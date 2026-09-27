# SMA Spam Detector

A resilient multi-agent system for spam/phishing detection with defense against prompt injection attacks — built with LangGraph and OpenAI's GPT models.

This repository is the code companion to my master's thesis, **"Sistema Multi-Agente Resiliente para Detecção de Spam com Proteção Contra Prompt Injection"** (Multi-Agent Resilient System for Spam Detection with Prompt Injection Protection), submitted for the Master's Degree in Artificial Intelligence Engineering at **ISEP** (Instituto Superior de Engenharia do Porto), in a dual-degree program with **IFMA** (Instituto Federal do Maranhão). Advisors: Prof. Isabel Praça (ISEP) and Prof. Daniel Duarte Costa (IFMA). Porto, September 2025.

## The problem

Email remains the primary vector for cyberattacks: spam accounted for **45.6% of global email traffic in 2023** (~160 billion malicious emails/day), and modern spam/phishing has evolved well beyond simple unsolicited messages into sophisticated social engineering, malware distribution, and LLM-generated content designed to evade filters.

LLMs are very good at catching this kind of sophisticated, context-dependent threat — but putting an LLM in a security pipeline introduces a new attack surface: **prompt injection**. Studies cited in the thesis found successful prompt injection attacks against 31 of 36 tested commercial LLM applications. A system that uses an LLM to defend against threats can itself become the thing that gets manipulated.

This project asks: **can a multi-agent architecture detect spam effectively while remaining resilient if one of its components — including the LLM itself — is compromised or manipulated?**

## The solution: defense in depth via specialized agents

Rather than relying on a single LLM call, the system splits detection into six specialized agents coordinated through **LangGraph**, each handling one concern and contributing to a weighted final decision:

| Agent | Responsibility |
|---|---|
| `SanitizationAgent` | Unicode normalization, control-character stripping, HTML cleanup — always runs first |
| `PromptInjectionAgent` | Flags jailbreak/injection attempts against a database of ~86,500 known patterns |
| `LLMClassifier` | Contextual spam/phishing classification via OpenAI GPT, with a pattern-matching fallback if the API is unavailable |
| `HashAnalyzer` | Compares attachment hashes (MD5/SHA1/SHA256) against ~92,400 known-malware signatures |
| `MaliciousContentAgent` | URL/domain analysis: typosquatting, shorteners, phishing keyword patterns |
| `ResultAggregator` | Combines all of the above into a final classification + confidence score |

**Why this design is resilient, not just accurate:**
- **Weighted aggregation, not a single point of failure.** `LLMClassifier` is the primary semantic signal, `MaliciousContentAgent` is a secondary technical validator, and `PromptInjectionAgent`/`HashAnalyzer` act as conditional penalty agents — silent when there's nothing to flag, but capable of overriding everything else the moment they detect a known threat.
- **Early-exit / circuit-breaker rules.** A prompt-injection score above 0.9, or a match against a known-malicious hash, short-circuits the pipeline straight to "malicious" — no need to wait on a (potentially manipulated) LLM call.
- **Fault tolerance by design.** If the OpenAI API is down, `LLMClassifier` falls back to pattern matching instead of failing the whole request. A single agent failing doesn't take down the pipeline — it's scored as neutral and the rest of the system keeps going. External calls use retry with exponential backoff + jitter, and each agent has its own timeout.
- **Explicit anti-manipulation instructions and detection.** The LLM's own system prompt tells it not to follow instructions embedded in the content it's analyzing, and `LLMClassifier` independently scans for known injection phrasing, role-play/jailbreak patterns, and context-escape sequences (code fences, template tags) *before* trusting the model's output.

See [`docs/architecture.md`](docs/architecture.md) for the full breakdown (state graph, weighting configuration, early-exit table).

## Results

Evaluated on 1,000 balanced samples (500 legitimate / 500 malicious) drawn from the [`ealvaradob/phishing-dataset`](https://huggingface.co/datasets/ealvaradob/phishing-dataset) (combined_reduced version, covering emails, SMS, URLs and website HTML), seed 42 for reproducibility:

| Metric | Score |
|---|---|
| Accuracy | **87.0%** |
| Precision | 80.1% |
| Recall | **92.8%** |
| F1-Score | 86.0% |

Confusion matrix: 398 true positives, 472 true negatives, 99 false positives, 31 false negatives — the system leans conservative (few malicious emails slip through, at the cost of some legitimate emails needing manual review), which is the right trade-off for a security-first tool.

This positions the system above traditional ML baselines (Naive Bayes/SVM, ~70–80% F1) and competitive with Deep Learning approaches (~80–90% F1), while adding interpretability (every decision is traceable to individual agent scores) and modularity (new agents can be added without restructuring the pipeline).

Full metrics breakdown, per-agent behavior, timing analysis, and benchmark comparison: [`docs/results.md`](docs/results.md). Raw run output backing these numbers: [`results/resultado.txt`](results/resultado.txt).

### Honest limitations

- `PromptInjectionAgent` and `HashAnalyzer` recorded **zero activations** on the 1,000-sample test set — not because they don't work (synthetic unit tests confirmed 94% and 100% detection rates respectively), but because no public dataset currently combines traditional spam/phishing *and* prompt-injection/malware-hybrid threats. This is a dataset availability gap, not a functionality gap — see `docs/results.md` §Limitations for the full discussion.
- Average processing time is ~6.8s/sample (mostly OpenAI API latency), which is fine for corporate email triage or high-value transaction review, but not suited to high-throughput or sub-second-latency scenarios without further optimization.
- The system depends on external LLM API availability/connectivity — not designed for fully offline/air-gapped environments as-is.

## Tech stack

- **Orchestration:** [LangGraph](https://github.com/langchain-ai/langgraph) (state graph, conditional edges, checkpointing), LangChain Core, LangChain OpenAI
- **LLM:** OpenAI GPT (via the `openai` SDK), with a rule-based fallback provider
- **Data & metrics:** pandas, NumPy, scikit-learn (accuracy/precision/recall/F1/ROC-AUC)
- **Security/analysis:** `hashlib` (MD5/SHA1/SHA256), `re`, `urllib.parse`; optional [Guardrails AI](https://github.com/guardrails-ai/guardrails) `DetectJailbreak` validator as an additional injection-detection layer
- **Visualization:** Matplotlib, Seaborn, tqdm
- **Config:** python-dotenv

## Repository layout

```
.
├── sanitization_agent.py          # Text cleaning & normalization
├── prompt_injection_agent.py      # Jailbreak/injection pattern detection
├── hash_analyzer.py                # Known-malware hash verification
├── llm_classifier.py               # OpenAI GPT-based contextual classifier (+ fallback)
├── malicious_content_agent.py      # URL/phishing/domain analysis
├── result_aggregator.py            # Weighted decision aggregation
├── metrics_analyzer.py             # Accuracy/precision/recall/F1/ROC-AUC + plots
├── full_dataset_test.py            # Batch runner over a dataset (checkpointing/retry)
├── json_to_csv_converter.py        # Converts agent-result JSON into CSV for analysis
├── notebooks/                      # Exploratory & demo notebooks (see below)
├── docs/                           # Extended write-ups (architecture, results, datasets, future work)
└── results/                        # Sample output from the 1,000-sample evaluation run
```

Notebooks in `notebooks/`:
- `spam-detection-agent-with-langgraph-langfuse.ipynb` — a self-contained LangGraph workflow example with Langfuse tracing
- `advanced_spam_detection_multiagent.ipynb` / `spam_detection_multiagent_fixed.ipynb` — end-to-end multi-agent system notebooks
- `main.ipynb` — quickstart/setup notebook
- `detect prompt injection example.ipynb` — minimal Guardrails AI jailbreak-detection demo

## Getting started

```bash
pip install -r requirements.txt
cp .env.example .env   # then add your OPENAI_API_KEY
python full_dataset_test.py --dataset path/to/dataset.json --limit 100
python metrics_analyzer.py --csv <generated_results>.csv
```

`OPENAI_API_KEY` is required for `LLMClassifier` to use GPT; without it, the agent automatically falls back to pattern-matching classification.

## Future work

- Adversarial evaluation against attackers who know the architecture
- Performance optimization: parallel agent execution, caching, hybrid fast/deep analysis
- Multilingual validation
- Local/open-source LLM support (LLaMA, Mistral) to remove the external API dependency
- Richer datasets that combine traditional spam/phishing with prompt-injection and hybrid threats
- Longitudinal evaluation to track concept drift as attackers and underlying LLMs evolve

Full discussion: [`docs/future-work.md`](docs/future-work.md).

## Datasets & credits

This system was built and evaluated using third-party datasets, which are **not redistributed in this repository** — see [`docs/datasets.md`](docs/datasets.md) for full descriptions, licenses, and links:
- [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) (Alvarado, 2024) — evaluation dataset
- [romainmarcoux/malicious-hash](https://github.com/romainmarcoux/malicious-hash) (Marcoux, 2023) — malware hash signatures
- [Prompt Injection in the Wild](https://www.kaggle.com/datasets/arielzilber/prompt-injection-in-the-wild) (Zilber, 2024) — injection pattern training data

## License

Code in this repository is released under the [MIT License](LICENSE). Third-party datasets referenced above retain their own licenses.
