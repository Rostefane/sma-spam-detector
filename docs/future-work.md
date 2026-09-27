# Recommended applications & future work

## Where this system fits well

- **Critical corporate email / financial transaction analysis**, where the depth of multi-agent analysis can catch subtle threats that simpler filters miss.
- **Second-layer validation** for messages already flagged by primary filters — reducing false positives and increasing confidence in security decisions.
- **High-security environments** (government, financial institutions), where the cost of a missed threat far outweighs the cost of extra processing time and API usage.

## Where it's not (yet) the right fit

- **High-volume real-time processing.** The current architecture makes multiple sequential external API calls per message — throughput-incompatible with, e.g., filtering millions of emails/day without further optimization.
- **Sub-second latency requirements.** The system prioritizes analytical depth over response speed.
- **Environments without reliable external connectivity.** The architecture currently depends on hosted LLM APIs; it isn't suited to isolated or intermittently-connected environments as-is.

## Future work

- **Adversarial evaluation.** Test resilience against attackers who know the system's architecture and specifically craft evasion techniques — the current results reflect natural/organic spam, not adaptive adversaries.
- **Performance optimization.** Parallel agent execution, intelligent caching for recurring decisions, and hybrid strategies (fast initial pass + selective deep validation) to reduce the ~6.8s/sample latency.
- **Multilingual expansion.** Validate effectiveness across languages and cultural contexts, and identify any linguistic/cultural biases in agent behavior.
- **Local LLM integration.** Incorporating open-source models (LLaMA, Mistral family) to reduce dependency on external APIs, cut long-term operational costs, and address data-privacy/latency/availability concerns — enabling fully on-premises deployment.
- **Richer, integrated datasets.** Enrich evaluation with more sophisticated phishing, adversarial attacks, and genuine prompt-injection attempts *within the same dataset* as traditional spam — directly closing the gap described in `docs/results.md` (Limitations).
- **Longitudinal study.** Track performance over time as attackers develop new tactics and underlying LLMs are updated, to catch concept drift and identify maintenance/retraining needs.

This work establishes a solid baseline for intelligent-agent-based threat detection, validating the multi-agent + LLM architecture's viability while providing a clear, honest map of what still needs validation before broader deployment.
