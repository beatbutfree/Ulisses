## Chapter 1. Introduction

### 1.1 Life in a Security Operations Center and the Alert Fatigue Problem

Security Operations Centers operate in an environment characterized by persistent alert volume, heterogeneous telemetry sources, and SLA (service level agreement) regulated response times. In this context, L1 analysts are expected to manage these large numbers of events while preserving efficiency, quality, and escalation correctness. As alert streams grow, the investigative burden is not distributed evenly: a substantial fraction of analyst time is consumed by repetitive tasks, triage checks, and evidence gathering before a meaningful judgment can even be formulated.

This workload pattern creates the phenomenon commonly described as alert fatigue. Alert fatigue is not only a human factor; it is also an architectural problem. Traditional deterministic automated pipelines, although reliable for narrow and stable use cases, require continuous maintenance, rule tuning, and procedural updates to remain effective. As data sources evolve and environments change, deterministic logic must be repeatedly adjusted, and this adjustment effort grows non-linearly with system complexity.

For this reason, purely deterministic security-alert handling does not scale rapidly enough to match the rate of operational change in modern SOC practice. The challenge is not the absence of detection logic, but the inability to sustain fast adaptation without scaling human capital at the same pace. This thesis addresses that gap by investigating whether an agent-based pipeline can absorb part of this load while maintaining industry standards.

### 1.2 Research Goal

The central goal of this research is to test whether an LLM-based swarm of agents can investigate, classify, and manage security events in a way that is operationally meaningful for first-line SOC workflows. The emphasis is on practical analytical support rather than full autonomous response. The system is therefore designed to perform evidence-oriented analysis and produce structured outputs through a consistent approach and the use of external tools.

The research focus is intentionally empirical and engineering-oriented. The objective is not to claim a universal replacement for SOC analysts, but to evaluate whether a coordinated agent pipeline can produce measurable value under realistic constraints. Value is defined through quality of investigation, sustainability of computational cost, and the ability to adapt to new types of alerts with less than O(n) effort.

A second strategic objective is to test whether analytical capability can improve over time by accumulating reusable knowledge. This includes storing queries in a vector database using description:query as a key-value pair, which allows for semantic-based retrieval.

### 1.3 Research Questions

The thesis is organized around a set of practical research questions that reflect both technical feasibility and operational viability.

1. Does the precision achieved by an LLM-based multi-agent investigation process justify the additional architectural complexity?
2. Is the cost per managed alert sustainable, and how does this compare across in-house inference and hosted inference options?
3. Can the analysis pace and quality keep up with an L1 analyst handling the same alert categories?
4. Is the approach more scalable than deterministic-only triage flows, and if so, where is the largest performance and operational advantage?
5. Can a reusable knowledge base be created, based on vector retrieval of description-query pairs, so that analysis quality improves over time?
6. What is the mean variance of the quality of the automated analysis?
7. Does the multiple-agent architecture mitigate the risk of hallucinations?

### 1.4 Scope, Delimitations, and Assumptions

The scope of this thesis is to design, build, test, and evaluate an approach to automated L1 security-event analysis through a coordinated agent architecture. The work is focused on the analysis phase of incident handling, with a controlled extension toward autonomous improvement through persistent knowledge mechanisms. The contribution is therefore centered on investigative workflow support and process scalability.

A deliberate delimitation is applied to final alert classification accuracy. Although classification precision is important, it is treated here as a secondary target relative to analysis quality, evidence completeness, and adaptive behavior. This choice is due to the complexity of high-confidence classification and recognizes that classification itself could be studied as a dedicated research.

The implemented system is designed to preserve a path for future scoring enhancement. In particular, the reporting and pipeline outputs are structured so that a subsequent machine-learning component can be introduced to score final reports or estimate confidence quality.

### 1.5 Thesis Roadmap

The remainder of this thesis is structured to guide the reader from context to implementation and evaluation. The next chapter introduces the technological background required to understand the technologies involved: SOC triage, LLM reasoning, tool-based agents, and orchestration paradigms with auditable workflows.

The third chapter defines project requirements and methodological choices. The fourth chapter presents the full system architecture and the principal design decisions, including skill decomposition, pipeline stages, and knowledge mechanisms. The fifth chapter provides a detailed implementation analysis, including engineering tradeoffs and validation strategy.

The sixth chapter reports tests and evaluations, covering quantitative and qualitative observations against the research questions. The final chapter summarizes conclusions, discusses limitations, and proposes future research directions that can extend the present work toward broader SOC automation capability.
