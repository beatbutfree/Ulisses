## Chapter 1. Introduction

### 1.1 Life in a Security Operations Center and the Alert Fatigue Problem

Security Operations Centers operate in an environment characterized by persistent alert volume, heterogeneous telemetry sources, and SLA (service level agreements) regulated response time. In this context, L1 analysts are expected to manage this large numbers of events while preserving efficiency, quality, and escalation correctness. As alert streams grow, the investigative burden is not distributed evenly: a substantial fraction of analyst time is consumed by repetitive  tasks, triage checks, and evidence gathering before a meaningful judgement can even be formulated.

This workload pattern creates the phenomenon commonly described as alert fatigue. Alert fatigue is not only a human factor; it is also an architectural problem. Traditional deterministic automated pipelines, although reliable for narrow and stable use cases, require continuous maintenance, rule tuning, and procedural updates to remain effective. As data sources evolve and environments change, deterministic logic must be repeatedly adjusted, and this adjustment effort grows non-linearly with system complexity.

For this reason, purely deterministic security-alert handling does not scale rapidly enough to match the rate of operational change in modern SOC practice. The challenge is not the absence of detection logic, but the inability to sustain fast adaptation without scaling human capital at the same pace. This thesis addresses that gap by investigating whether an agent based pipeline can absorb part of this load while maintaining industry standard.

### 1.2 Research Goal

The central goal of this research is to test whether an LLM-based swarm of agents can investigate, classify, and manage security events in a way that is operationally meaningful for first-line SOC workflows. The emphasis is on practical analytical support rather than full autonomous response. The system is therefore designed to perform evidence-oriented analysis and produce structured outputs through a consistent approach and the use of external tools.

The research focus is intentionally empirical and engineering-oriented. The objective is not to claim a universal replacement for SOC analysts, but to evaluate whether a coordinated agent pipeline can produce measurable value under realistic constraints. Value is defined through quality of investigation, sustainability of computational cost and the ability to adapt to new type of alerts in an efficient way.

A second strategic objective is to test whether analytical capability can improve over time by accumulating reusable knowledge. This includes storing queries in a vector database using description:query as key value pair, this allow for semantic retrieval usable by the LLM analyst.

### 1.3 Research Questions

The thesis is organized around a set of practical research questions that reflect both technical feasibility and operational viability.

1. Does the precision achieved by an LLM-based multi-agent investigation process justify the additional architectural complexity?
2. Is the cost per managed alert sustainable, and how does this compare across in-house inference and hosted inference options?
3. Can the analysis pace and quality keep up with an L1 analyst handling the same alert categories?
4. Is the approach more scalable than deterministic-only triage flows, and if so, where is the largest performance and operational advantage?
5. Can a reusable knowledge base be created, based on vector retrieval of description-query pairs, so that analysis quality improves over time?

These questions jointly address the main adoption barrier for intelligent SOC automation: a technically interesting solution is insufficient unless it remains economically sustainable, operationally comparable to human baseline performance, and progressively improvable.

### 1.4 Scope, Delimitations, and Assumptions

The scope of this thesis is to design, build, test, and evaluate an approach to automated L1 security-event analysis through a coordinated agent architecture. The work is focused on the analysis phase of incident handling, with a controlled extension toward autonomous improvement through persistent knowledge mechanisms. The contribution is therefore centered on investigative workflow support and process scalability.

A deliberate delimitation is applied to final alert classification accuracy. Although classification precision is important, it is treated here as a secondary target relative to analytical process quality, evidence completeness, and adaptive behavior. This choice reflects the complexity of high-confidence security classification and recognizes that classification itself can be studied as a dedicated research track with additional ground-truth and modeling requirements.

The implemented system is designed to preserve a path for future scoring enhancement. In particular, the reporting and pipeline outputs are structured so that a subsequent machine-learning component can be introduced to score final reports or estimate confidence quality. This forward-compatible design allows the present thesis to remain focused on analysis orchestration while enabling future work on statistical or learning-based adjudication.

### 1.5 Contribution Statement

This thesis contributes an operationally grounded framework for evaluating LLM-based swarm analysis in SOC environments. The contribution is not limited to a software artifact; it includes a method for testing tradeoffs between precision, cost, throughput, and scalability in a structured manner. By framing the problem around concrete operational questions, the work aims to reduce ambiguity in how AI-based SOC support should be assessed.

A second contribution is the explicit integration of a long-term knowledge mechanism based on vector retrieval of description-query artifacts. This design enables iterative analytical improvement without requiring model retraining at each iteration. As a result, the system can be evaluated not only as a static assistant but as a learning operational component whose utility may compound over time.

A third contribution is methodological clarity regarding what is being optimized. Instead of maximizing a single metric, the thesis formalizes a multi-criteria perspective in which technical performance, economic sustainability, and workflow fit must all be considered jointly.

### 1.6 Thesis Roadmap

The remainder of this thesis is structured to guide the reader from context to implementation and evaluation. The next chapter introduces the technological and scientific background required to understand SOC triage constraints, tool-augmented language-model reasoning, and orchestration paradigms suitable for auditable analysis workflows.

The third chapter defines project requirements and methodological choices. The fourth chapter presents the full system architecture and the principal design decisions, including skill decomposition, pipeline stages, and knowledge mechanisms. The fifth chapter provides a detailed implementation analysis, including engineering tradeoffs and validation strategy.

The sixth chapter reports tests and evaluations, covering quantitative and qualitative observations against the research questions. The final chapter summarizes conclusions, discusses limitations, and proposes future research directions that can extend the present work toward broader SOC automation capability.
