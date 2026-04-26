## Chapter 3. Methodology and Requirements

### 3.1 Engineering-Research Methodology

The methodological approach adopted in this thesis is engineering-research with iterative validation. The objective is not to formulate a purely theoretical model of SOC automation, but to design, implement, and empirically evaluate an operational system under realistic constraints. The research process follows a build-measure-refine logic where architectural decisions are progressively validated through tests and controlled executions.

The development strategy is intentionally incremental. Instead of implementing a full autonomous pipeline in one step, the system is constructed in bounded phases, each delivering a concrete capability with explicit interfaces and dedicated tests (detailed further in Chapter 5). This staged process reduces coupling risk, supports reproducibility, and allows design tradeoffs to be evaluated while the system is still modular.

A second methodological principle is explainability-by-design. Components are selected and composed so that the full analytical path can be inspected: which skill was called, which query was executed, which evidence was retrieved, and how the final verdict was justified. This principle directly influences technology selection (Python modular design, LangGraph explicit state transitions, structured JSON logging) and prevents hidden control paths that would weaken methodological transparency.

### 3.2 Functional Requirements of the Analyst Agent

The functional requirements are derived from the investigative workflow expected from an L1 SOC analyst and from the architecture implemented in the project.

1. Alert intake and context initialization
The system must accept a Wazuh alert together with a contextual prompt from the SOAR layer. It then initializes a context containing source metadata, decoder information, and an investigative prompt.

2. Skill-based evidence enrichment
The analyst must invoke compatible skills to retrieve contextual evidence (for example IP activity, username activity, and triggered rules) and summarize each skill outcome in analyst-readable form.

3. Decoder-aware skill selection
The system must select analysis skills according to decoder-specific compatibility to avoid silent failures caused by field-schema mismatch.

4. Layered query construction and execution
Analysis skills must construct and execute queries through foundational layers (query builder and query executor) rather than direct indexer access.

5. Multi-agent analytical separation
The pipeline must separate investigative reasoning, verdict assessment, and report generation across distinct agents (Analyst, Evaluator, Formatter), with optional Reflector for post-verdict memory policy.

6. Structured incident report generation
The final output must conform to a stable report schema containing verdict, confidence, severity, technical breakdown, findings, recommendations, and preserved raw intermediate artifacts.

7. Persistent knowledge accumulation
The system must be able to store and retrieve reusable investigative queries through a vector-backed memory layer, with policy-controlled promotion of newly crafted queries.

8. End-to-end trace generation
Every run must emit machine-readable logs for pipeline start, skill calls, retrieval/crafting events, and final completion.


These requirements define the minimum capabilities needed for practical L1 support while preserving architectural discipline.

### 3.3 Non-Functional Requirements

In addition to functional capabilities, the system must satisfy non-functional properties relevant to real operations.

1. Reliability
The system must fail predictably, propagate error information, and avoid hidden failure modes.

2. Traceability
All relevant analytical actions must be reconstructable from logs and preserved artifacts.

3. Extensibility
New skills and security components must be addable without redesigning core orchestration logic.

4. Testability
Core components must be independently testable with deterministic inputs and dependency injection, including mocked external clients.

5. Operational efficiency
The pipeline should control unnecessary token and data volume by removing redundant payload sections and limiting irrelevant fields.

6. Security and configuration hygiene
Credentials and environment-specific parameters must remain externalized through environment variables or an external vault.

### 3.4 Data and Interface Constraints

The system design is shaped by explicit data and interface constraints coming from both the security component and the agent architecture.

At telemetry level, Wazuh data is schema-heterogeneous across decoders. Equivalent concepts may appear under different field names (for example `srcIp` vs `src_ip`). This means that query correctness is source-dependent; a syntactically valid query can still be semantically wrong for a given decoder. The architecture addresses this through decoder-specific analysis skills and explicit "field not present" notes when a source does not expose required attributes.

At query interface level, log retrieval is constrained to Wazuh Indexer/OpenSearch (port 9200). The default index family is `wazuh-archives-*` for broad event context, with `wazuh-alerts-*` used selectively for alert-level logs.

At agent interface level, each skill must comply with a stable contract: typed input/output behavior, JSON-serialisable data payload, bounded summary, and execution through the public wrapper rather than private internals. This preserves consistency across heterogeneous skills and supports standard orchestration.

At reporting level, the final incident report must satisfy a fixed schema contract. This is necessary to make outputs auditable and comparable across runs.

At memory interface level, the vector store accepts queries coupled with metadata, including conversion choices required by backend limitations (for example parameter list normalization). This constraint is operationally relevant because retrieval quality depends on metadata consistency.

### 3.5 Evaluation Design Principles

The evaluation methodology in this thesis is designed as a metrics-oriented process with formal measurement expanding as logged run data accumulates.

1. Separation of implementation validation and analytical effectiveness
Component-level correctness is verified first through unit and integration tests; operational effectiveness is then evaluated through end-to-end alert investigations.

2. Metrics anchored to SOC relevance
Primary metrics include detection quality, false-positive behavior, query reuse effectiveness, and response latency. These dimensions map directly to L1 operational concerns.

3. Evidence-first interpretation
Evaluations should privilege trace-backed interpretation over subjective quality impressions. Any claim about model behavior must be supported by logs, intermediate artifacts, and report outputs.

4. Repeatability over anecdotal success
The objective is not a single impressive run but consistent behavior across scenarios. Repetition and variance observation are therefore mandatory.


### 3.6 Chapter Summary

This chapter defines the methodological and requirement framework that guides the implementation chapters. The project is positioned as an engineering-research artifact with incremental construction, strict interface contracts, and audit-oriented observability. Functional requirements define what the pipeline must do; non-functional requirements define how robustly and transparently it must do it. Data constraints and evaluation principles complete the framework needed to assess whether the resulting agent can provide meaningful L1 SOC investigative support.
