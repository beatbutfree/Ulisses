# Thesis Index (Condensed for 30-40 Pages)

## Chapter 1. Introduction (4-5 pages)
- Security operations context and alert-fatigue problem
- Research objective and motivation
- Research questions
- Scope, assumptions, and delimitations
- Main contributions and chapter roadmap

## Chapter 2. Background (5-6 pages)
- L1 SOC workflow and investigative requirements
- Wazuh telemetry model and query capabilities
- LLM tool-use in cybersecurity analysis
- Agentic reasoning and graph-based orchestration
- Explainability and auditability as design constraints

## Chapter 3. Methodology and Requirements (4-5 pages)
- Engineering-research methodology
- Functional requirements of the analyst agent
- Non-functional requirements (reliability, traceability, extensibility)
- Data/interface constraints and schema consistency
- Evaluation design principles

## Chapter 4. System Design and Architecture (9-10 pages)
- End-to-end architecture overview
- Skill contract and execution lifecycle
- Decoder-specific analysis-skill strategy
- Layered query pipeline and dependency boundaries
- Multi-agent pipeline: Analyst, Evaluator, Formatter, Reflector
- Knowledge memory and reflection policy
- Structured logging and severity normalization

## Chapter 5. Implementation and Validation (5-6 pages)
- Incremental implementation strategy
- Core component realization
- Enrichment workflow from alert to report
- Self-improvement mechanisms (retrieval, crafting, promotion)
- Testing strategy and verification outcomes

## Chapter 6. Experimental Results and Discussion (5-6 pages)
- Experimental setup and scenario design
- Metrics: detection quality, false positives, reuse, latency
- Quantitative and qualitative results
- Threats to validity
- Practical implications for SOC operations

## Chapter 7. Conclusion and Future Work (2-3 pages)
- Final conclusions
- Contribution recap
- Limitations
- Future research directions

## Back Matter (1-2 pages)
- Bibliography
- Appendices (prompts, policy details, supplementary tables)
