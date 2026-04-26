## Chapter 7. Conclusion and Future Work

### 7.1 Final Conclusions

This thesis investigated whether a multi-agent, skill-based architecture can provide operational value for L1 SOC investigation workflows under realistic engineering constraints. The resulting artifact demonstrates that a structured agent pipeline can perform evidence-oriented triage with explicit control flow, stable output contracts, and auditable intermediate reasoning artifacts.

The main conclusion is that the proposed approach is technically viable as an analyst-augmentation system, particularly for repetitive and evidence-heavy alert classes. The architecture does not eliminate uncertainty, nor does it replace human judgment, but it provides a reproducible investigation scaffold that can reduce manual overhead in first-line triage.

A second conclusion concerns architectural explainability. The explicit decomposition into Analyst, Evaluator, Formatter, and Reflector stages proved valuable not only for implementation modularity but also for scientific defensibility. Each stage can be reasoned about, tested, and evolved with clear boundaries. This property is essential for both thesis rigor and SOC adoption, where opaque automation is often rejected.

A third conclusion is that controlled adaptive memory is promising but must remain policy-governed. Retrieval and crafting capabilities improved flexibility, yet long-term quality depends on conservative promotion logic and continuous monitoring of memory drift.

### 7.2 Contribution Recap

The work contributes at three levels: architectural, implementation, and evaluation methodology.

1. Architectural contribution
A full end-to-end SOC L1 investigation pipeline was defined with explicit state-machine orchestration, layered query services, decoder-specific analysis skills, and post-verdict reflection policy.

2. Implementation contribution
The architecture was realized in a concrete Python system with strict skill contracts, stable report schema, structured logging, and a memory loop that couples semantic retrieval with gated promotion.

3. Methodological contribution
The project established a reproducible engineering-research process, including interface-first development, staged validation, and metric-oriented instrumentation to support later empirical campaigns.

Together, these contributions form a coherent baseline for future SOC-agent research that prioritizes auditability and operational realism over purely benchmark-oriented performance claims.

### 7.3 Limitations

Despite positive pilot signals, the current system has important limitations that constrain interpretation and deployment scope.

1. Synthetic evaluation corpus
Experimental results were derived from synthetic but plausible scenarios, not from long-horizon enterprise production telemetry. This limits external validity.

2. Limited source diversity
Current analysis depth is strongest for selected decoder families. Broader environments with additional network, cloud, and identity sources may expose unhandled schema variation.

3. Latency volatility in complex cases
Multi-step tool-use and query-crafting retries can produce substantial tail latency, reducing suitability for strict real-time response paths.

4. Prompt and model sensitivity
Pipeline quality still depends on prompt formulation and model behavior stability. Small changes can alter confidence distributions and borderline verdict tendencies.

5. Memory cold-start and curation burden
Chroma-based reuse is less effective in early stages and can degrade if promotion policy is loosened without quality controls.

6. Cost model not yet fully quantified
Token consumption and infrastructure costs were observed indirectly but not yet analyzed through a formal cost-per-alert model across scenario classes.

7. Human-factor integration not yet evaluated
The system has not yet been tested in analyst-in-the-loop studies measuring trust, adoption friction, and escalation behavior under workload.

These limitations do not invalidate the architecture, but they define the conditions under which current claims should be interpreted.

### 7.4 Future Work

Future work should prioritize empirical hardening, broader interoperability, and integration with multiple security components.

#### 7.4.1 Live Data Evaluation Campaign

The highest priority is a longitudinal evaluation on live SOC telemetry. This campaign should include:
1. Month-scale collection windows.
2. Per-scenario drift tracking.
3. Explicit analyst agreement/disagreement annotation.
4. Robust confidence calibration analysis.

This step is required to move from synthetic plausibility to operational evidence.

#### 7.4.2 Multi-Source Skill Expansion

The decoder-specific strategy should be extended to additional log domains:
1. Firewall and proxy telemetry.
2. Cloud control-plane and identity events.
3. Endpoint process/network lineage signals.

Expansion must preserve the same contract discipline (explicit field semantics, absent-field signaling, layered query access).

#### 7.4.3 Adaptive Cost and Latency Optimization

Given observed latency tails, optimization should focus on:
1. Dynamic iteration budgets per alert complexity.
2. Early-stop heuristics based on evidence saturation.
3. Query result-size control and smarter aggregation defaults.
4. Model-routing policies (lighter models for low-risk stages, stronger models for ambiguous adjudication).

A formal objective should optimize quality under bounded cost and latency, rather than maximizing one dimension alone.

#### 7.4.4 Memory Governance and Anti-Drift Controls

The self-improvement loop requires stronger governance before production use:
1. Query quality scoring before promotion.
2. Time-decay or archival for low-utility memories.
3. Duplicate/near-duplicate suppression.
4. Periodic memory audits with rollback capability.

This would reduce long-term degradation risk while preserving compounding utility.

#### 7.4.5 Human-in-the-Loop Operational Integration

Future integration should explicitly evaluate analyst collaboration patterns:
1. Review queue interfaces for uncertain/inconclusive cases.
2. Escalation templates tuned for SOC handoff workflows.
3. Feedback capture loops to improve prompt and policy layers.

The target operating model should be cooperative automation where the system accelerates evidence handling and human analysts remain final decision owners.

#### 7.4.6 Security, Robustness, and Governance Hardening

Before broad deployment, additional safeguards are needed:
1. Prompt-injection and adversarial log-content resilience testing.
2. Permission scoping for query capabilities.
3. Policy guardrails for high-impact recommendations.
4. Governance reporting for compliance and audit requirements.

These controls are essential for trustworthy use in regulated operational environments.

### 7.5 Closing Remarks

This thesis shows that SOC L1 investigation can be meaningfully supported by a modular multi-agent architecture when system boundaries are explicit, outputs are schema-constrained, and memory adaptation is policy-governed. The contribution is not a claim of fully autonomous SOC reasoning, but a practical and explainable framework that can evolve toward stronger operational reliability.

The central research outcome is therefore twofold: first, the approach is feasible and useful in controlled conditions; second, the path to production-grade adoption is clear, measurable, and grounded in concrete engineering improvements.
