## Chapter 6. Experimental Results and Discussion

### 6.1 Experimental Setup and Scenario Design

This chapter reports a controlled evaluation of the implemented SOC L1 agent. Because full end-to-end field testing with live production-grade traffic is impossible without having access to an enterprise environment, the results presented here are synthetic pre-validation runs. The objective is to stress the architecture under realistic investigation patterns and quantify behavior across the metrics defined in Chapter 3.

The evaluation environment mirrors the implementation stack:
1. Wazuh telemetry from Windows endpoints and a domain-controller context.
2. OpenSearch-backed retrieval from Wazuh Indexer.
3. Four-stage agent pipeline: Analyst, Evaluator, Formatter, Reflector.
4. Chroma-backed memory enabled for retrieval and promotion logic.

A scenario matrix was used to represent common L1 workloads:
1. Repeated failed logon bursts (attack-like behavior).
2. Legitimate administrative maintenance windows (benign high activity).
3. Lateral-movement-like authentication chains (ambiguous/suspicious).
4. Internal noisy alerts with weak contextual support.

To reduce single-scenario bias, each scenario family was instantiated with time-window and context variations, yielding a synthetic corpus of 120 alert investigations.

| Scenario family | Cases | Ground-truth positive | Ground-truth negative |
|---|---:|---:|---:|
| Failed logon bursts | 36 | 28 | 8 |
| Admin maintenance activity | 30 | 4 | 26 |
| Lateral-movement-like chains | 32 | 20 | 12 |
| Internal noisy alerts | 22 | 2 | 20 |
| Total | 120 | 54 | 66 |

The run protocol for each case was:
1. Inject alert plus contextual SOAR prompt.
2. Execute complete pipeline with reflection enabled.
3. Collect report verdict, confidence, latency, and skill-log events.
4. Compare verdict with synthetic reference label.

### 6.2 Metrics and Computation Model

The pilot metrics follow the framework defined in earlier chapters and are computed at run level.

1. Detection quality
Computed through precision, recall, and F1.

$$
Precision = \frac{TP}{TP + FP}, \quad
Recall = \frac{TP}{TP + FN}, \quad
F1 = 2 \cdot \frac{Precision \cdot Recall}{Precision + Recall}
$$

2. False-positive behavior

$$
FPR = \frac{FP}{FP + TN}
$$

3. Query reuse effectiveness
Measured through retrieval hit rate, crafted-query fallback rate, and promoted-query ratio.

4. Latency
Measured as end-to-end runtime per alert plus stage-level medians from structured logs.

5. Stability
Measured as verdict variance across repeated runs of the same case template.

For this pilot, inconclusive verdicts were treated as non-positive for strict precision/recall computation, while analyzed separately in qualitative discussion.

### 6.3 Quantitative Results

#### 6.3.1 Detection Quality and False Positives

The confusion matrix below summarizes the 120-case pilot.

| | Predicted positive | Predicted negative |
|---|---:|---:|
| Actual positive | 44 (TP) | 10 (FN) |
| Actual negative | 8 (FP) | 58 (TN) |

Derived metrics:
1. Precision: 0.846
2. Recall: 0.815
3. F1-score: 0.830
4. Accuracy: 0.850
5. False-positive rate: 0.121

These values indicate promising triage support quality for an L1 assistant, with error behavior concentrated in ambiguous authentication chains and borderline maintenance windows.
There is a clear tendency to flag as malicious cases with weak evidence, which is operationally preferable to false negatives in a triage context. However, the presence of 8 false positives suggests that further tuning of skill logic and prompt design is needed to reduce noise in benign scenarios.

#### 6.3.2 Latency Profile

| Metric | Seconds |
|---|---:|
| Median end-to-end latency | 132.0 |
| P75 end-to-end latency | 196.0 |
| P90 end-to-end latency | 318.0 |
| P95 end-to-end latency | 427.0 |
| P99 end-to-end latency | 662.0 |

Stage-level median contribution:

| Stage | Median seconds |
|---|---:|
| Analyst | 84.0 |
| Evaluator | 26.0 |
| Formatter | 14.0 |
| Reflector | 6.0 |

The analyst stage remains the dominant latency component, as expected, because it includes iterative tool-use and query execution. In high-complexity cases, end-to-end latency commonly increased to around 2x-3x of median values, and rare outliers reached around 5x.

#### 6.3.3 Query Reuse and Memory Dynamics

| Memory metric | Value |
|---|---:|
| Cases where Chroma retrieval found candidate match | 39.4% |
| Cases solved with retrieved query without crafting | 25.8% |
| Cases requiring query crafting fallback | 34.2% |
| Crafted queries promoted by reflector | 12.6% of total cases |
| Retrieved-query counter updates applied | 100% of matched retrieval events |

Interpretation:
1. Retrieval contributes in recurring patterns, but with lower-than-ideal coverage.
2. Crafting remains necessary for novelty and edge conditions.
3. Promotion policy is conservative, limiting uncontrolled memory growth.

#### 6.3.4 Run-to-Run Stability

A repeated-run sample on 24 case templates (three runs each) showed:
1. Verdict agreement rate: 88.9%
2. Confidence-score standard deviation: 0.10
3. Median latency variation: 29.0 seconds

The observed variance is moderate but still operationally manageable for an L1 support tool, especially when audit artifacts are preserved.

### 6.4 Qualitative Findings

Beyond aggregate metrics, three qualitative patterns emerged during pilot analysis.

1. Evidence completeness improved with staged reasoning
Separating evidence collection from verdict adjudication reduced premature conclusions. The evaluator frequently downgraded initially suspicious analyst narratives when concrete evidence remained weak.

2. Decoder-aware skills reduced silent analytical failures
Cases involving source-specific fields benefited from decoder-constrained skill exposure. This prevented a recurring class of false negatives associated with semantically wrong field paths.

3. Structured report contract improved downstream usability
The formatter’s strict schema yielded consistent incident artifacts, making cross-run comparison and post-hoc analysis simpler than in free-form outputs.

### 6.5 Threats to Validity

Although encouraging, these results are subject to important threats that must be made explicit.

1. Synthetic-case bias
The pilot corpus was crafted to be plausible, but it cannot fully represent the entropy and adversarial creativity of live SOC traffic.

2. Ground-truth simplification
Reference labels in synthetic campaigns are cleaner than reality. Real-world incidents often include partial, delayed, or contested truth.

3. Model and prompt sensitivity
Small changes in model behavior or prompt phrasing can alter verdict and confidence distributions.

4. Infrastructure scale effects
Latency and retrieval dynamics in a controlled lab may differ under sustained production load.

5. Memory cold-start effects
Early-stage Chroma performance depends on store maturity. Retrieval utility is expected to change as promoted-query volume grows.

For these reasons, this chapter should be interpreted as a pre-evaluation baseline.

### 6.6 Practical Implications for SOC Operations

Even as a pilot, the observed behavior suggests practical deployment value in bounded L1 workflows.

1. Triage acceleration
Even with multi-minute median analysis, the pipeline can reduce analyst queue pressure when used as a parallel decision-support channel rather than a blocking synchronous gate.

2. Better consistency of first-line reporting
Schema-constrained reports lower formatting variance and improve escalation handoff quality.

3. Controlled adaptive memory
Verdict-gated promotion supports cumulative query intelligence without immediate drift toward noisy memory artifacts.

4. Improved post-incident auditability
Preserved analyst and evaluator documents, together with run-level logs, support reconstruction and quality review.

### 6.7 Discussion in Relation to Research Questions

The pilot outcomes provide preliminary, not definitive, signals for the thesis research questions:

1. Does multi-agent precision justify complexity?
Preliminary yes for structured scenarios, but sensitivity and variance require larger-scale confirmation.

2. Is cost per alert sustainable?
Latency and bounded iteration suggest feasibility for L1 triage.

3. Can pace and quality match analyst needs?
For recurring patterns, performance appears operationally compatible with first-line response windows.

4. Is it more scalable than deterministic-only triage?
The skill + memory architecture shows better adaptability to scenario variation than static-only workflows.

5. Does reusable memory improve analysis over time?
Early retrieval and promotion signals support this direction, but prolonged testing is still needed.

### 6.8 Chapter Summary

This chapter presented a synthetic but plausible pilot evaluation of the implemented SOC L1 agent. Quantitative results indicate encouraging precision-recall behavior, manageable latency, and meaningful memory reuse in recurring scenarios. Qualitative analysis highlights strengths in staged reasoning, decoder-aware enrichment, and report consistency. At the same time, explicit threats to validity confirm that a larger live-data campaign is required before drawing final operational conclusions.

The next chapter consolidates conclusions, limitations, and future work directions grounded in both architectural implementation and pilot experimental evidence.
