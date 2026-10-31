# CyberFox: AI-Assisted Security Event Detection

**A defensive prototype for validating, detecting and triaging security events from CSV logs**

## Objective

Small security teams collect more event data than they can review manually. Failed-login
bursts, port sweeps, request floods and unusual-hour access are buried in the same flat log.
CyberFox was built to deliver a working prototype that validates a CSV of login, web and
connection events, applies deterministic rules and behavioural anomaly detection, and
presents the result as an explainable alert queue. Every alert must come from real detection
logic and every metric from the project's own evaluation.

## Design and architecture

CyberFox is a five-stage pipeline. The parser validates required columns, timestamp format,
IP syntax, event and status values, port range and byte count; rejected rows are recorded
with physical line numbers and reasons. Valid rows reach two independent detectors: four
window-based rules and an Isolation Forest that scores source IPs. A merge stage combines
the alert sets, marks events suspicious and produces severity counts.

Results are persisted in SQLite as runs, events, alerts and rejected rows. Flask exposes a
dashboard with key figures, a normal-versus-suspicious donut, an hourly chart and source
tables; an alerts page with search and severity/source filters; and an analyze page that
previews an upload before detection and then shows the stored result. The bundled sample is
analysed at first start. Uploads are CSV-only, capped at 10 MB, stored under a random
identifier and deleted after analysis; tokens are validated and confined to the upload
directory. The suite contains 46 pytest tests, including 17 route tests.

## Detection methods

The rule engine implements four detections, each mapped to MITRE ATT&CK:

| Detection | Threshold | Severity | MITRE |
| --- | --- | --- | --- |
| Brute force | 5+ failed logins from one IP in 10 minutes | High; Critical if a success follows | T1110 |
| Port scan | 15+ distinct ports per IP | High | T1046 |
| Request flood | 60+ events from one IP in one minute | High | T1498 |
| Off-hours login | Successful login 23:00–05:00 | Medium | T1078 |

The ML path analyses IPs, not rows, using total events, failed logins, distinct ports, peak
requests per minute and off-hours logins. An Isolation Forest with 200 trees, contamination
0.2 and a fixed seed of 42 scores each IP; scores are rescaled to 0–100, with 85 or above
Critical, 70 or above High, 55 or above Medium and the rest Low. Each reason names the
largest absolute z-score feature against the population mean, for example "25 distinct ports
versus median 4 across 29 IPs". The label column is read only by evaluation.

## Dataset

The seeded generator (`random_state = 42`) produced 2,000 events from 2026-03-01 to
2026-03-03, from 29 source IPs and 19 users. Normal traffic is internal and business-hours
based; its 668 login events include 42 failures, a 6.3% failure rate. Four attacks inject 117
rows: 14 failed logins across two IPs, a 25-port scan, 75 requests in one minute, and two
off-hours successes. The other 1,883 rows are benign. Each row carries a 1/0 label used only
for evaluation.

## Results

All 2,000 rows passed validation. The engine raised 12 alerts (6 rule, 6 ML): 4 Critical, 4
High, 3 Medium and 1 Low, and marked 173 events suspicious (8.65%).

| Approach | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Rules | 117 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ML | 117 | 56 | 0 | 0.676 | 1.000 | 0.807 |
| Combined | 117 | 56 | 0 | 0.676 | 1.000 | 0.807 |

Rules score perfectly because the synthetic attacks were generated to match their
thresholds; this validates the implementation, not production accuracy. ML detects every
malicious row through its IP-level alerts but also flags 56 benign events from one internal
host (`192.168.1.14`) whose profile is unusual, giving precision 0.676 and recall 1.000.
Combined equals ML because an event is detected if either approach covers it; the 173
suspicious events exceed the 117 malicious rows for the same IP-level reason.

## Limitations

The evaluation uses one synthetic dataset, so the perfect rule scores are optimistic by
construction. There is no train/test split or threshold tuning, and a single contamination
value is used. IP-level ML coverage inflates false positives when a benign host differs from
its peers, and statistical anomalies are not always attacks. The application has no
authentication, TLS or rate limiting; it is a local prototype with SQLite storage and a
development server. The interface was checked in Chrome at desktop and mobile widths but not
evaluated with real analysts.

## Conclusion

CyberFox delivers an end-to-end defensive prototype: validation with line-level errors, four
explainable rules, a deterministic Isolation Forest, a merged alert view, SQLite persistence,
and a responsive dashboard, alert queue and upload workflow. Every alert comes from the
detection logic, and every number here comes from the project's own evaluation script and
dataset. The next step is to replay real, authorised logs, tune thresholds against analyst
feedback, and add authentication before wider deployment.
