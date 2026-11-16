# Testing

CyberFox is tested at two levels: unit tests for the detection pipeline and route tests
that drive the real Flask app through its test client with a temporary SQLite database.

## Environment

| Item | Value |
| --- | --- |
| Python | 3.12.10 (project targets 3.11+) |
| Flask | 3.1.3 |
| pandas | 3.1.0 |
| scikit-learn | 1.9.1 |
| numpy | 2.5.4 |
| pytest | 9.2.0 |

Install exact versions with `pip install -r requirements.txt`.

## Running the tests

```bash
cd cyberfox
python -m pytest
```

Verbose mode with test names:

```bash
python -m pytest -v
```

`pytest.ini` sets `testpaths = tests` and `pythonpath = .`, so the suite runs from the
project root without installing the package.

## Real pytest output

Output from `python -m pytest -v` on the delivered project:

```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0 -- C:\Users\USER\AppData\Local\Programs\Python\Python312\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\USER\Documents\Qoder\2026-10-30\96491a2e\cyberfox
configfile: pytest.ini
testpaths: tests
collecting ... collected 46 items

tests/test_app.py::test_root_redirects_to_dashboard PASSED               [  2%]
tests/test_app.py::test_dashboard_loads_with_sample PASSED               [  4%]
tests/test_app.py::test_alerts_page_lists_engine_alerts PASSED           [  6%]
tests/test_app.py::test_alerts_severity_filter PASSED                    [  8%]
tests/test_app.py::test_alerts_source_filter PASSED                      [ 10%]
tests/test_app.py::test_alerts_search_filter PASSED                      [ 13%]
tests/test_app.py::test_alerts_search_with_no_results PASSED             [ 15%]
tests/test_app.py::test_analyze_page_offers_upload_and_sample PASSED     [ 17%]
tests/test_app.py::test_sample_preview_shows_statistics PASSED           [ 19%]
tests/test_app.py::test_upload_preview_lists_invalid_rows PASSED         [ 21%]
tests/test_app.py::test_upload_rejects_non_csv PASSED                    [ 23%]
tests/test_app.py::test_unknown_token_is_rejected PASSED                 [ 26%]
tests/test_app.py::test_path_traversal_token_is_rejected PASSED          [ 28%]
tests/test_app.py::test_sample_run_stores_analysis_and_redirects PASSED  [ 30%]
tests/test_app.py::test_uploaded_file_is_removed_after_analysis PASSED   [ 32%]
tests/test_app.py::test_sample_download PASSED                           [ 34%]
tests/test_app.py::test_unknown_run_returns_404 PASSED                   [ 36%]
tests/test_engine.py::test_engine_merges_alerts_and_flags_events PASSED  [ 39%]
tests/test_engine.py::test_alerts_are_sorted_by_severity PASSED          [ 41%]
tests/test_engine.py::test_empty_events_produce_empty_result PASSED      [ 43%]
tests/test_ml.py::test_build_features_per_ip PASSED                      [ 45%]
tests/test_ml.py::test_isolation_forest_flags_extreme_ip PASSED          [ 47%]
tests/test_ml.py::test_detection_is_deterministic PASSED                 [ 50%]
tests/test_ml.py::test_too_few_ips_returns_no_alerts PASSED              [ 52%]
tests/test_ml.py::test_empty_events_return_no_alerts PASSED              [ 54%]
tests/test_parser.py::test_missing_file_raises_parse_error PASSED        [ 56%]
tests/test_parser.py::test_empty_file_raises_parse_error PASSED          [ 58%]
tests/test_parser.py::test_missing_required_column_is_reported PASSED    [ 60%]
tests/test_parser.py::test_valid_rows_and_statistics PASSED              [ 63%]
tests/test_parser.py::test_invalid_rows_are_reported_with_line_numbers PASSED [ 65%]
tests/test_parser.py::test_blank_lines_are_ignored PASSED                [ 67%]
tests/test_parser.py::test_header_only_file_is_valid PASSED              [ 69%]
tests/test_parser.py::test_label_column_is_optional PASSED               [ 71%]
tests/test_parser.py::test_ipv6_and_lower_case_values_are_normalised PASSED [ 73%]
tests/test_rules.py::test_alert_schema PASSED                            [ 76%]
tests/test_rules.py::test_brute_force_threshold PASSED                   [ 78%]
tests/test_rules.py::test_brute_force_below_threshold PASSED             [ 80%]
tests/test_rules.py::test_brute_force_outside_window_is_not_combined PASSED [ 82%]
tests/test_rules.py::test_brute_force_from_different_ips_is_not_combined PASSED [ 84%]
tests/test_rules.py::test_successful_login_after_burst_is_critical PASSED [ 86%]
tests/test_rules.py::test_port_scan_threshold PASSED                     [ 89%]
tests/test_rules.py::test_port_scan_below_threshold PASSED               [ 91%]
tests/test_rules.py::test_flood_threshold PASSED                         [ 93%]
tests/test_rules.py::test_flood_below_threshold PASSED                   [ 95%]
tests/test_rules.py::test_off_hours_successful_login PASSED              [ 97%]
tests/test_rules.py::test_off_hours_ignores_business_hours_and_failures PASSED [100%]

============================= 46 passed in 32.40s =============================
```

## Test cases

### Parser — `tests/test_parser.py` (9)

| Test | What it proves |
| --- | --- |
| `test_missing_file_raises_parse_error` | A missing path fails with a clear `ParseError` |
| `test_empty_file_raises_parse_error` | An empty file is rejected, not parsed as zero rows |
| `test_missing_required_column_is_reported` | Header validation names the missing column |
| `test_valid_rows_and_statistics` | Types, counts, time range and failure rate are correct |
| `test_invalid_rows_are_reported_with_line_numbers` | Bad rows keep physical line numbers and reasons |
| `test_blank_lines_are_ignored` | Blank lines do not become invalid rows |
| `test_header_only_file_is_valid` | A header-only file yields an empty, valid frame |
| `test_label_column_is_optional` | Detection does not require ground-truth labels |
| `test_ipv6_and_lower_case_values_are_normalised` | IPv6 is accepted and event/status casing normalised |

### Rules — `tests/test_rules.py` (12)

| Test | What it proves |
| --- | --- |
| `test_alert_schema` | Every alert has IP, user, timestamp, severity, reason, source, MITRE |
| `test_brute_force_threshold` | Five failures inside ten minutes fire a High alert |
| `test_brute_force_below_threshold` | Four failures do not fire |
| `test_brute_force_outside_window_is_not_combined` | Failures spread beyond ten minutes do not combine |
| `test_brute_force_from_different_ips_is_not_combined` | Counts are per IP |
| `test_successful_login_after_burst_is_critical` | A success after the burst upgrades severity to Critical |
| `test_port_scan_threshold` | Fifteen distinct ports fire T1046 |
| `test_port_scan_below_threshold` | Fourteen ports do not fire |
| `test_flood_threshold` | Sixty events in a minute fire T1498 |
| `test_flood_below_threshold` | Fifty-nine events do not fire |
| `test_off_hours_successful_login` | Successful 23:00–05:00 login fires T1078 |
| `test_off_hours_ignores_business_hours_and_failures` | Business-hour and failed logins are ignored |

### Machine learning — `tests/test_ml.py` (5)

| Test | What it proves |
| --- | --- |
| `test_build_features_per_ip` | The five per-IP features are computed correctly |
| `test_isolation_forest_flags_extreme_ip` | A deliberately extreme IP produces a Critical alert |
| `test_detection_is_deterministic` | The same input and seed give the same alerts |
| `test_too_few_ips_returns_no_alerts` | Fewer than five IPs skips modelling safely |
| `test_empty_events_return_no_alerts` | Empty input returns no alerts |

### Engine — `tests/test_engine.py` (3)

| Test | What it proves |
| --- | --- |
| `test_engine_merges_alerts_and_flags_events` | Rule and ML alerts merge; counts and flags agree |
| `test_alerts_are_sorted_by_severity` | Critical alerts sort before High, Medium and Low |
| `test_empty_events_produce_empty_result` | Empty input produces a zeroed summary |

### Web routes — `tests/test_app.py` (17)

| Test | What it proves |
| --- | --- |
| `test_root_redirects_to_dashboard` | `/` redirects to `/dashboard` |
| `test_dashboard_loads_with_sample` | Dashboard renders sample figures and labels |
| `test_alerts_page_lists_engine_alerts` | Alerts page lists stored engine alerts |
| `test_alerts_severity_filter` | Severity filter returns only Critical rows |
| `test_alerts_source_filter` | Source filter returns only ML rows |
| `test_alerts_search_filter` | Search matches IP and excludes other sources |
| `test_alerts_search_with_no_results` | No-match search shows the empty state |
| `test_analyze_page_offers_upload_and_sample` | Analyze page offers upload and sample actions |
| `test_sample_preview_shows_statistics` | Sample preview shows stats, rows and a run token |
| `test_upload_preview_lists_invalid_rows` | Upload preview shows the rejected line and reason |
| `test_upload_rejects_non_csv` | Non-CSV uploads are rejected with a message |
| `test_unknown_token_is_rejected` | Unknown upload tokens cannot start a run |
| `test_path_traversal_token_is_rejected` | Traversal tokens are rejected and no run is stored |
| `test_sample_run_stores_analysis_and_redirects` | A run is stored and redirects to the result page |
| `test_uploaded_file_is_removed_after_analysis` | The temporary upload is deleted after analysis |
| `test_sample_download` | Sample CSV downloads as an attachment |
| `test_unknown_run_returns_404` | Unknown run ids render the 404 page |

## What is not covered

- No browser automation inside pytest; responsive layout and the Chart.js render were checked
  manually in Chrome at 1440 px and 390 px.
- No load, concurrency or rate-limit testing.
- No authentication or CSRF tests because the prototype has no accounts or forms with state
  changing GET requests.
- Detection quality is measured on one synthetic dataset only; see the results section in
  [README.md](README.md) for the honest limitations.
