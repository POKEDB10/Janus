# Recorded sample fixtures

Recorded samples are deliberately separate from live analysis. They must be captured from the running Janus API, never authored in the UI.

The UI treats `GET /api/analysis/:id/results` → `compliance` as the canonical compliance source. Findings, CVE/CWE/CVSS/NVD references, and post-quantum status must come from that embedded object rather than a second compliance endpoint.

Run `node scripts/record-fixtures.mjs --base-url http://127.0.0.1:8000 --capture scenario_01` after a real pipeline run. To record every available sample, use `--all-samples`; the script skips `scenario_04`. It removes capture tokens and request credentials before writing the response JSON here.

Do not record `scenario_04` until the backend's forced score and grade override has been removed and the returned result is verified.
