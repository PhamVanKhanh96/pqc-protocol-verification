# PQC protocol verification

This five-file release preserves all 15 ProVerif models and the 79 selected queries of the full verification suite. The validated v133 model filenames are retained for source traceability.

| File | Purpose |
|---|---|
| `pqc_authenticated_connection_v133.pv` | Main protocol model: 19 security queries and three honest-execution reachability checks. |
| `verification_suite.json` | Fourteen supplementary model sources, the original query manifest and source hashes. |
| `recorded_results.json` | Recorded solver verdicts, source/transcript hashes and execution provenance. |
| `run_verification.py` | Checks the release, exports model files or runs the complete suite. Python standard library only. |
| `README.md` | Instructions. |

Install ProVerif 2.04 to run the main model directly:

```bash
proverif -in pitype pqc_authenticated_connection_v133.pv
```

With Python 3, check the source hashes and archived verdicts without running ProVerif:

```bash
python run_verification.py --check-only
```

Run all 15 models with ProVerif:

```bash
python run_verification.py --command-json '["proverif"]' --execution-route 'native installed ProVerif 2.04'
```

Replace `proverif` inside the JSON list with the executable path if it is not on PATH. The runner writes the supplementary sources verbatim to a new output directory before invoking the solver. It records complete stdout/stderr, commands, source hashes and observed verdicts. Use `--out DIRECTORY` to choose a new results directory or `--timeout 180` for a slower machine. Generated results are separate from the five upload files.

To inspect or run every `.pv` file manually:

```bash
python run_verification.py --export-models exported_models
```

The supplementary models cover Phase-2 diagnostic variants, response/signature exposure, SID-dependent wrapping, bounded connection lifecycle and pending disconnect. Their source bytes and queries are unchanged. FALSE verdicts are expected for designated diagnostic properties; FALSE for a NOT-event reachability query indicates the event is reachable. The main baseline has 19 TRUE security verdicts and three reachable honest-execution checks.

Python coordinates reproduction and checks the recorded results. ProVerif performs the symbolic protocol verification. The recorded results preserve the executed solver route.
