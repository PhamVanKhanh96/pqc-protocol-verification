# ProVerif verification sources and complete recorded results

This five-file release supports manuscript and response v166. The models and recorded solver results remain unchanged from the release prepared with manuscript v163 and response v164. It preserves all **15 current model sources and 79 query expectations unchanged**. The primary model remains a directly readable `.pv` file. Its `v133` filename identifies the unchanged model revision, not the manuscript revision.

The recorded native ProVerif 2.04 run completed on **13 October 2026 at 08:35:19 UTC**: all 79 selected queries resolved with their expected verdicts; all 15 processes exited successfully without timeout. The primary model has **19 TRUE security queries and three FALSE negated reachability queries**, which witness honest executions. Expected FALSE results in diagnostic variants identify assumption boundaries; 79 results are not 79 positive security theorems. This packaging update is **not a new solver run**.

## Five files

| File | Contents |
| --- | --- |
| `README.md` | Scope, provenance and reproduction commands. |
| `pqc_authenticated_connection_v133.pv` | Unchanged primary model, readable and runnable directly. |
| `verification_suite.json` | The 14 supplementary model texts, exact query manifest, source hashes and historical query crosswalk. |
| `recorded_results.json` | Complete native stdout/stderr, original receipts, engine records, per-model metadata and build logs, stored as lossless UTF-8 text with SHA-256 hashes. |
| `run_verification.py` | Standard-library Python checker, exporter and solver runner. |

No solver binary or dependency source archive is included. Checking and exporting require only Python 3. Running the models additionally requires an installed **native ProVerif 2.04** executable. The recorded run used Linux x86-64, OCaml 4.14.2 and official unmodified ProVerif source. Official source URLs and hashes are preserved in the recorded `RECEIPT.json` and are listed below. A native Windows executable can run the same model bytes; this package does not claim a newly executed Windows run.

## Check or inspect the evidence

Run from this directory. Use `python3` on Linux/macOS, or replace it with `py -3` on Windows.

```sh
python3 run_verification.py --check-only
python3 run_verification.py --export-models exported-models
python3 run_verification.py --export-evidence exported-evidence
```

The output directories must not already exist. The check verifies all model and full-transcript hashes, reconciles the native receipt, and parses all 79 selected verdicts from the complete stdout. It does **not** execute ProVerif. Exporting reconstructs the original `.pv` files and evidence bytes; the evidence directory contains `results/`, `build_logs/` and `RECEIPT.json`. Original absolute paths in receipts document the recorded host and need not exist on your machine.

## Run all 15 models again

Linux, with ProVerif 2.04 on `PATH`:

```sh
python3 run_verification.py --proverif proverif --execution-route "native installed ProVerif 2.04" --timeout 180
```

Windows PowerShell, using the actual installed executable path:

```powershell
py -3 run_verification.py --check-only
py -3 run_verification.py --proverif "C:\Tools\ProVerif\proverif.exe" --execution-route "native Windows ProVerif 2.04" --timeout 180
```

`--proverif` passes the executable as a Python subprocess argument, so paths with spaces do not require JSON escaping. Prefer a direct native executable; these commands do not perform Windows/WSL path conversion. Advanced command prefixes remain available through `--command-json`.

A solver run creates a new timestamped directory under `results/`, containing the exact exported sources, engine identity, full stdout/stderr and per-query comparisons. Use `--out NEW_DIRECTORY` to choose another destination. `--timeout` is a limit **per model**, not total suite time; slower machines may need a larger value. Never replace the recorded evidence with new output silently.

For a direct baseline check only:

```sh
proverif -in pitype pqc_authenticated_connection_v133.pv
```

## Provenance and interpretation

The complete recorded transcripts are from the native Linux run on 13 October 2026, not from the earlier October 2 compatibility route. The public package changes the evidence container/checker while retaining every current model byte and query expectation. Supplementary models and the manifest can be extracted without ProVerif. The historical 23-to-19 crosswalk remains reference metadata and is not an additional model in the 15-model execution count.

- ProVerif 2.04 official source: <https://bblanche.gitlabpages.inria.fr/proverif/proverif2.04.tar.gz>
  SHA-256: `a96e5ec13f35c9ead7a0e960df69bc4018eb6a46939da501613d9d93cab5fc75`
- OCaml 4.14.2 official source used for the recorded build: <https://caml.inria.fr/pub/distrib/ocaml-4.14/ocaml-4.14.2.tar.gz>
  SHA-256: `93b4f3ba39d559a963fc10744563b4c6e92e9ffb540ce89e5c5ebf76086b99f3`

Preserve downloaded file bytes. Automatic line-ending conversion of the raw `.pv` file causes its checksum check to fail. For a Git checkout on Windows, clone with `git -c core.autocrlf=false clone REPOSITORY_URL`, or download the files without text re-encoding. New solver stdout may differ by toolchain/platform even when the selected semantic verdicts agree; the runner compares those verdicts for new executions.

The symbolic conclusions retain the manuscript's trusted-authority, protected-channel/interface, response and joint-use assumptions. Sign(m), the empty ML-DSA context and the distinction between content origin, at-most-once acceptance and same-session correspondence are unchanged. These results do not establish physical PUF/TRNG properties, concrete PQC security, post-disclosure recovery or embedded timing.

## Package hashes

These hashes identify the supplied files; they are not a digital signature of the publisher.

| File | SHA-256 |
| --- | --- |
| `pqc_authenticated_connection_v133.pv` | `e247f941918eb489f8ed64b5662dffbbd1e26f55466be7374d21e81781e33465` |
| `verification_suite.json` | `777a92529d59566afa0a80f91187d156776a6e2d6d27d681863c01efc9f103e4` |
| `recorded_results.json` | `0cabd21bd06f61ff70919109caf2ffa77f0b02466544675cb7b8a1e6687ce847` |
| `run_verification.py` | `79cb538bf3a328ec5b23599f9ce7b6dc8d83ef7f6c176c258143e09d16343ca4` |
