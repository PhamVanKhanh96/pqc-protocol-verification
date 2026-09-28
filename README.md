# PQC protocol verification

Five self-contained ProVerif models for the PUF–TRNG-assisted post-quantum IoT protocol.

## Run

Install ProVerif separately and make its executable available on `PATH`. The
reference tool version is 2.04. From this directory, run:

```sh
proverif -in pitype pqc_current_v91.pv
proverif -in pitype signature_exposure_v91.pv
proverif -in pitype rx_response_exposure_v91.pv
proverif -in pitype kw_without_sid_v91.pv
proverif -in pitype report_evidence_exposure_v91.pv
```

On Windows, use `proverif.exe` in place of `proverif`. No Python packages,
manifest or auxiliary source files are required.

## Models

| File | Purpose |
|---|---|
| `pqc_current_v91.pv` | Baseline protocol and its stated assumptions |
| `signature_exposure_v91.pv` | Standalone signature-binding diagnostic |
| `rx_response_exposure_v91.pv` | Disclosure of the receiver response |
| `kw_without_sid_v91.pv` | Key wrapping without SID binding |
| `report_evidence_exposure_v91.pv` | Exposure of a valid message/signature pair in the full protocol |

These are symbolic models of the ML-KEM-512/ML-DSA-44 protocol with a 256-bit
reconstructed response and AES-128-CFB report encryption; byte-level algorithms
and physical security are not verified. Enrollment, owner authentication,
authority policy, perfect reconstruction and atomic single-use state are premises.
Message-only signatures do not independently bind the intended receiver or SID.
The diagnostics intentionally relax assumptions and may produce counterexamples.
The two baseline `not event` completion queries test reachability: `false` means
an honest completion is reachable, not that a secrecy query failed.

This source-only package omits archived execution logs. It does not represent a
new solver run. Model declarations, processes and queries are unchanged; only
obsolete documentation references in comments were removed.

No repository-wide reuse license has been selected by the rights holders.
ProVerif and third-party examples or binaries are not distributed here.
