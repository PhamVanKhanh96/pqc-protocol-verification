# ProVerif verification revision 186

This five-file package accompanies manuscript revision 186. A new native Linux ProVerif 2.04 execution checks **19 models and 114 selected results**. Every selected result matches its declared expectation. The baseline has **20 TRUE security results** and three FALSE negated-reachability results confirming honest send, receive and login. Diagnostic FALSE results identify assumption boundaries; this is not a count of 114 positive security theorems.

Revision 186 corrects the session identifier assumption to match Fig. 5: SID is fresh and confidential on the protected setup channels and in protected session/audit state. The public report remains E_SS || E_SK || IV || E_m; signing remains Sign(m) with an empty context. No cryptographic message or figure is changed. Existing phase-2 and bounded lifecycle scenarios are retained. The standalone signature diagnostic deliberately exposes its record and remains distinct from the protected report protocol.

## Five files

| File | Contents |
| --- | --- |
| `README.md` | Scope and reproduction instructions. |
| `pqc_authenticated_connection_v186.pv` | Directly readable and runnable baseline. |
| `verification_suite.json` | Other 18 model sources, exact 114-query manifest, hashes and historical query crosswalk. |
| `recorded_results.json` | Complete solver stdout/stderr, per-model receipts, engine identity and historical build provenance. |
| `run_verification.py` | Standard-library Python checker, exporter and native solver runner. |

## Security interpretation

| Scenario | Shared secret SS | Wrapping key | Content key and fresh message |
| --- | --- | --- | --- |
| Both epoch responses disclosed after actual RX completion; SID/control histories protected | Exposed | Secret | Secret |
| Same disclosure plus completed-session SID | Exposed | Exposed | Exposed |
| Unbounded other-session secret disclosures under the same unrevealed epoch roots | Target secret | Target secret | Target secret |
| Same other-session disclosures, but content key reused | Target secret | Target secret | Target exposed |

The forward-secrecy experiment uses ProVerif phase 1 only after an actual completed receive in phase 0. Both RX and TX epoch responses are disclosed. The private completion observer is test instrumentation, not a network acknowledgement. F06/F07 confirm that the roots become known, F08 witnesses completion followed by disclosure, and F09 checks the ordering. F01/F03/F04/F05 preserve the completed SID, wrapping key, content key and message. F02 deliberately fails because a revealed RX response permits valid-ciphertext decapsulation regardless of fallback z. Revealing SID as well makes all five secrecy queries fail.

This establishes **symbolic content-key forward secrecy against post-session PQC-response disclosure with SID/control histories protected**. It does not establish forward secrecy of SS, security against a CA-store or transport-key compromise, physical erasure, or authentication/recovery after compromise. The current software audit stores retain SID and assume protected storage. A deployment seeking protection after transport-key or database compromise needs additional channel/lifecycle guarantees; they are not silently assumed proved here.

The known-key model exposes SID, SS, wrapping/content keys, encapsulation/signing randomness and signed plaintext from arbitrarily many non-target sessions under the target's epoch roots. The target has fresh independent values. Non-target secrets can be disclosed before target completion, a conservative strengthening of an after-completion reveal. The model has only one kind of queried target receiver; exposed sessions provide honest sender records and explicitly reveal their generated secrets. K01 and K02 witness exposure and exposure together with target acceptance. This is not a test of compromise of target state or roots. Reusing content keys fails even with a fresh secret target SID.

With secret SID, the full-report signed-plaintext exposure diagnostic preserves Q11/Q13/Q16. Omitting SID from key derivation makes those correspondences fail. The standalone public-signature diagnostic still shows that Sign(m) alone does not bind identities, roles, SID or epochs. These differences correct the old public-SID interpretation; they do not modify the signature format.

ProVerif uses ideal KEM, signature, key-wrap and hash terms, exact PUF reconstruction, and selected CFB malleability rules. The application hash is a public constructor. A fresh private SID name abstracts an independent random 128-bit value; symbolic secrecy does not quantify guessing, entropy, collisions, quantum attacks or concrete composition security. Trusted CA, protected control channels, protected storage and the stated response/joint-use premises remain. The administrative revocation reference is separate software evidence.

## Check or export without running the solver

```sh
python3 run_verification.py --check-only
python3 run_verification.py --export-models exported-models
python3 run_verification.py --export-evidence exported-evidence
```

Use new output directories. The check reconciles source hashes, complete transcripts, native receipts and every selected verdict. Export reconstructs all 19 sources and full evidence. It does not execute ProVerif. Original host paths identify provenance and need not exist on another machine.

## Run ProVerif

With an installed native ProVerif 2.04 executable:

```sh
python3 run_verification.py --proverif proverif --timeout 180
```

Windows PowerShell:

```powershell
py -3 run_verification.py --check-only
py -3 run_verification.py --proverif "C:\Tools\ProVerif\proverif.exe" --execution-route "native Windows ProVerif 2.04" --timeout 180
```

The recorded execution was on Linux, not Windows. The executable is a subprocess argument; no shell command interpolation or Windows/WSL path conversion is performed. A fresh timestamped results directory preserves each new run. `--out NEW_DIRECTORY` selects another location. The timeout is per model; the bounded lifecycle model may need longer on slower systems. The bundle contains no solver binary.

Direct baseline:

```sh
proverif -in pitype pqc_authenticated_connection_v186.pv
```

Official ProVerif 2.04 source: https://bblanche.gitlabpages.inria.fr/proverif/proverif2.04.tar.gz
Source SHA-256: a96e5ec13f35c9ead7a0e960df69bc4018eb6a46939da501613d9d93cab5fc75
The retained executable was built from the official unmodified source with OCaml 4.14.2. Build logs and the original build receipt are explicitly historical; the revision-186 run receipts and complete output are new.

Preserve file bytes. On Windows, disable Git line-ending conversion when checking out this release, for example `git -c core.autocrlf=false clone REPOSITORY_URL`. Source hashes detect re-encoding. New runs compare semantic verdicts, since stdout can vary by platform.

## Publication

These five files are supplied for updating the repository. This task did not publish them. The previously cited immutable commit 891e14b contains older models; it must not be cited as the location of the new results. Replace the five release files, remove the obsolete v133 baseline file if present, and record the new commit identifier in the manuscript citation. Historical material remains in the full manuscript package.

Recorded run completed/collected (UTC): 2026-10-15T08:07:51.604594+00:00

## File hashes

| File | SHA-256 |
| --- | --- |
| `pqc_authenticated_connection_v186.pv` | `d469fbc3c9f8f5ac7811e06d0cf8e434938b87bdcb4b3ab6e11612d2dec3bc66` |
| `recorded_results.json` | `4d5fd5c06ae127a19d4b4b9290d1e8ebd6fdaeddad1c0a8441c700f7988878fd` |
| `run_verification.py` | `e57a9e5c8b1f64d41e6d7cf32dd975087252400b64256048249c77fc635b3c3a` |
| `verification_suite.json` | `6d1420943edd1a8077926245b924150b9577732d0e4713d3f8d36e7970ef5516` |
