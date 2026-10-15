#!/usr/bin/env python3
"""Check complete recorded evidence, export sources/logs, or run the ProVerif suite."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import subprocess
import time

BASE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(s): return re.sub(r'\s+','',s)

def parse(stdout,queries):
    lines=[];seen=set();auxiliary=[]
    for raw in stdout.splitlines():
        raw=raw.strip().lstrip('\ufeff')
        if not raw.startswith('RESULT '):continue
        key=compact(raw)
        if key in seen:continue
        seen.add(key)
        if key.startswith(('RESULT(but','RESULT(even')):
            auxiliary.append(raw);continue
        lines.append(raw)
    matched={q['id']:[] for q in queries};unmapped=[]
    for raw in lines:
        key=compact(raw)
        hits=[]
        for q in queries:
            kind=('secrecy' if re.search(r'attacker(?:_p[0-9]+)?\(',key) else 'correspondence' if '==>' in key else 'reachability')
            if kind!=q['kind']:continue
            if ('inj-event(' in key)!=q['injective']:continue
            if all(name+'(' in key for name in q['match_events']):hits.append(q)
        if hits:
            specificity=max(len(q['match_events']) for q in hits)
            hits=[q for q in hits if len(q['match_events'])==specificity]
        if len(hits)!=1:unmapped.append(raw);continue
        m=re.search(r'\bis\s+(true|false)\s*\.\s*$',raw)
        matched[hits[0]['id']].append({'raw':raw,'result':m.group(1) if m else 'unknown'})
    rows=[]
    for q in queries:
        results={r['result'] for r in matched[q['id']]}
        observed=next(iter(results)) if len(results)==1 else 'missing' if not results else 'conflict'
        rows.append(dict(q,observed_result=observed,raw_result_lines=[r['raw'] for r in matched[q['id']]],matches_expectation=observed==q['expected_printed_result']))
    return rows,unmapped,auxiliary


def load_release():
    suite_bytes = (BASE / 'verification_suite.json').read_bytes()
    suite = json.loads(suite_bytes)
    if suite.get('schema_version') != 1:
        raise ValueError('Unsupported verification suite schema')
    manifest_bytes = suite['query_manifest_json'].encode('utf-8')
    if sha(manifest_bytes) != suite['query_manifest_sha256']:
        raise ValueError('Query manifest checksum mismatch')
    manifest = json.loads(manifest_bytes)
    declarations = {model['file']: model for model in manifest['models']}
    if len(declarations) != 19 or len(manifest['models']) != 19:
        raise ValueError('The manifest must contain nineteen distinct models')
    primary = suite['primary_model']
    if primary not in declarations or Path(primary).name != primary:
        raise ValueError('Invalid primary model filename')
    sources = {primary: (BASE / primary).read_bytes()}
    for model in suite['supplementary_models']:
        name = model['file']
        if Path(name).name != name or name in sources:
            raise ValueError('Invalid or duplicate model filename: ' + name)
        data = model['source_utf8'].encode('utf-8')
        if sha(data) != model['sha256']:
            raise ValueError('Embedded source checksum mismatch: ' + name)
        sources[name] = data
    if set(sources) != set(declarations):
        raise ValueError('Embedded sources differ from the query manifest')
    for name, data in sources.items():
        if sha(data) != declarations[name]['sha256']:
            raise ValueError('Source checksum mismatch: ' + name)
    recorded_bytes = (BASE / 'recorded_results.json').read_bytes()
    if sha(recorded_bytes) != suite['recorded_results_sha256']:
        raise ValueError('Recorded results checksum mismatch')
    return suite, manifest, sources, json.loads(recorded_bytes), sha(suite_bytes)


def safe_relative(name):
    path = PurePosixPath(name)
    if not isinstance(name, str) or not name or path.is_absolute() or any(part in ('.', '..') for part in path.parts) or ':' in name or '\\' in name:
        raise ValueError('Unsafe evidence path: ' + str(name))
    return Path(*path.parts)


def evidence_files(recorded):
    files = {}
    for model in recorded['models']:
        for stream in ('stdout', 'stderr'):
            name = model[stream + '_file']
            if Path(name).name != name:
                raise ValueError('Invalid transcript filename: ' + name)
            path = 'results/' + name
            data = model[stream + '_utf8'].encode('utf-8')
            if sha(data) != model['full_' + stream + '_sha256']:
                raise ValueError('Full transcript checksum mismatch: ' + path)
            if path in files:
                raise ValueError('Duplicate evidence path: ' + path)
            safe_relative(path)
            files[path] = data
    for entry in recorded['supporting_files']:
        path = entry['file']
        safe_relative(path)
        data = entry['utf8'].encode('utf-8')
        if sha(data) != entry['sha256']:
            raise ValueError('Supporting evidence checksum mismatch: ' + path)
        if path in files:
            raise ValueError('Duplicate evidence path: ' + path)
        files[path] = data
    return files


def check_recorded(suite, manifest, sources, recorded):
    if recorded.get('schema_version') != 2:
        raise ValueError('Complete-transcript evidence schema 2 is required')
    files = evidence_files(recorded)
    native_status = json.loads(files['results/RUN_STATUS.json'])
    if native_status['completed_utc'] != recorded['completed_utc'] or native_status['query_manifest_sha256'] != suite['query_manifest_sha256']:
        raise ValueError('Native run provenance differs')
    if not native_status['all_results_resolved'] or not native_status['expectations_met']:
        raise ValueError('Native run was incomplete')
    native_models = {model['model']: model for model in native_status['models']}
    if len(native_models) != 19 or len(native_status['models']) != 19:
        raise ValueError('Native record must contain nineteen distinct models')
    declared = {model['file']: model for model in manifest['models']}
    observed_names = [model['model'] for model in recorded['models']]
    if len(observed_names) != 19 or set(observed_names) != set(declared):
        raise ValueError('Recorded model list differs from the manifest')
    if recorded['manifest_sha256'] != suite['query_manifest_sha256']:
        raise ValueError('Recorded query manifest hash differs')
    count = 0
    baseline = None
    for result in recorded['models']:
        model = declared[result['model']]
        if result['source_sha256'] != sha(sources[result['model']]):
            raise ValueError('Recorded source hash differs: ' + model['file'])
        if result['exit_code'] != 0 or result['timed_out']:
            raise ValueError('Incomplete recorded run: ' + model['file'])
        native = native_models[result['model']]
        for current, original in [('source_sha256', 'model_sha256'), ('full_stdout_sha256', 'stdout_sha256'), ('full_stderr_sha256', 'stderr_sha256'), ('exit_code', 'exit_code'), ('timed_out', 'timed_out')]:
            if result[current] != native[original]:
                raise ValueError('Recorded transcript differs from native receipt: ' + model['file'])
        rows, unmapped, _ = parse(result['stdout_utf8'], model['queries'])
        if unmapped or not all(row['observed_result'] in ('true', 'false') and row['matches_expectation'] for row in rows):
            raise ValueError('Recorded verdicts differ from the manifest: ' + model['file'])
        count += len(rows)
        if model['file'] == suite['primary_model']:
            baseline = rows
    security = [row for row in baseline if row['kind'] != 'reachability']
    reachability = [row for row in baseline if row['kind'] == 'reachability']
    if count != 114 or len(security) != 20 or len(reachability) != 3:
        raise ValueError('Unexpected query counts')
    if not all(row['observed_result'] == 'true' for row in security):
        raise ValueError('Baseline security verdicts differ')
    if not all(row['observed_result'] == 'false' for row in reachability):
        raise ValueError('Baseline reachability verdicts differ')
    print('Checked 19 model sources, complete native transcripts and 114 recorded verdicts from ' + recorded['completed_utc'] + '. Baseline: 20 TRUE security queries and 3 reachable honest-execution checks. No solver execution was performed by this check.')


def export_models(sources, destination):
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in sources.items():
        (destination / name).write_bytes(data)
    return destination


def export_evidence(recorded, sources, destination):
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in evidence_files(recorded).items():
        path = destination / safe_relative(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    export_models(sources, destination / 'results' / 'models')
    return destination


def run_solver(args, suite, manifest, sources, suite_hash):
    command = json.loads(args.command_json)
    if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError('command-json must be a nonempty list of strings')
    if args.timeout <= 0:
        raise ValueError('timeout must be positive')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = (args.out or BASE / 'results' / stamp).resolve()
    out.mkdir(parents=True, exist_ok=False)
    models_dir = export_models(sources, out / 'models')
    engine = {
        'command_prefix': command,
        'execution_route': args.execution_route,
        'platform': platform.platform(),
        'command_file_sha256': {str(Path(item).resolve()): sha(Path(item).read_bytes()) for item in command if Path(item).is_file()},
    }
    help_run = subprocess.run(command + ['-help'], capture_output=True, timeout=min(15, args.timeout))
    (out / 'engine_help.stdout.txt').write_bytes(help_run.stdout)
    (out / 'engine_help.stderr.txt').write_bytes(help_run.stderr)
    engine.update(help_exit_code=help_run.returncode, version_line=help_run.stdout.decode(errors='replace').splitlines()[:1])
    (out / 'ENGINE.json').write_text(json.dumps(engine, indent=2) + '\n', encoding='utf-8')
    if help_run.returncode != 0:
        raise RuntimeError('The ProVerif help command failed; inspect ENGINE.json')
    records = []
    for model in manifest['models']:
        source = models_dir / model['file']
        cmd = command + ['-in', 'pitype', str(source)]
        started = time.monotonic()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=(os.name != 'nt'))
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == 'nt':
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        stdout_path = out / (source.stem + '.stdout.txt')
        stderr_path = out / (source.stem + '.stderr.txt')
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        rows, unmapped, auxiliary = parse(stdout.decode(errors='replace'), model['queries'])
        resolved = not timed_out and process.returncode == 0 and not unmapped and all(row['observed_result'] in ('true', 'false') for row in rows)
        record = {
            'model': model['file'], 'model_sha256': sha(source.read_bytes()), 'command': cmd,
            'exit_code': process.returncode, 'timed_out': timed_out,
            'elapsed_seconds': round(time.monotonic() - started, 4),
            'all_results_resolved': resolved,
            'expectations_met': resolved and all(row['matches_expectation'] for row in rows),
            'queries': rows, 'unmapped': unmapped, 'auxiliary': auxiliary,
            'stdout': stdout_path.name, 'stdout_sha256': sha(stdout),
            'stderr': stderr_path.name, 'stderr_sha256': sha(stderr),
        }
        (out / (source.stem + '.json')).write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
        records.append(record)
        print(model['file'] + ': ' + ', '.join(row['id'] + '=' + row['observed_result'] for row in rows), flush=True)
    status = {
        'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'query_manifest_sha256': suite['query_manifest_sha256'],
        'suite_sha256': suite_hash,
        'runner_sha256': sha(Path(__file__).read_bytes()),
        'all_results_resolved': all(record['all_results_resolved'] for record in records),
        'expectations_met': all(record['expectations_met'] for record in records),
        'models': records,
    }
    (out / 'RUN_STATUS.json').write_text(json.dumps(status, indent=2) + '\n', encoding='utf-8')
    print('Results: ' + str(out))
    return 0 if status['expectations_met'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument('--check-only', action='store_true', help='Check source/full-log hashes and recorded verdicts without running ProVerif')
    operation.add_argument('--export-models', type=Path, metavar='DIRECTORY', help='Export all nineteen original .pv sources into a new directory')
    operation.add_argument('--export-evidence', type=Path, metavar='DIRECTORY', help='Export complete recorded native logs, model snapshots and provenance into a new directory')
    operation.add_argument('--proverif', metavar='PATH', help='Run a native ProVerif executable by path or PATH name; avoids JSON quoting')
    operation.add_argument('--command-json', help='Run ProVerif using a JSON command-prefix list, for example ["proverif"]')
    parser.add_argument('--execution-route', default='native installed ProVerif', help='Describe the solver execution route used for this run')
    parser.add_argument('--out', type=Path, help='New output directory for a solver run')
    parser.add_argument('--timeout', type=float, default=60, help='Maximum seconds per model, default 60')
    args = parser.parse_args()
    try:
        suite, manifest, sources, recorded, suite_hash = load_release()
        check_recorded(suite, manifest, sources, recorded)
        if args.check_only:
            return 0
        if args.export_evidence:
            export_evidence(recorded, sources, args.export_evidence.resolve())
            print('Exported complete native-run evidence to ' + str(args.export_evidence.resolve()))
            return 0
        if args.export_models:
            export_models(sources, args.export_models.resolve())
            print('Exported 15 original .pv sources to ' + str(args.export_models.resolve()))
            return 0
        if args.proverif:
            args.command_json = json.dumps([args.proverif])
        return run_solver(args, suite, manifest, sources, suite_hash)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Error: ' + str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
