"""Read-only PBX discovery, explicit path selection and runtime-user checks.

Standalone discovery uses only the standard library. Verification uses the
installed Agent's readers/connector and never prints credentials or call data.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

KEYS = {
    'asterisk': ('ASTERISK_CDR_CSV_PATH', 'ASTERISK_VOICEMAIL_PATH', 'ASTERISK_RECORDINGS_PATH'),
    'freeswitch': ('FREESWITCH_CDR_JSON_PATH', 'FREESWITCH_VOICEMAIL_PATH', 'FREESWITCH_RECORDINGS_PATH'),
}
LABELS = ('Completed calls (CDR)', 'Voicemail', 'Recordings')
LIMIT = 262144


def command(args, *, input_text=None, timeout=5):
    try:
        result = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return result.stdout.strip() if result.returncode == 0 and len(result.stdout) <= LIMIT else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def read_env(path):
    values = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    return values


def save_env(path, updates):
    target = Path(path)
    lines = target.read_text(encoding='utf-8').splitlines()
    seen = set()
    output = []
    for line in lines:
        key = line.split('=', 1)[0]
        if key in updates:
            if key not in seen:
                output.append(f'{key}={updates[key]}')
            seen.add(key)
        else:
            output.append(line)
    output.extend(f'{key}={value}' for key, value in updates.items() if key not in seen)
    # Preserve existing credentials/permissions; never source the env as shell code.
    target.write_text('\n'.join(output) + '\n', encoding='utf-8')


class Discovery:
    def __init__(self, pbx, *, run=command, exists=None, read=None, container='', mounts=()):
        self.pbx, self.run = pbx, run
        self.container, self.mounts = container, mounts
        self.exists = exists or (lambda path: Path(path).exists())
        self.read = read or self._read
        self.notes = []
        self.paths = [[], [], []]

    def host_path(self, path):
        if not self.container:
            return path
        for mount in sorted(self.mounts, key=lambda m: len(m.get('Destination', '')), reverse=True):
            root = mount.get('Destination', '').rstrip('/')
            if root and (path == root or path.startswith(root + '/')) and mount.get('Source'):
                return mount['Source'].rstrip('/') + path[len(root):]
        return ''

    def _read(self, path):
        try:
            with Path(path).open('rb') as file:
                data = file.read(LIMIT + 1)
            return data.decode('utf-8', errors='replace') if len(data) <= LIMIT else ''
        except OSError:
            return ''

    def config(self, path):
        host = self.host_path(path)
        text = self.read(host) if host else ''
        if not text and self.container:
            text = self.cli('head', '-c', str(LIMIT + 1), path)
        return text

    def cli(self, *args):
        return self.run((['docker', 'exec', self.container] if self.container else []) + list(args))

    def add(self, index, path, origin):
        if not path or not path.startswith('/') or '$' in path or any(c in path for c in '\r\n\x00'):
            return
        host = self.host_path(path)
        if host and self.exists(host) and all(item['path'] != host for item in self.paths[index]):
            self.paths[index].append({'path': host, 'origin': origin})

    def discover(self):
        if self.pbx == 'asterisk':
            settings = self.cli('asterisk', '-rx', 'core show settings')
            dirs = {'astlogdir':'/var/log/asterisk', 'astspooldir':'/var/spool/asterisk', 'astetcdir':'/etc/asterisk'}
            for key, label in (('astlogdir','Log'), ('astspooldir','Spool'), ('astetcdir','Configuration')):
                match = re.search(rf'^\s*{label}(?:ging)? directory\s*:\s*(/[^\r\n]+)', settings, re.I | re.M)
                if match:
                    dirs[key] = match[1].strip()
            config = self.config(dirs['astetcdir'] + '/asterisk.conf')
            section = ''
            for line in config.splitlines():
                if line.strip().startswith('['):
                    section = line.strip().split(']', 1)[0][1:]
                match = re.match(r'\s*(astlogdir|astspooldir|astetcdir)\s*=>?\s*(/[^;]+)', line)
                if section == 'directories' and match:
                    # Running PBX settings take precedence over possibly pending config.
                    label = {'astlogdir':'Log', 'astspooldir':'Spool', 'astetcdir':'Configuration'}[match[1]]
                    if not re.search(rf'^\s*{label}(?:ging)? directory\s*:', settings, re.I | re.M):
                        dirs[match[1]] = match[2].strip()
            for suffix in ('cdr-csv/Master.csv', 'cdr-custom/Master.csv', 'cdr/Master.csv'):
                self.add(0, dirs['astlogdir'] + '/' + suffix, 'PBX directories')
            self.add(1, dirs['astspooldir'] + '/voicemail', 'PBX spool directory')
            self.add(2, dirs['astspooldir'] + '/monitor', 'PBX spool directory')
            status = self.cli('asterisk', '-rx', 'cdr show status')
            if re.search(r'Logging\s*:\s*Disabled', status, re.I):
                self.notes.append('CDR logging is disabled in Asterisk. Enable a supported CSV backend explicitly; the installer will not change it.')
            elif status and not re.search(r'\bcsv\b', status, re.I):
                self.notes.append('No standard CSV backend confirmed. SQL/custom CDR output is not automatically compatible with Master.csv.')
            common = (('/var/log/asterisk/cdr-csv/Master.csv', '/var/log/asterisk/cdr-custom/Master.csv', '/var/log/asterisk/cdr/Master.csv'),
                      ('/var/spool/asterisk/voicemail','/var/lib/asterisk/voicemail'),
                      ('/var/spool/asterisk/monitor','/var/lib/asterisk/monitor'))
        else:
            variables = {}
            conf_guess = next((path for path in ('/etc/freeswitch','/usr/local/freeswitch/conf')
                               if self.config(path + '/vars.xml')), '/etc/freeswitch')
            try:
                text = self.config(conf_guess + '/vars.xml')
                if '<!DOCTYPE' in text.upper():
                    raise ET.ParseError('Unsupported declaration')
                for node in ET.fromstring(text).iter('X-PRE-PROCESS'):
                    if node.get('cmd') == 'set' and '=' in node.get('data', ''):
                        name, value = node.get('data').split('=', 1)
                        if name in ('conf_dir','log_dir','base_dir','storage_dir','recordings_dir'):
                            variables[name] = value
            except ET.ParseError:
                pass
            for name in ('conf_dir', 'log_dir', 'base_dir', 'storage_dir', 'recordings_dir'):
                value = self.cli('fs_cli', '-x', 'global_getvar ' + name)
                if value.startswith('/') and '\n' not in value:
                    variables[name] = value
            conf = variables.get('conf_dir', conf_guess)
            log = variables.get('log_dir', '/var/log/freeswitch')
            base = variables.get('base_dir', '/var/lib/freeswitch')
            variables.update(log_dir=log, base_dir=base)
            text = self.config(conf + '/autoload_configs/json_cdr.conf.xml')
            try:
                if '<!DOCTYPE' in text.upper():
                    raise ET.ParseError('Unsupported declaration')
                tree = ET.fromstring(text)
                for param in tree.findall('.//settings/param'):
                    if param.get('name') == 'log-dir':
                        value = param.get('value', '')
                        for name, setting in variables.items():
                            value = value.replace('$${' + name + '}', setting).replace('${' + name + '}', setting)
                        self.add(0, value + '/json_cdr', 'JSON CDR configuration')
                        self.add(0, value, 'JSON CDR configuration; check direct *.cdr.json output')
                        break
                else:
                    self.notes.append('JSON CDR disk logging is not configured in the inspected configuration. Configure mod_json_cdr explicitly before expecting history.')
            except ET.ParseError:
                self.notes.append('JSON CDR configuration could not be inspected; verify mod_json_cdr and its disk log-dir.')
            loaded = self.cli('fs_cli', '-x', 'module_exists mod_json_cdr')
            if loaded.lower() == 'false':
                self.notes.append('mod_json_cdr is not loaded. Enable it and disk logging explicitly; no PBX configuration was changed.')
            self.add(0, log + '/json_cdr', 'PBX log directory')
            self.add(0, log, 'PBX log directory; check direct *.cdr.json output')
            storage = variables.get('storage_dir', base + '/storage')
            self.add(1, storage + '/voicemail', 'PBX storage directory')
            self.add(2, variables.get('recordings_dir', storage + '/recordings'), 'PBX recording/storage directory')
            common = (('/var/log/freeswitch/json_cdr','/var/log/freeswitch/cdr-json','/var/log/cdr-json'),
                      ('/var/lib/freeswitch/storage/voicemail','/usr/local/freeswitch/storage/voicemail'),
                      ('/var/lib/freeswitch/recordings','/var/lib/freeswitch/storage/recordings','/usr/local/freeswitch/recordings'))
        for index, options in enumerate(common):
            for path in options:
                self.add(index, path, 'Common location')
        return self.paths


def select_path(label, candidates, current, *, interactive, ask=input):
    print('\n' + label)
    print('  Detected locations are suggestions; runtime access and content are checked after installation.')
    if label == LABELS[0]:
        print('  Optional: skipping disables completed-call history, not live monitoring.')
    else:
        print('  Optional: skipping disables this file-based feature, not the PBX connection.')
    for index, candidate in enumerate(candidates, 1):
        print(f"  {index}. {candidate['path']} ({candidate['origin']})")
    if current:
        print('  Existing setting: ' + current)
    if not interactive:
        return current or (candidates[0]['path'] if candidates else '')
    print('  m. Advanced: enter a path manually    s. Skip/disable this optional feature')
    default = ('keep ' + current) if current else ('use ' + candidates[0]['path'] if candidates else 'skip; no location detected')
    answer = ask(f'Choose a number, m or s [Enter: {default}]: ').strip().lower()
    if answer == 's':
        return ''
    if answer == 'm':
        value = ask('Absolute path (empty disables): ').strip()
        if value and (not value.startswith('/') or any(c in value for c in '\r\n\x00')):
            raise ValueError('Use a single absolute path.')
        return value
    if not answer:
        return current or (candidates[0]['path'] if candidates else '')
    if answer.isdigit() and 1 <= int(answer) <= len(candidates):
        return candidates[int(answer) - 1]['path']
    raise ValueError('Choose a listed number, m or s.')


def probe(path, kind, pbx):
    if not path:
        return {'state':'not configured', 'records':0}
    try:
        root = Path(path)
        if kind == 'cdr' and pbx == 'asterisk':
            with root.open('rb') as handle:
                handle.read(1)
        else:
            with os.scandir(root) as entries:
                next(entries, None)
        records = 0
        if kind == 'cdr':
            if pbx == 'asterisk':
                from pbxsense_agent.history import read_recent_cdr_calls
                calls = read_recent_cdr_calls(path, limit=5, strict=True)
            else:
                from pbxsense_agent.freeswitch import _read_json_cdr_calls
                calls = _read_json_cdr_calls(path, limit=5, strict=True)
            calls = [call for call in calls if call.started_at is not None and call.disposition]
            records = len(calls)
        result = {'state':'readable', 'records':records}
        if records:
            result['evidence'] = sorted(hashlib.sha256(json.dumps([str(call.started_at), call.source,
                call.destination, call.disposition, call.duration_seconds, call.channel], separators=(',',':')).encode()).hexdigest()
                for call in calls)
        return result
    except FileNotFoundError:
        return {'state':'missing', 'records':0}
    except PermissionError:
        return {'state':'permission denied', 'records':0}
    except (OSError, csv.Error):
        return {'state':'unreadable or incompatible', 'records':0}


def child(values, user='', *, paths_only=False):
    prefix = []
    if user:
        if not shutil.which('runuser'):
            return {}
        prefix = ['runuser', '-u', user, '--']
    raw = command(prefix + [sys.executable, str(Path(__file__).resolve()), 'check'] + (['--paths-only'] if paths_only else []),
                  input_text=json.dumps(values), timeout=45)
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def check(values, *, live=True):
    # This branch executes under the real service/container user, not root.
    os.environ.update(values)
    pbx = values.get('PBXSENSE_PBX_TYPE', 'asterisk')
    result = {'paths': [probe(values.get(key, ''), kind, pbx) for key, kind in
                       zip(KEYS[pbx], ('cdr','voicemail','recordings'))]}
    if not live:
        return result
    from pbxsense_agent.connectors import connector_for_settings
    from pbxsense_agent.settings import AgentSettings
    try:
        snapshot = connector_for_settings(AgentSettings.from_env()).snapshot()
        state = snapshot.sources.get('liveCalls', {}).get('state', 'ready')
        result['live'] = ('ready (successful live snapshot)' if state == 'ready' else
                          'connected; live-call capability not verified') if snapshot.reachable else 'connection/authentication not verified'
    except Exception:
        result['live'] = 'not verified; inspect Agent diagnostics'
    return result


def sandbox_blocked(path):
    return bool(path) and (path.startswith(('/home/', '/root/', '/tmp/', '/run/user/')) or
                          Path(path).resolve().as_posix().startswith(('/home/', '/root/', '/tmp/', '/run/user/')))


def report(values, *, user='', docker=False):
    result = child(values, user)
    print('\nAgent capability check (' + ('container runtime account' if docker else 'service account ' + (user or 'current user')) + ')')
    live = result.get('live', 'not verified')
    attention = not live.startswith('ready')
    print('  Live monitoring: ' + ('Ready — ' if not attention else 'Needs attention — ') + live)
    if attention:
        print('    Next: check the PBX host/port, connector credentials and monitoring permissions in Agent diagnostics. Do not use your Linux login or browser setup code as PBX credentials.')
    pbx = values.get('PBXSENSE_PBX_TYPE', '')
    for index, key in enumerate(KEYS.get(pbx, ())):
        row = result.get('paths', [{}, {}, {}])[index]
        path = values.get(key, '')
        if user and sandbox_blocked(path):
            row = {'state':'blocked/unavailable in native service sandbox', 'records':0}
        text = row.get('state', 'not verified under runtime account')
        if index == 0 and text == 'readable':
            text += ': parsed completed records found' if row.get('records') else ': no parseable completed records yet; logging/format still needs a test call'
        grade = 'Not enabled' if text == 'not configured' else ('Ready' if text == 'readable' or row.get('records', 0) > 0 else 'Needs attention')
        if index == 0 and text.startswith('readable') and not row.get('records'):
            grade = 'Needs confirmation'
        attention = attention or grade in ('Needs attention','Needs confirmation')
        print('  ' + LABELS[index] + ': ' + grade + ' — ' + text)
        if grade == 'Not enabled':
            print('    You can enable this optional source later; live monitoring can still work.')
        elif row.get('state') == 'permission denied':
            print('    Next: grant only the required read access to the Agent account/group. Do not make PBX files world-readable.')
        elif row.get('state') == 'missing':
            print('    Next: choose an existing PBX source; for Docker, check the host mount and container-visible path separately.')
        elif grade == 'Needs confirmation':
            print('    Next: run the completed-call check. Confirm CDR logging is enabled and uses a supported format.')
        elif grade == 'Needs attention':
            print('    Next: inspect the selected path and Agent diagnostics; sandbox restrictions may require a different source location.')
    print('  Summary: ' + ('Needs attention / functional confirmation' if attention else 'Ready for functional checks; optional disabled sources are not errors'))
    print('  No PBX files, modules, ownership or permissions were changed.')
    print('  Next: answer and end a test call, then verify it in Agent diagnostics and the app Calls screen.')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('select','report','check','watch-cdr'))
    parser.add_argument('--env-file')
    parser.add_argument('--pbx', choices=tuple(KEYS))
    parser.add_argument('--mode', choices=('native','docker'), default='native')
    parser.add_argument('--service-user', default='')
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--paths-only', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.action == 'select' and not args.env_file:
        parser.error('Path selection requires --env-file.')
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    if args.action == 'check':
        values = json.loads(sys.stdin.read(LIMIT))
        print(json.dumps(check(values, live=not args.paths_only)))
        return
    values = read_env(args.env_file) if args.env_file else dict(os.environ)
    pbx = args.pbx or values.get('PBXSENSE_PBX_TYPE', '')
    if pbx not in KEYS:
        return
    if args.action in ('report','watch-cdr'):
        if args.action == 'watch-cdr':
            key = KEYS[pbx][0]
            if not values.get(key):
                print('CDR is not configured. Select its source before testing a completed call.')
                report(values, user=args.service_user, docker=args.mode == 'docker')
                return
            if args.service_user and sandbox_blocked(values.get(key, '')):
                print('Selected CDR path is unavailable in the native service sandbox; cannot verify a test call.')
                report(values, user=args.service_user)
                return
            before = child(values, args.service_user, paths_only=True).get('paths', [{}])[0]
            # File change alone is not proof; require parseable records too.
            def signature():
                path = Path(values.get(key, '/nonexistent'))
                try:
                    if path.is_file():
                        stat = path.stat()
                        return (stat.st_mtime_ns, stat.st_size)
                    with os.scandir(path) as entries:
                        return sorted((item.name, item.stat().st_mtime_ns) for _, item in zip(range(1000), entries) if item.is_file() and item.name.endswith('.json'))
                except OSError:
                    return None
            baseline = signature()
            print('Make an answered test call now and end it. Watching for changed parseable CDR evidence for 60 seconds.')
            for _ in range(12):
                time.sleep(5)
                if signature() != baseline:
                    after = child(values, args.service_user, paths_only=True).get('paths', [{}])[0]
                    if after.get('records', 0) > 0 and after.get('evidence') != before.get('evidence'):
                        print('Changed, parseable completed-call evidence observed. Confirm the specific test call in the app; other PBX calls may also generate records.')
                        break
            else:
                print('No changed, parseable CDR evidence confirmed. Check logging, selected path, format and runtime permissions; this is not a successful test.')
        report(values, user=args.service_user, docker=args.mode == 'docker')
        return
    container, mounts = '', []
    if args.mode == 'docker' and not sys.stdin.isatty():
        print('Docker path selection skipped in noninteractive mode; existing environment/mounts are preserved.')
        return
    if args.mode == 'docker' and sys.stdin.isatty():
        print('Docker files are host sources, not container-visible paths. We will create read-only mounts separately.')
        container = input('PBX container name for read-only discovery [native PBX on this host]: ').strip()
        if container:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', container):
                raise ValueError('Use a Docker container name or ID.')
            raw = command(['docker','inspect','--format','{{json .Mounts}}',container])
            mounts = json.loads(raw) if raw else []
    discovery = Discovery(pbx, container=container, mounts=mounts)
    # Do not mistake a local PBX for a remote installation.
    host = values.get('ASTERISK_AMI_HOST' if pbx == 'asterisk' else 'FREESWITCH_ESL_HOST', '127.0.0.1')
    candidates = discovery.discover() if container or host in ('127.0.0.1','localhost','::1') else [[],[],[]]
    for note in discovery.notes:
        print('  Attention: ' + note)
    updates, bindings = {}, []
    for index, key in enumerate(KEYS[pbx]):
        current = values.get(key, '') if args.mode == 'native' and not args.fresh else ''
        while True:
            try:
                selected = select_path(LABELS[index], candidates[index], current, interactive=sys.stdin.isatty())
                break
            except ValueError as error:
                print(error)
        if args.mode == 'docker' and selected:
            source = Path(selected)
            if not source.exists():
                print('Selected Docker source does not exist. Rerun path selection and choose an existing host source or skip the feature.')
                raise ValueError('Docker bind source does not exist; refusing to create an empty host directory.')
            if source.resolve() == Path('/').resolve() or (index == 0 and pbx == 'asterisk' and not source.is_file()) or (
                    (index != 0 or pbx != 'asterisk') and not source.is_dir()):
                print('Use the specific CDR file or feature directory, not the filesystem root or an incompatible source type.')
                raise ValueError('Unsafe or incompatible Docker source.')
            target = '/var/lib/pbxsense-agent/pbx-files/' + ('cdr','voicemail','recordings')[index]
            if index == 0 and pbx == 'asterisk':
                target += '/' + source.name
            bindings.append({'type':'bind','source':str(source.resolve()),'target':target,'read_only':True})
            updates[key] = target
        else:
            updates[key] = selected
    if args.mode == 'docker':
        override = Path(args.env_file).resolve().parent / 'docker/docker-compose.detected.yml'
        if override.exists():
            print('Existing detected override preserved. Review it manually; container paths were not changed.')
            return
        override.parent.mkdir(parents=True, exist_ok=True)
        # JSON is valid YAML. Long bind syntax fails on missing sources rather
        # than silently creating folders; passwords are never written here.
        for binding in bindings:
            binding['bind'] = {'create_host_path':False}
        override.write_text(json.dumps({'services':{'pbxsense-agent':{'environment':updates,'volumes':bindings}}}, indent=2) + '\n', encoding='utf-8')
        os.chmod(override, 0o600)
    save_env(args.env_file, updates)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print('Path setup could not complete. Review paths/configuration manually; no PBX configuration was changed.', file=sys.stderr)
        sys.exit(1)
