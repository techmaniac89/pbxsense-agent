import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('installer_paths', Path('scripts/installer_paths.py'))
paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths)


class InstallerPathsTest(unittest.TestCase):
    def test_running_asterisk_directories_override_pending_config(self):
        commands = {
            ('asterisk','-rx','core show settings'): 'Log directory: /custom/log\nSpool directory: /custom/spool\nConfiguration directory: /custom/conf',
            ('asterisk','-rx','cdr show status'): 'Logging: Enabled\nRegistered Backends: csv',
        }
        present = {'/custom/log/cdr-csv/Master.csv', '/custom/spool/voicemail', '/custom/spool/monitor'}
        d = paths.Discovery('asterisk', run=lambda args:commands.get(tuple(args), ''), exists=lambda p:p in present,
                            read=lambda p:'[directories]\nastlogdir => /pending/log')
        found = d.discover()
        self.assertEqual(found[0][0]['path'], '/custom/log/cdr-csv/Master.csv')
        self.assertEqual(found[1][0]['path'], '/custom/spool/voicemail')
        self.assertEqual(d.notes, [])

    def test_asterisk_config_fallback_and_logging_disabled(self):
        d = paths.Discovery('asterisk', run=lambda args:'Logging: Disabled' if args[-1]=='cdr show status' else '',
                            exists=lambda p:p=='/alt/cdr-csv/Master.csv',
                            read=lambda p:'[directories]\nastlogdir => /alt\n')
        self.assertEqual(d.discover()[0][0]['path'], '/alt/cdr-csv/Master.csv')
        self.assertIn('disabled', d.notes[0])

    def test_freeswitch_runtime_paths_expansion_and_missing_module(self):
        values = {'conf_dir':'/fs/conf','log_dir':'/fs/log','base_dir':'/fs','storage_dir':'/fs/storage'}
        def run(args):
            if args[-1].startswith('global_getvar '):
                return values.get(args[-1].split()[-1], '')
            return 'false' if args[-1]=='module_exists mod_json_cdr' else ''
        config = '<configuration><settings><param name="log-dir" value="$${log_dir}"/></settings></configuration>'
        present = {'/fs/log/json_cdr','/fs/log','/fs/storage/voicemail','/fs/storage/recordings'}
        d = paths.Discovery('freeswitch', run=run, exists=lambda p:p in present,
                            read=lambda p:config if p.endswith('json_cdr.conf.xml') else '')
        found = d.discover()
        self.assertEqual(found[0][0]['path'], '/fs/log/json_cdr')
        self.assertEqual(found[1][0]['path'], '/fs/storage/voicemail')
        self.assertIn('not loaded', d.notes[0])

    def test_freeswitch_static_vars_without_cli_and_disk_disabled(self):
        def read(path):
            if path.endswith('vars.xml'):
                return '<include><X-PRE-PROCESS cmd="set" data="storage_dir=/custom/storage"/></include>'
            return '<configuration><settings><!-- log-dir is disabled --></settings></configuration>'
        d = paths.Discovery('freeswitch', run=lambda args:'', exists=lambda p:p=='/custom/storage/voicemail', read=read)
        self.assertEqual(d.discover()[1][0]['path'], '/custom/storage/voicemail')
        self.assertIn('not configured', d.notes[0])

    def test_no_existing_paths_means_no_invented_default(self):
        for pbx in paths.KEYS:
            d = paths.Discovery(pbx, run=lambda args:'', exists=lambda p:False, read=lambda p:'')
            self.assertEqual(d.discover(), [[],[],[]])
        with patch('sys.stdout', io.StringIO()):
            self.assertEqual(paths.select_path('CDR', [], '', interactive=False), '')

    def test_selection_preserves_existing_and_has_skip_and_manual(self):
        candidates = [{'path':'/found','origin':'config'}]
        with patch('sys.stdout', io.StringIO()):
            self.assertEqual(paths.select_path('CDR', candidates, '/existing', interactive=False), '/existing')
            self.assertEqual(paths.select_path('CDR', candidates, '/existing', interactive=True, ask=lambda _: 's'), '')
            answers = iter(('m','/manual'))
            self.assertEqual(paths.select_path('CDR', candidates, '', interactive=True, ask=lambda _:next(answers)), '/manual')
            with self.assertRaises(ValueError):
                paths.select_path('CDR', candidates, '', interactive=True, ask=lambda _:'99')

    def test_nested_docker_mount_translation_not_container_paths(self):
        d = paths.Discovery('freeswitch', container='pbx', mounts=[
            {'Destination':'/var/lib','Source':'/broad'},
            {'Destination':'/var/lib/freeswitch','Source':'/volume/data'}])
        self.assertEqual(d.host_path('/var/lib/freeswitch/storage/voicemail'), '/volume/data/storage/voicemail')
        self.assertEqual(d.host_path('/var/library'), '')

    def test_save_env_preserves_secrets_and_removes_duplicate_path_settings(self):
        with TemporaryDirectory() as directory:
            env = Path(directory)/'.env'
            env.write_text('SECRET=keep\nPATH_KEY=/old\nPATH_KEY=/duplicate\n')
            paths.save_env(env, {'PATH_KEY':'/new','OTHER':''})
            self.assertEqual(env.read_text(), 'SECRET=keep\nPATH_KEY=/new\nOTHER=\n')

    def test_probe_missing_empty_inaccessible_and_valid_cdr(self):
        self.assertEqual(paths.probe('', 'cdr', 'asterisk')['state'], 'not configured')
        self.assertEqual(paths.probe('/missing/pbxsense/test', 'cdr', 'asterisk')['state'], 'missing')
        with TemporaryDirectory() as directory:
            file = Path(directory)/'Master.csv'
            file.write_text('')
            self.assertEqual(paths.probe(str(file), 'cdr', 'asterisk'), {'state':'readable','records':0})
            with patch.object(Path, 'open', side_effect=PermissionError):
                self.assertEqual(paths.probe(str(file), 'cdr', 'asterisk')['state'], 'permission denied')

    def test_cdr_evidence_changes_only_for_new_parseable_records(self):
        with TemporaryDirectory() as directory:
            file = Path(directory)/'Master.csv'
            row = ['', 'private-caller', 'private-destination', '', '', '', '', '', '',
                   '2026-10-14 12:00:00', '', '', '30', '', 'ANSWERED']
            file.write_text(','.join(row) + '\n')
            first = paths.probe(str(file), 'cdr', 'asterisk')
            self.assertEqual(first['records'], 1)
            self.assertNotIn('private-caller', json.dumps(first))
            file.write_text(','.join(row) + '\nmalformed\n')
            self.assertEqual(paths.probe(str(file), 'cdr', 'asterisk')['evidence'], first['evidence'])
            row[9] = '2026-10-14 12:01:00'
            file.write_text(','.join(row) + '\n')
            self.assertNotEqual(paths.probe(str(file), 'cdr', 'asterisk')['evidence'], first['evidence'])

    def test_child_uses_runtime_user_and_stdin_not_secret_arguments(self):
        with patch.object(paths.shutil, 'which', return_value='/usr/sbin/runuser'), \
                patch.object(paths, 'command', return_value='{"live":"ready"}') as run:
            self.assertEqual(paths.child({'PASSWORD':'secret'}, 'pbxsense'), {'live':'ready'})
        args = run.call_args.args[0]
        self.assertEqual(args[:4], ['runuser','-u','pbxsense','--'])
        self.assertNotIn('secret', ' '.join(args))
        self.assertEqual(json.loads(run.call_args.kwargs['input_text'])['PASSWORD'], 'secret')

    def test_missing_runuser_is_not_a_root_success(self):
        with patch.object(paths.shutil, 'which', return_value=None):
            self.assertEqual(paths.child({}, 'pbxsense'), {})

    def test_standalone_child_reuses_actual_cdr_reader(self):
        with TemporaryDirectory() as directory:
            file = Path(directory)/'Master.csv'
            file.write_text(','.join(['','caller','destination','','','','','','','2026-10-14 12:00:00','','','30','','ANSWERED']) + '\n')
            result = paths.child({'PBXSENSE_PBX_TYPE':'asterisk', 'ASTERISK_CDR_CSV_PATH':str(file)}, paths_only=True)
        self.assertEqual(result['paths'][0]['records'], 1)
        self.assertNotIn('caller', json.dumps(result))

    def test_service_sandbox_paths_are_not_reported_ready(self):
        output = io.StringIO()
        with patch.object(paths, 'child', return_value={'live':'ready','paths':[{'state':'readable','records':2}]*3}), \
                patch('sys.stdout', output):
            paths.report({'PBXSENSE_PBX_TYPE':'asterisk','ASTERISK_CDR_CSV_PATH':'/home/pbx/Master.csv'}, user='pbxsense')
        self.assertIn('sandbox', output.getvalue())
        self.assertNotIn('parsed completed records found', output.getvalue())

    def test_docker_selection_writes_readonly_mounts_and_container_paths(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / '.env'
            env.write_text('PBXSENSE_PBX_TYPE=asterisk\nPASSWORD=keep\n')
            cdr = root / 'Master.csv'
            cdr.write_text('')
            with patch('sys.argv', ['installer_paths.py','select','--env-file',str(env),'--mode','docker']), \
                    patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value=''), \
                    patch.object(paths.Discovery, 'discover', return_value=[[],[],[]]), \
                    patch.object(paths, 'select_path', side_effect=[str(cdr),'','']), \
                    patch('sys.stdout', io.StringIO()):
                paths.main()
            data = json.loads((root / 'docker/docker-compose.detected.yml').read_text())['services']['pbxsense-agent']
            self.assertEqual(data['environment']['ASTERISK_CDR_CSV_PATH'], '/var/lib/pbxsense-agent/pbx-files/cdr/Master.csv')
            self.assertEqual(data['volumes'][0]['source'], str(cdr.resolve()))
            self.assertTrue(data['volumes'][0]['read_only'])
            self.assertFalse(data['volumes'][0]['bind']['create_host_path'])
            self.assertEqual(paths.read_env(env)['PASSWORD'], 'keep')

    def test_missing_docker_source_cannot_create_placeholder_directory(self):
        with TemporaryDirectory() as directory:
            env = Path(directory)/'.env'
            env.write_text('PBXSENSE_PBX_TYPE=asterisk\n')
            missing = str(Path(directory)/'missing')
            with patch('sys.argv', ['installer_paths.py','select','--env-file',str(env),'--mode','docker']), \
                    patch('sys.stdin.isatty', return_value=True), patch('builtins.input', return_value=''), \
                    patch.object(paths.Discovery, 'discover', return_value=[[],[],[]]), \
                    patch.object(paths, 'select_path', return_value=missing), \
                    patch('sys.stdout', io.StringIO()):
                with self.assertRaises(ValueError):
                    paths.main()
            self.assertFalse(Path(missing).exists())
            self.assertEqual(env.read_text(), 'PBXSENSE_PBX_TYPE=asterisk\n')

    def test_noninteractive_docker_keeps_existing_configuration(self):
        with TemporaryDirectory() as directory:
            env = Path(directory)/'.env'
            content = 'PBXSENSE_PBX_TYPE=freeswitch\nFREESWITCH_CDR_JSON_PATH=/custom/container/path\n'
            env.write_text(content)
            with patch('sys.argv', ['installer_paths.py','select','--env-file',str(env),'--mode','docker']), \
                    patch('sys.stdin.isatty', return_value=False), patch('sys.stdout', io.StringIO()):
                paths.main()
            self.assertEqual(env.read_text(), content)

    def test_generated_mounts_override_prepared_root_and_helper_is_in_image(self):
        source = Path('scripts/setup_docker.sh').read_text()
        self.assertIn('-f docker/docker-compose.detected.yml', source)
        self.assertIn('if [ ! -f "$PROJECT_DIR/docker/docker-compose.detected.yml" ]', source)
        self.assertIn('COPY scripts/installer_paths.py ./scripts/installer_paths.py', Path('docker/Dockerfile').read_text())
