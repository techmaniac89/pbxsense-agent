from pathlib import Path
import os
import shutil
import subprocess
import unittest


class InstallerSelectionTest(unittest.TestCase):
    def run_selection(self, answers, asterisk=False, freeswitch=False, interactive=True):
        bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
        if not bash or not Path(bash).exists():
            self.skipTest('Bash unavailable')
        source = Path('scripts/install_common.sh').read_text()
        normalizer = source[source.index('normalize_pbx_type() {'):source.index('prompt_value() {')]
        selection = source[source.index('choose_manual_pbx_type() {'):source.index('configure_asterisk_env() {')]
        script = ('unset PBXSENSE_PBX_TYPE\nENV_CREATED=1\n'
                  f'is_interactive() {{ return {0 if interactive else 1}; }}\n'
                  f'detect_asterisk() {{ return {0 if asterisk else 1}; }}\n'
                  f'detect_freeswitch() {{ return {0 if freeswitch else 1}; }}\n'
                  + normalizer + selection + '\nchoose_pbx_type\n')
        result = subprocess.run([bash, '-c', script], input=answers.encode(), capture_output=True, timeout=10)
        result.stdout = result.stdout.decode()
        result.stderr = result.stderr.decode()
        return result

    def test_all_manual_choices_and_order(self):
        for i, expected in enumerate(('asterisk', 'freeswitch', 'yeastar', 'grandstream', 'cucm'), 1):
            result = self.run_selection(f'2\n{i}\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)
            self.assertNotIn('mock', result.stderr.lower())

    def test_automatic_detection_and_confirmation(self):
        for asterisk, freeswitch, expected in ((True, False, 'asterisk'), (False, True, 'freeswitch')):
            result = self.run_selection('1\ny\n', asterisk, freeswitch)
            self.assertEqual(result.stdout.strip(), expected)
            self.assertIn('connection is not yet verified', result.stderr)

    def test_ambiguous_or_absent_detection_requires_manual_selection(self):
        for found in (False, True):
            result = self.run_selection('1\n4\n', found, found)
            self.assertEqual(result.stdout.strip(), 'grandstream')
            self.assertIn('No single local PBX', result.stderr)

    def test_reject_detected_product_and_reject_mock_menu_input(self):
        result = self.run_selection('1\nn\nmock\n3\n', True, False)
        self.assertEqual(result.stdout.strip(), 'yeastar')
        self.assertIn('Choose one of the five', result.stderr)

    def test_unattended_without_evidence_never_assumes_asterisk(self):
        result = self.run_selection('', interactive=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
