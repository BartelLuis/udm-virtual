"""Exercise the PowerShell entry point with simulated WSL calls, never a build."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'build.ps1'
POWERSHELL = shutil.which('powershell.exe') if os.name == 'nt' else None


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


@unittest.skipUnless(POWERSHELL, 'Requires Windows PowerShell; WSL itself is mocked')
class BuildWrapperTests(unittest.TestCase):
    def invoke(self, arguments, *, conversion_exit=0, build_exit=0):
        source = r'''
$ErrorActionPreference = 'Stop'
$global:udmWrapperCalls = [System.Collections.Generic.List[object]]::new()
function global:wsl {
    $items = @($args | ForEach-Object { [string]$_ })
    $global:udmWrapperCalls.Add($items)
    $global:LASTEXITCODE = 0
    if ($items -contains 'wslpath') {
        $global:LASTEXITCODE = CONVERSION_EXIT
        if ($global:LASTEXITCODE -eq 0) {
            '/mock/' + $items[-1].Substring(3)
        }
    }
    else { $global:LASTEXITCODE = BUILD_EXIT }
}
$errorMessage = $null
try { & SCRIPT ARGUMENTS }
catch { $errorMessage = $_.Exception.Message }
@{calls = @($global:udmWrapperCalls.ToArray()); error = $errorMessage} | ConvertTo-Json -Depth 8 -Compress
'''.replace('CONVERSION_EXIT', str(conversion_exit)).replace('BUILD_EXIT', str(build_exit))
        source = source.replace('SCRIPT', quote(SCRIPT)).replace('ARGUMENTS', arguments)
        encoded = base64.b64encode(source.encode('utf-16-le')).decode('ascii')
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive',
                                 '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_absolute_windows_paths_and_spaces_are_converted(self):
        result = self.invoke(r"-Profile virtual -Output 'D:\VM Builds\new' -Firmware 'C:\Firmware Files\beast.bin'")
        self.assertIsNone(result['error'])
        command = result['calls'][-1]
        self.assertEqual(command[command.index('--output') + 1], '/mock/VM Builds/new')
        self.assertEqual(command[command.index('--firmware') + 1], '/mock/Firmware Files/beast.bin')
        self.assertEqual(command[command.index('--profile') + 1], 'virtual')
        self.assertEqual(len(result['calls']), 4)

    def test_relative_windows_paths_use_project_directory(self):
        result = self.invoke(r"-Output 'builds\new' -Firmware 'input\beast.bin' -StateSizeGiB 16")
        self.assertIsNone(result['error'])
        command = result['calls'][-1]
        self.assertEqual(command[command.index('--cd') + 1], '/mock/' + SCRIPT.parent.as_posix()[3:])
        self.assertEqual(command[command.index('--output') + 1], 'builds/new')
        self.assertEqual(command[command.index('--firmware') + 1], 'input/beast.bin')
        self.assertEqual(command[command.index('--state-size-gib') + 1], '16')
        self.assertEqual(len(result['calls']), 2)

    def test_linux_absolute_paths_pass_through_and_firmware_is_optional(self):
        result = self.invoke("-Output '/home/luis/udm-build' -Distro Debian")
        self.assertIsNone(result['error'])
        command = result['calls'][-1]
        self.assertEqual(command[command.index('--output') + 1], '/home/luis/udm-build')
        self.assertNotIn('--firmware', command)
        self.assertEqual(len(result['calls']), 2)

    def test_drive_relative_or_empty_output_fails_before_build(self):
        for output in ('C:build', 'C:', ''):
            with self.subTest(output=output):
                result = self.invoke('-Output ' + quote(output))
                self.assertIsNotNone(result['error'])
                self.assertFalse(any('--cd' in call for call in result['calls']))

    def test_conversion_failure_prevents_build(self):
        result = self.invoke('-Profile virtual', conversion_exit=73)
        self.assertIn('WSL path conversion failed', result['error'])
        self.assertEqual(len(result['calls']), 1)

    def test_failed_build_is_reported(self):
        result = self.invoke('-Profile virtual', build_exit=17)
        self.assertEqual(result['error'], 'Build failed with exit code 17')


if __name__ == '__main__':
    unittest.main()
