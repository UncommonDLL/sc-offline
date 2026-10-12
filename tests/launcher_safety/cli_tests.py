"""Run the built launcher against disposable files; never invoke its mutation helper."""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

EXE = pathlib.Path(sys.argv.pop(1)).resolve()

class LauncherCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sco-cli-test-")
        self.root = pathlib.Path(self.temp.name)
        self.exe = self.root / "sc-offline.exe"
        shutil.copy2(EXE, self.exe)
        self.bin = self.root / "LIVE" / "Bin64"
        self.bin.mkdir(parents=True)
        (self.bin / "StarCitizen.exe").write_bytes(b"disposable; never executed")
        (self.root / "dinput8.dll").write_bytes(b"sc-offline v test; never loaded")

    def tearDown(self):
        self.temp.cleanup()

    def run_launcher(self, config, command="play", dry=True):
        (self.root / "sc-offline.ini").write_text("check_updates = off\n" + config, encoding="utf-8")
        args = [str(self.exe), command, "--game", str(self.bin)]
        if dry:
            args.append("--dry-run")
        return subprocess.run(args, capture_output=True, text=True, timeout=20)

    def test_isolation_off_rejected_for_play_and_install(self):
        for command in ("play", "install"):
            r = self.run_launcher("block_network = off\n", command)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("mandatory", r.stdout)
            self.assertFalse((self.bin / "dinput8.dll").exists())

    def test_default_multiplayer_off_accepts_dry_run(self):
        r = self.run_launcher("")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("require verified isolation", r.stdout)

    def test_multiplayer_requires_peers_and_ports(self):
        for config in ("multiplayer = on\n", "multiplayer = on\nmultiplayer_peers = 192.168.1.2\nmultiplayer_ports = 80\n", "multiplayer_allow = 100.64.0.0/10\n", "block_network = invalid\n"):
            r = self.run_launcher(config)
            self.assertNotEqual(r.returncode, 0, r.stdout)

    def test_explicit_multiplayer_dry_run(self):
        r = self.run_launcher("multiplayer = on\nmultiplayer_peers = 192.168.1.2\nmultiplayer_ports = 64090\n")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_unmanaged_state_cannot_report_restoration(self):
        r = self.run_launcher("", "status", False)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Safe to go online", r.stdout)
        self.assertIn("State unknown", r.stdout)

if __name__ == "__main__":
    unittest.main()
