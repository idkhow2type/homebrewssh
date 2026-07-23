import unittest
import subprocess
import shutil
import os
import socket
import tempfile
from main import Server

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.sshd_bin = shutil.which("sshd")
        self.keygen_bin = shutil.which("ssh-keygen")
        self.temp_dir = tempfile.mkdtemp()
        self.sshd_process = None
        self.port: int = 0

    def tearDown(self):
        if self.sshd_process:
            self.sshd_process.terminate()
            self.sshd_process.wait()
        if hasattr(self, 'log_file') and self.log_file:
            self.log_file.close()
        shutil.rmtree(self.temp_dir, True)

    def start_mock_sshd(self):
        if not self.sshd_bin or not self.keygen_bin:
            self.skipTest("sshd or ssh-keygen not found in PATH")

        # 1. Generate host keys
        host_key = os.path.join(self.temp_dir, "ssh_host_rsa_key")
        subprocess.run(
            [self.keygen_bin, "-t", "rsa", "-f", host_key, "-N", "", "-q"], check=True
        )

        # 2. Create config file
        config_path = os.path.join(self.temp_dir, "sshd_config")
        config_content = (
            "Port 0\n"
            "HostKey " + host_key + "\n"
            "PasswordAuthentication no\n"
            "PubkeyAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "PidFile " + os.path.join(self.temp_dir, "sshd.pid") + "\n"
        )
        with open(config_path, "w") as f:
            f.write(config_content)

        os.chmod(host_key, 0o600)

        # 3. Start sshd on a random port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("localhost", 0))
            self.port = s.getsockname()[1]

        self.log_file = open(os.path.join(self.temp_dir, "sshd.log"), "w")
        self.sshd_process = subprocess.Popen(
            [self.sshd_bin, "-ddd", "-p", str(self.port), "-f", config_path],
            stdout=subprocess.DEVNULL,
            stderr=self.log_file,
        )

        import time
        time.sleep(0.5)

    def test_full_handshake(self):
        self.start_mock_sshd()

        try:
            client = Server("localhost", self.port)
            client.connect()
            client = client.negotiate_algos()
            client.algos.kex(client)
            from messages.kex import NewKeys
            client.send(NewKeys.build())
            client.recv()
            self.assertIsNotNone(client.encryption_key_ctos)
            self.assertIsNotNone(client.session_id)
            client.disconnect()
        except Exception as e:
            log_content = ""
            log_path = os.path.join(self.temp_dir, "sshd.log")
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as log_file:
                        log_content = "\n\n--- Server Debug Logs ---\n" + log_file.read()
                except Exception as log_e:
                    log_content = f"\n\nCould not read server logs: {log_e}"
            self.fail(f"Handshake failed with temporary sshd: {e.__class__.__name__}: {e}{log_content}")
        self.tearDown()
