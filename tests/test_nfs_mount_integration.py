import os
import tempfile

from nxc.modules.nfs_mount import NXCModule


class TestNFSMountIntegration:
    """Integration tests for NFS mount module"""

    def test_real_nfs_protocol_integration(self):
        """Test module integration with actual NFS protocol patterns"""
        module = NXCModule()

        # Simulate real NetExec NFS connection structure
        class RealNFSConnection:
            def __init__(self):
                self.host = "192.168.1.100"
                self.hostname = "nfs-server"
                self.mount = self._create_mount_service()

            def _create_mount_service(self):
                """Simulate pyNfsClient Mount service"""
                class Mount:
                    def export(self):
                        # Simulate real export node structure
                        class ExportNode:
                            def __init__(self, path, next_node=None):
                                self.ex_dir = path.encode() if isinstance(path, str) else path
                                self.ex_next = next_node

                            def __str__(self):
                                # Simulate pyNfsClient export node string representation
                                next_str = str(self.ex_next) if self.ex_next else ""
                                return f"<ExportNode ex_dir={self.ex_dir!r} ex_next={next_str}>"

                            def __repr__(self):
                                return self.__str__()

                        # Chain of exports like real NFS
                        node3 = ExportNode("/opt/shared")
                        node2 = ExportNode("/var/log", node3)
                        return ExportNode("/home", node2)

                return Mount()

        # Simulate NetExec context
        class RealContext:
            def __init__(self):
                self.log = self._create_logger()

            def _create_logger(self):
                class Logger:
                    def __init__(self):
                        self.messages = []

                    def display(self, msg):
                        self.messages.append(f"[*] {msg}")
                        print(f"[*] {msg}")

                    def success(self, msg):
                        self.messages.append(f"[+] {msg}")
                        print(f"[+] {msg}")

                    def highlight(self, msg):
                        self.messages.append(f"[!] {msg}")
                        print(f"[!] {msg}")

                    def fail(self, msg):
                        self.messages.append(f"[-] {msg}")
                        print(f"[-] {msg}")

                    def debug(self, msg):
                        self.messages.append(f"[DEBUG] {msg}")

                return Logger()

        # Configure module with realistic options
        context = RealContext()
        connection = RealNFSConnection()

        fd, outfile = tempfile.mkstemp(suffix=".sh")
        os.close(fd)

        module_options = {
            "MOUNT_BASE": "/tmp/test-mounts",
            "USE_HOSTNAME": "true",
            "CREATE_DIRS": "false",
            "SHARES": "backup-server:/backups,data-server:/datasets",
            "OUTFILE": outfile,
        }

        module.options(context, module_options)

        # Execute full module workflow
        module.on_login(context, connection)

        # Verify expected behavior
        messages = context.log.messages

        # Should discover 3 exports
        assert any("Found 3 exports" in msg for msg in messages)
        assert any("/home" in msg and "/var/log" in msg and "/opt/shared" in msg for msg in messages)

        # Should process 2 manual shares
        assert any("Processing 2 manual shares" in msg for msg in messages)

        # Should generate 5 total mount commands (3 discovered + 2 manual)
        mount_commands = [msg for msg in messages if "mount -t nfs" in msg]
        assert len(mount_commands) == 5

        # Verify resilient options in commands
        for cmd in mount_commands:
            assert "soft,timeo=30,retry=2,intr" in cmd

        # Verify mount points follow pattern
        mount_points = [
            "/tmp/test-mounts/nfs-server/home",
            "/tmp/test-mounts/nfs-server/var_log",
            "/tmp/test-mounts/nfs-server/opt_shared",
            "/tmp/test-mounts/backup-server/backups",
            "/tmp/test-mounts/data-server/datasets"
        ]

        for mount_point in mount_points:
            assert any(mount_point in cmd for cmd in mount_commands)

    def test_module_with_netexec_patterns(self):
        """Test module follows NetExec module conventions"""
        module = NXCModule()

        # Verify module metadata matches NetExec patterns
        assert hasattr(module, "name")
        assert hasattr(module, "description")
        assert hasattr(module, "supported_protocols")
        assert hasattr(module, "category")

        # Verify required methods exist
        assert hasattr(module, "options")
        assert hasattr(module, "on_login")
        assert callable(module.options)
        assert callable(module.on_login)

        # Verify protocol support
        assert "nfs" in module.supported_protocols

        # Verify category is appropriate
        from nxc.helpers.misc import CATEGORY
        assert module.category == CATEGORY.ENUMERATION
