import tempfile
import shutil
import os
from nxc.modules.nfs_mount import NXCModule
from nxc.helpers.misc import CATEGORY


def test_module_metadata():
    """Test module has correct metadata attributes"""
    module = NXCModule()

    assert module.name == "nfs_mount"
    assert module.description == "Generate resilient NFS mount commands for discovered and manual shares"
    assert module.supported_protocols == ["nfs"]
    assert module.category == CATEGORY.ENUMERATION


def test_sanitize_share_name():
    """Test share path sanitization for filesystem compatibility"""
    module = NXCModule()

    # Test cases from spec
    assert module._sanitize_share_name("/") == "root"
    assert module._sanitize_share_name("/home") == "home"
    assert module._sanitize_share_name("/var/www/html") == "var_www_html"
    assert module._sanitize_share_name("/opt/shared") == "opt_shared"

    # Edge cases
    assert module._sanitize_share_name("/home/") == "home"
    assert module._sanitize_share_name("///multiple///slashes///") == "multiple_slashes"
    assert module._sanitize_share_name("/single") == "single"


def test_build_mount_point():
    """Test mount point path construction with various options"""
    module = NXCModule()

    # With hostname
    assert module._build_mount_point("/mnt", "server1", "/home", True) == "/mnt/server1/home"
    assert module._build_mount_point("/tmp/nfs", "target", "/var/log", True) == "/tmp/nfs/target/var_log"
    assert module._build_mount_point("/opt", "host", "/", True) == "/opt/host/root"

    # Without hostname
    assert module._build_mount_point("/mnt", "server1", "/home", False) == "/mnt/home"
    assert module._build_mount_point("/tmp", "target", "/var/log", False) == "/tmp/var_log"
    assert module._build_mount_point("/opt", "host", "/", False) == "/opt/root"

    # Different base directories
    assert module._build_mount_point("/custom/path", "srv", "/data", True) == "/custom/path/srv/data"


def test_parse_manual_shares():
    """Test parsing of manual shares parameter"""
    module = NXCModule()

    # Valid formats
    shares = module._parse_manual_shares("server1:/home,server2:/data")
    assert shares == [("server1", "/home"), ("server2", "/data")]

    # Single share
    shares = module._parse_manual_shares("host:/backup")
    assert shares == [("host", "/backup")]

    # With spaces
    shares = module._parse_manual_shares(" server1:/home , server2:/data ")
    assert shares == [("server1", "/home"), ("server2", "/data")]

    # Complex paths
    shares = module._parse_manual_shares("srv:/var/www/html,backup:/opt/shared")
    assert shares == [("srv", "/var/www/html"), ("backup", "/opt/shared")]

    # Empty string
    shares = module._parse_manual_shares("")
    assert shares == []

    # Invalid formats (should be skipped)
    shares = module._parse_manual_shares("invalid,server:/good,badformat")
    assert shares == [("server", "/good")]


def test_generate_mount_command():
    """Test generation of resilient mount commands"""
    module = NXCModule()

    # Basic command
    cmd = module._generate_mount_command("server1", "/home", "/mnt/server1/home", False)
    expected = "mount -t nfs -o soft,timeo=30,retry=2,intr server1:/home /mnt/server1/home"
    assert cmd == expected

    # With directory creation
    cmd = module._generate_mount_command("host", "/var/log", "/tmp/host/var_log", True)
    expected = "mkdir -p /tmp/host/var_log && mount -t nfs -o soft,timeo=30,retry=2,intr host:/var/log /tmp/host/var_log"
    assert cmd == expected

    # Root share
    cmd = module._generate_mount_command("backup", "/", "/mnt/backup/root", False)
    expected = "mount -t nfs -o soft,timeo=30,retry=2,intr backup:/ /mnt/backup/root"
    assert cmd == expected


def test_options_processing():
    """Test module option parsing and defaults"""
    module = NXCModule()

    # Mock context and module_options
    class MockContext:
        pass

    context = MockContext()

    # Test defaults
    module_options = {}
    module.options(context, module_options)
    assert module.mount_base == "/mnt"
    assert module.use_hostname is True
    assert module.create_dirs is False
    assert module.manual_shares == []

    # Test custom options
    module_options = {
        "MOUNT_BASE": "/tmp/nfs",
        "USE_HOSTNAME": "false",
        "CREATE_DIRS": "true",
        "SHARES": "server1:/home,server2:/data"
    }
    module.options(context, module_options)
    assert module.mount_base == "/tmp/nfs"
    assert module.use_hostname is False
    assert module.create_dirs is True
    assert module.manual_shares == [("server1", "/home"), ("server2", "/data")]


def test_discover_exports():
    """Test NFS export discovery using connection"""
    module = NXCModule()

    # Mock connection with mount attribute
    class MockMount:
        def export(self):
            # Simulate pyNfsClient export response with string representation
            class MockExportNode:
                def __repr__(self):
                    return "<ExportNode ex_dir=b'/home' ex_next=<ExportNode ex_dir=b'/var/log' ex_next=None>>"

            return MockExportNode()

    class MockConnection:
        def __init__(self):
            self.mount = MockMount()
            self.host = "test-server"

    connection = MockConnection()

    # Mock context for logging
    class MockLogger:
        def display(self, msg): pass
        def debug(self, msg): pass
        def fail(self, msg): pass

    class MockContext:
        def __init__(self):
            self.log = MockLogger()

    context = MockContext()

    exports = module._discover_exports(context, connection)
    assert exports == ["/home", "/var/log"]


def test_create_mount_directories():
    """Test mount directory creation functionality"""
    module = NXCModule()

    # Create temporary directory for testing
    temp_dir = tempfile.mkdtemp()

    try:
        # Mock context for logging
        class MockLogger:
            def __init__(self):
                self.messages = []

            def success(self, msg):
                self.messages.append(("success", msg))

            def fail(self, msg):
                self.messages.append(("fail", msg))

        class MockContext:
            def __init__(self):
                self.log = MockLogger()

        context = MockContext()

        # Test successful creation
        mount_points = [
            f"{temp_dir}/server1/home",
            f"{temp_dir}/server2/data"
        ]

        module._create_mount_directories(context, mount_points)

        # Verify directories were created
        assert os.path.exists(f"{temp_dir}/server1/home")
        assert os.path.exists(f"{temp_dir}/server2/data")

        # Verify success messages
        assert len(context.log.messages) == 2
        assert context.log.messages[0][0] == "success"
        assert "Created mount point" in context.log.messages[0][1]

    finally:
        # Clean up
        shutil.rmtree(temp_dir)


def test_on_login_integration():
    """Test complete on_login workflow"""
    module = NXCModule()

    # Set up options
    module.mount_base = "/mnt"
    module.use_hostname = True
    module.create_dirs = True
    module.manual_shares = [("manual-server", "/backup")]

    # Mock connection
    class MockMount:
        def export(self):
            class MockExportNode:
                def __init__(self, path):
                    self.ex_dir = path.encode()
                    self.ex_next = None

                def __repr__(self):
                    return f"<ExportNode ex_dir=b'{self.ex_dir.decode()}' ex_next={self.ex_next}>"

            return MockExportNode("/home")

    class MockConnection:
        def __init__(self):
            self.mount = MockMount()
            self.host = "test-server"
            self.hostname = "test-server"

    # Mock context
    class MockLogger:
        def __init__(self):
            self.messages = []

        def display(self, msg):
            self.messages.append(("display", msg))

        def success(self, msg):
            self.messages.append(("success", msg))

        def highlight(self, msg):
            self.messages.append(("highlight", msg))

        def fail(self, msg):
            self.messages.append(("fail", msg))

        def debug(self, msg):
            self.messages.append(("debug", msg))

    class MockContext:
        def __init__(self):
            self.log = MockLogger()

    context = MockContext()
    connection = MockConnection()

    # Mock the directory creation to avoid filesystem operations
    original_create = module._create_mount_directories
    module._create_mount_directories = lambda ctx, paths: None

    try:
        module.on_login(context, connection)

        # Verify discovery was attempted
        display_messages = [msg[1] for msg in context.log.messages if msg[0] == "display"]
        assert any("Discovering NFS exports" in msg for msg in display_messages)

        # Verify mount commands were generated
        highlight_messages = [msg[1] for msg in context.log.messages if msg[0] == "highlight"]
        mount_commands = [msg for msg in highlight_messages if "mount -t nfs" in msg]
        assert len(mount_commands) >= 2  # At least discovered + manual

    finally:
        # Restore original method
        module._create_mount_directories = original_create


def test_error_handling():
    """Test error handling for various failure scenarios"""
    module = NXCModule()

    # Set up basic options
    module.mount_base = "/mnt"
    module.use_hostname = True
    module.create_dirs = False
    module.manual_shares = [("invalid", "badformat"), ("good", "/path")]

    # Mock connection that fails export discovery
    class MockConnection:
        def __init__(self):
            self.mount = None  # This will cause AttributeError
            self.host = "failing-server"
            self.hostname = "failing-server"

    # Mock context
    class MockLogger:
        def __init__(self):
            self.messages = []

        def display(self, msg):
            self.messages.append(("display", msg))

        def success(self, msg):
            self.messages.append(("success", msg))

        def highlight(self, msg):
            self.messages.append(("highlight", msg))

        def fail(self, msg):
            self.messages.append(("fail", msg))

        def debug(self, msg):
            self.messages.append(("debug", msg))

    class MockContext:
        def __init__(self):
            self.log = MockLogger()

    context = MockContext()
    connection = MockConnection()

    # Should handle discovery failure gracefully
    module.on_login(context, connection)

    # Verify discovery failure was logged
    fail_messages = [msg[1] for msg in context.log.messages if msg[0] == "fail"]
    assert any("Failed to discover exports" in msg for msg in fail_messages)

    # Verify it continued with manual shares
    debug_messages = [msg[1] for msg in context.log.messages if msg[0] == "debug"]
    assert any("Continuing with manual shares only" in msg for msg in debug_messages)

    # Should still generate command for valid manual share
    highlight_messages = [msg[1] for msg in context.log.messages if msg[0] == "highlight"]
    mount_commands = [msg for msg in highlight_messages if "good:/path" in msg]
    assert len(mount_commands) == 1


def test_write_commands_to_file():
    """Test writing mount commands to an executable script file"""
    module = NXCModule()

    temp_dir = tempfile.mkdtemp()
    try:
        class MockLogger:
            def __init__(self):
                self.messages = []

            def success(self, msg):
                self.messages.append(("success", msg))

            def fail(self, msg):
                self.messages.append(("fail", msg))

        class MockContext:
            def __init__(self):
                self.log = MockLogger()

        context = MockContext()
        outfile = os.path.join(temp_dir, "subdir", "out.sh")
        commands = [
            "mount -t nfs -o soft,timeo=30,retry=2,intr srv:/home /mnt/srv/home",
            "mount -t nfs -o soft,timeo=30,retry=2,intr srv:/data /mnt/srv/data",
        ]

        module._write_commands_to_file(context, outfile, "srv", commands)

        assert os.path.exists(outfile)
        with open(outfile) as f:
            content = f.read()
        assert content.startswith("#!/bin/bash\n")
        assert "# NFS mount commands for srv" in content
        for cmd in commands:
            assert cmd in content

        # Executable bit set for user
        assert os.stat(outfile).st_mode & 0o100

        success_msgs = [m[1] for m in context.log.messages if m[0] == "success"]
        assert any(outfile in msg for msg in success_msgs)
    finally:
        shutil.rmtree(temp_dir)
