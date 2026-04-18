import os
import re
import shlex
import stat

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    # Generates resilient NFS mount commands for discovered and manual shares
    # Module by @bandrel

    name = "nfs_mount"
    description = "Generate resilient NFS mount commands for discovered and manual shares"
    supported_protocols = ["nfs"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.mount_base = "/mnt"
        self.use_hostname = True
        self.create_dirs = False
        self.manual_shares = []
        self.outfile = None

    def options(self, context, module_options):
        """
        MOUNT_BASE     Base directory for mount points (default: /mnt)
        USE_HOSTNAME   Include hostname in mount path (default: true)
        CREATE_DIRS    Prepend `mkdir -p <mount_point>` to each emitted mount command (default: false)
        SHARES         Manually specified shares "server1:/path1,server2:/path2"
        OUTFILE        Write commands as executable script (default: ~/.nxc/modules/nfs_mount/<host>.sh)
        """
        self.context = context
        self.module_options = module_options

        # Process options with defaults
        self.mount_base = module_options.get("MOUNT_BASE", "/mnt")

        # Parse boolean options
        self.use_hostname = module_options.get("USE_HOSTNAME", "true").lower() == "true"
        self.create_dirs = module_options.get("CREATE_DIRS", "false").lower() == "true"

        # Parse manual shares
        shares_string = module_options.get("SHARES", "")
        self.manual_shares = self._parse_manual_shares(shares_string)

        # Output file path (resolved per-target in on_login if not set)
        self.outfile = module_options.get("OUTFILE")

    def on_login(self, context, connection):
        """
        Main module execution on successful NFS connection.

        Args:
            context: NXC context for logging and options
            connection: Established NFS connection
        """
        # Discover NFS exports
        discovered_exports = self._discover_exports(context, connection)

        # Process manual shares
        if self.manual_shares:
            context.log.display(f"Processing {len(self.manual_shares)} manual shares")
            for server, path in self.manual_shares:
                context.log.debug(f"Manual share: {server}:{path}")

        # Combine all shares for processing
        hostname = getattr(connection, "hostname", connection.host)
        all_shares = [(connection.host, export_path, hostname) for export_path in discovered_exports]
        # Manual shares use the server as hostname for the mount path
        all_shares.extend((server, path, server) for server, path in self.manual_shares)

        if not all_shares:
            context.log.display("No NFS shares found to process")
            return

        # Generate mount commands
        commands = []

        for server, share_path, hostname_for_path in all_shares:
            mount_point = self._build_mount_point(
                self.mount_base, hostname_for_path, share_path, self.use_hostname
            )
            command = self._generate_mount_command(
                server, share_path, mount_point, self.create_dirs
            )
            commands.append(command)

        # Output mount commands
        context.log.display("\n[*] NFS Mount Commands:")
        for command in commands:
            context.log.highlight(command)

        context.log.success(f"Generated {len(commands)} mount commands ready for execution")

        # Write commands to output file
        outfile_path = self.outfile or os.path.join(NXC_PATH, "modules", "nfs_mount", f"{hostname}.sh")
        self._write_commands_to_file(context, outfile_path, hostname, commands)

    def _sanitize_share_name(self, share_path):
        """
        Sanitize share path for use as filesystem directory name.

        Args:
            share_path (str): NFS export path (e.g., "/var/www/html")

        Returns:
            str: Sanitized name safe for filesystem use (e.g., "var_www_html")
        """
        if share_path == "/":
            return "root"

        # Remove leading/trailing slashes and replace internal slashes with underscores
        sanitized = share_path.strip("/").replace("/", "_")

        # Handle multiple consecutive slashes
        while "__" in sanitized:
            sanitized = sanitized.replace("__", "_")

        return sanitized

    def _build_mount_point(self, base_dir, hostname, share_path, use_hostname):
        """
        Build mount point path based on configuration.

        Args:
            base_dir (str): Base directory for mounts (e.g., "/mnt")
            hostname (str): Target hostname
            share_path (str): NFS export path (e.g., "/home")
            use_hostname (bool): Include hostname in path

        Returns:
            str: Full mount point path
        """
        share_name = self._sanitize_share_name(share_path)

        if use_hostname:
            return f"{base_dir}/{hostname}/{share_name}"
        else:
            return f"{base_dir}/{share_name}"

    def _discover_exports(self, context, connection):
        """
        Discover NFS exports using established connection.

        Args:
            context: NXC context for logging
            connection: Established NFS connection

        Returns:
            list: List of export paths discovered
        """
        exports = []

        try:
            context.log.display("Discovering NFS exports")

            # Get exports using connection's mount service
            export_nodes = connection.mount.export()

            # Extract export paths from nodes
            output_export = str(export_nodes)
            reg = re.compile(r"ex_dir=b'([^']*)'")
            exports = list(reg.findall(output_export))

            if exports:
                context.log.display(f"Found {len(exports)} exports: {', '.join(exports)}")
            else:
                context.log.display("No exports discovered")

        except Exception as e:
            context.log.fail(f"Failed to discover exports: {e}")
            context.log.debug("Continuing with manual shares only")

        return exports

    def _parse_manual_shares(self, shares_string):
        """
        Parse manual shares parameter into server/path tuples.

        Args:
            shares_string (str): Comma-separated shares "server1:/path1,server2:/path2"

        Returns:
            list: List of (server, path) tuples for valid shares
        """
        if not shares_string or not shares_string.strip():
            return []

        shares = []
        for share in shares_string.split(","):
            share = share.strip()

            # Validate format: must contain : and /
            if ":" in share and "/" in share:
                try:
                    server, path = share.split(":", 1)
                    server = server.strip()
                    path = path.strip()

                    if server and path:
                        shares.append((server, path))
                    else:
                        # Log invalid format but don't fail module
                        if hasattr(self, "context") and self.context:
                            self.context.log.fail(f"Invalid share format: '{share}' (empty server or path)")
                except ValueError:
                    # Log invalid format but don't fail module
                    if hasattr(self, "context") and self.context:
                        self.context.log.fail(f"Invalid share format: '{share}' (expected server:/path)")
            else:
                # Log invalid format but don't fail module
                if hasattr(self, "context") and self.context:
                    self.context.log.fail(f"Invalid share format: '{share}' (expected server:/path)")

        return shares

    def _generate_mount_command(self, server, share_path, mount_point, create_dirs):
        """
        Generate resilient NFS mount command.

        Args:
            server (str): NFS server hostname/IP
            share_path (str): Export path on server
            mount_point (str): Local mount point path
            create_dirs (bool): Include mkdir command

        Returns:
            str: Complete mount command ready for execution
        """
        # Validate and sanitize inputs to prevent command injection
        server = shlex.quote(str(server).strip())
        share_path = shlex.quote(str(share_path).strip())
        mount_point = shlex.quote(str(mount_point).strip())

        # Resilient mount options for stability when systems go offline
        mount_cmd = f"mount -t nfs -o soft,timeo=30,retry=2,intr {server}:{share_path} {mount_point}"

        if create_dirs:
            return f"mkdir -p {mount_point} && {mount_cmd}"
        else:
            return mount_cmd

    def _write_commands_to_file(self, context, outfile_path, hostname, commands):
        """
        Write mount commands to an executable shell script.

        Args:
            context: NXC context for logging
            outfile_path (str): Destination path for the script
            hostname (str): Target hostname (used in header)
            commands (list): Mount command strings to write
        """
        try:
            os.makedirs(os.path.dirname(outfile_path), exist_ok=True)
            with open(outfile_path, "w") as f:
                f.write("#!/bin/bash\n")
                f.write(f"# NFS mount commands for {hostname}\n")
                f.write("# Generated by NetExec nfs_mount module\n\n")
                for command in commands:
                    f.write(f"{command}\n")
            os.chmod(outfile_path, os.stat(outfile_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            context.log.success(f"Wrote mount script to {outfile_path}")
        except OSError as e:
            context.log.fail(f"Failed to write output file {outfile_path}: {e}")
