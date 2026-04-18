import errno
import json
import re
import time
from os import makedirs
from os.path import abspath, join, splitext

from pyNfsClient import NFSv3
from pyNfsClient.const import NFS_PROGRAM, NFS_V3, NFSSTAT3

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


def human_size(nbytes):
    """Takes a number of bytes as input and converts it to a human-readable size representation with appropriate units (e.g., KB, MB, GB, TB)"""
    suffixes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]

    for i in range(len(suffixes)):
        if nbytes < 1024 or i == len(suffixes) - 1:
            break
        nbytes /= 1024.0

    size_str = f"{nbytes:.2f}".rstrip("0").rstrip(".")
    return f"{size_str} {suffixes[i]}"


def human_time(timestamp):
    """Takes a numerical timestamp (seconds since the epoch) and formats it as a human-readable date and time in the format "YYYY-MM-DD HH:MM:SS"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def make_dirs(path):
    """Creates directories at the given path. It handles the exception `os.errno.EEXIST` that may occur if the directories already exist."""
    try:
        makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def get_list_from_option(opt):
    """Takes a comma-separated string and converts it to a list of lowercase strings.
    It filters out empty strings from the input before converting.
    """
    return [o.lower() for o in filter(bool, opt.split(","))]


class NFSSpiderPlus:
    def __init__(
        self,
        nfs,
        logger,
        stats_flag,
        exclude_exts,
        exclude_filter,
        max_file_size,
        max_depth,
        output_folder,
    ):
        self.nfs = nfs
        self.host = self.nfs.host
        self.logger = logger
        self.results = {}
        self.stats = {
            "shares": [],
            "shares_readable": [],
            "num_files": 0,
            "num_files_filtered": 0,
            "file_sizes": [],
            "file_exts": set(),
        }
        self.stats_flag = stats_flag
        self.exclude_exts = exclude_exts
        self.exclude_filter = exclude_filter
        self.max_file_size = max_file_size
        self.max_depth = max_depth
        self.output_folder = output_folder

        make_dirs(self.output_folder)

    def get_share_list(self):
        """Returns the list of NFS exports to spider, honoring the global --share flag."""
        try:
            output_export = str(self.nfs.mount.export())
        except Exception as e:
            self.logger.fail(f"Failed to enumerate NFS exports: {e}")
            return []

        reg = re.compile(r"ex_dir=b'([^']*)'")
        all_shares = [s.rstrip("/") or "/" for s in reg.findall(output_export)]

        requested = getattr(self.nfs.args, "share", None)
        if requested:
            if requested in all_shares:
                return [requested]
            self.logger.fail(f"Requested share {requested!r} not found in exports: {all_shares}")
            return []
        return all_shares

    def spider_shares(self):
        """Entry point: mount each share, list its contents, record filtered metadata, dump JSON."""
        self.logger.info("Enumerating NFS exports for spidering.")

        # Ensure an NFSv3 connection is active for the lifetime of the spider
        nfs_port = self.nfs.portmap.getport(NFS_PROGRAM, NFS_V3)
        self.nfs.nfs3 = NFSv3(self.nfs.host, nfs_port, self.nfs.args.nfs_timeout, self.nfs.auth)
        self.nfs.nfs3.connect()

        try:
            for share in self.get_share_list():
                self.stats["shares"].append(share)
                self._spider_share(share)
        finally:
            try:
                self.nfs.nfs3.disconnect()
            except Exception as e:
                self.logger.debug(f"Error disconnecting nfs3: {e}")

        self.dump_folder_metadata(self.results)

        if self.stats_flag:
            self.print_stats()

        return self.results

    def _spider_share(self, share):
        """Mounts a single share, lists it recursively via nfs.list_dir, and processes entries."""
        self.logger.info(f'Spidering export "{share}"')
        mount_info = None
        mounted = False
        try:
            mount_info = self.nfs.mount.mnt(share, self.nfs.auth)
            if mount_info["status"] != 0:
                self.logger.fail(f'Cannot mount export "{share}": {NFSSTAT3[mount_info["status"]]}')
                return
            mounted = True

            fhandle = mount_info["mountinfo"]["fhandle"]
            self.nfs.update_auth(fhandle)

            entries = self.nfs.list_dir(fhandle, share, recurse=self.max_depth)
            if entries is None:
                entries = []

            self.stats["shares_readable"].append(share)
            self.results[share] = {}

            for entry in entries:
                self._process_entry(share, entry)
        except Exception as e:
            msg = str(e)
            if "RPC_AUTH_ERROR: AUTH_REJECTEDCRED" in msg:
                self.logger.fail(f"{share} - RPC access denied")
            elif "RPC_AUTH_ERROR: AUTH_TOOWEAK" in msg:
                self.logger.fail(f"{share} - Kerberos authentication required")
            elif "Insufficient Permissions" in msg:
                self.logger.fail(f"{share} - Insufficient permissions for share listing")
            else:
                self.logger.fail(f'Error spidering export "{share}": {e}')
                self.logger.exception(e)
        finally:
            if mounted:
                try:
                    self.nfs.mount.umnt(self.nfs.auth)
                except Exception as e:
                    self.logger.debug(f"Error unmounting {share}: {e}")

            # Drop the share key if no files were recorded (keeps JSON concise).
            if share in self.results and not self.results[share]:
                del self.results[share]

    def _process_entry(self, share, entry):
        """Applies filters to a single entry from list_dir and records it if kept."""
        path = entry.get("path", "")
        # list_dir marks directory entries (only in recurse=0 mode) with trailing "/".
        if path.endswith("/"):
            return

        # Strip share prefix to get a path relative to the share root.
        prefix = share.rstrip("/") + "/"
        relative = path[len(prefix):] if path.startswith(prefix) else path.lstrip("/")

        size_bytes = entry.get("size_bytes", 0)

        # Filter 1: extension (case-insensitive).
        _, ext = splitext(relative)
        ext_lower = ext.lstrip(".").lower() if ext else ""
        if ext_lower and ext_lower in self.exclude_exts:
            self.logger.info(f'Filtered "{relative}" in {share} (extension "{ext_lower}")')
            self.stats["num_files_filtered"] += 1
            return

        # Filter 2: path substring (case-insensitive).
        relative_lower = relative.lower()
        if any(f in relative_lower for f in self.exclude_filter):
            self.logger.info(f'Filtered "{relative}" in {share} (path filter match)')
            self.stats["num_files_filtered"] += 1
            return

        # Filter 3: size.
        if size_bytes > self.max_file_size:
            self.logger.info(f'Filtered "{relative}" in {share} (size {human_size(size_bytes)} > max {human_size(self.max_file_size)})')
            self.stats["num_files_filtered"] += 1
            return

        self.results[share][relative] = {
            "size": human_size(size_bytes),
            "ctime_epoch": human_time(entry.get("ctime", 0)),
            "mtime_epoch": human_time(entry.get("mtime", 0)),
            "atime_epoch": human_time(entry.get("atime", 0)),
        }
        self.stats["num_files"] += 1
        self.stats["file_sizes"].append(size_bytes)
        if ext_lower:
            self.stats["file_exts"].add(ext_lower)

    def dump_folder_metadata(self, results):
        """Writes the metadata results to `{output_folder}/{host}.json`."""
        metadata_path = join(self.output_folder, f"{self.host}.json")
        try:
            with open(metadata_path, "w", encoding="utf-8") as fd:
                fd.write(json.dumps(results, indent=4, sort_keys=True))
            self.logger.success(f'Saved share-file metadata to "{metadata_path}".')
        except Exception as e:
            self.logger.fail(f"Failed to save share metadata: {e}")

    def print_stats(self):
        """Prints enumeration summary."""
        shares = self.stats.get("shares", [])
        if shares:
            self.logger.display(f"NFS Exports:          {len(shares)} ({', '.join(shares)})")

        shares_readable = self.stats.get("shares_readable", [])
        if shares_readable:
            sr_str = ", ".join(shares_readable[:10]) + ("..." if len(shares_readable) > 10 else "")
            self.logger.display(f"NFS Readable Exports: {len(shares_readable)} ({sr_str})")

        num_files = self.stats.get("num_files", 0)
        self.logger.display(f"Total files kept:     {num_files}")
        num_filtered = self.stats.get("num_files_filtered", 0)
        if num_filtered:
            self.logger.display(f"Files filtered:       {num_filtered}")
        if num_files == 0:
            return

        file_sizes = self.stats.get("file_sizes", [])
        if file_sizes:
            total = sum(file_sizes)
            self.logger.display(f"File size average:    {human_size(total / num_files)}")
            self.logger.display(f"File size min:        {human_size(min(file_sizes))}")
            self.logger.display(f"File size max:        {human_size(max(file_sizes))}")

        file_exts = sorted(self.stats.get("file_exts", set()))
        if file_exts:
            exts_str = ", ".join(file_exts[:10]) + ("..." if len(file_exts) > 10 else "")
            self.logger.display(f"File unique exts:     {len(file_exts)} ({exts_str})")


class NXCModule:
    """NFS Spider Plus Module

    Adapted from the SMB spider_plus module.
    """

    name = "nfs_spider_plus"
    description = "List files recursively via NFS and save JSON share-file metadata to the 'OUTPUT_FOLDER'."
    supported_protocols = ["nfs"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        List files recursively via NFS and save JSON share-file metadata to the OUTPUT_FOLDER.

        STATS_FLAG        Disable file/extension statistics output (Default: True)
        EXCLUDE_EXTS      Case-insensitive file extensions to exclude (Default: ico,lnk)
        EXCLUDE_FILTER    Case-insensitive path substrings to exclude (Default: none)
        MAX_FILE_SIZE     Max file size in bytes to record (Default: 51200)
        MAX_DEPTH         Max directory recursion depth (Default: 10)
        OUTPUT_FOLDER     Local folder for the JSON output (Default: NXC_PATH/modules/nxc_nfs_spider_plus)
        """
        self.stats_flag = True
        if any("STATS" in key for key in module_options):
            self.stats_flag = False
        self.exclude_exts = get_list_from_option(module_options.get("EXCLUDE_EXTS", "ico,lnk"))
        self.exclude_filter = get_list_from_option(module_options.get("EXCLUDE_FILTER", ""))
        self.max_file_size = int(module_options.get("MAX_FILE_SIZE", 50 * 1024))
        self.max_depth = int(module_options.get("MAX_DEPTH", 10))
        self.output_folder = module_options.get("OUTPUT_FOLDER", abspath(join(NXC_PATH, "modules/nxc_nfs_spider_plus")))

    def on_login(self, context, connection):
        context.log.display("Started NFS spider_plus module with the following options:")
        context.log.display(f"    STATS_FLAG: {self.stats_flag}")
        context.log.display(f"  EXCLUDE_EXTS: {self.exclude_exts}")
        context.log.display(f"EXCLUDE_FILTER: {self.exclude_filter}")
        context.log.display(f" MAX_FILE_SIZE: {human_size(self.max_file_size)}")
        context.log.display(f"     MAX_DEPTH: {self.max_depth}")
        context.log.display(f" OUTPUT_FOLDER: {self.output_folder}")

        spider = NFSSpiderPlus(
            connection,
            context.log,
            self.stats_flag,
            self.exclude_exts,
            self.exclude_filter,
            self.max_file_size,
            self.max_depth,
            self.output_folder,
        )
        spider.spider_shares()
