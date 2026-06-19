from impacket.ldap import ldaptypes
from impacket.smbconnection import SessionError
from impacket.smb3structs import (
    SMB2_0_INFO_SECURITY,
    OWNER_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    DACL_SECURITY_INFORMATION,
    READ_CONTROL,
    FILE_SHARE_READ,
    FILE_OPEN,
)
from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException

from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.helpers.ntsecuritydescriptor import SIDResolver, render_security_descriptor


class NXCModule:
    """Read NTFS security descriptors (owner/group/DACL) of files and directories over SMB.

    Module by NetExec
    """

    name = "smbcacls"
    description = "Read the security descriptor (owner, group, DACL) of a file or directory on a share (smbcacls analog)"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self):
        self.share = None
        self.path = ""
        self.recurse = False
        self.resolve_sids = True

    def options(self, context, module_options):
        """
        SHARE         Share to read from (required), e.g. C$
        PATH          File or directory path within the share (default: share root)
        RECURSE       Recurse into a directory, reading every entry's SD (default: False)
        RESOLVE_SIDS  Resolve SIDs to names via LSARPC (default: True)
        """
        self.share = module_options.get("SHARE")
        self.path = module_options.get("PATH", "").replace("/", "\\").lstrip("\\")
        self.recurse = module_options.get("RECURSE", "false").lower() in ("true", "1", "yes")
        self.resolve_sids = module_options.get("RESOLVE_SIDS", "true").lower() in ("true", "1", "yes")

    def _make_lsa_lookup(self, context, connection):
        """Return (lookup_func(sid)->name, rpc) backed by LSARPC, or (None, None) if unavailable.

        The caller is responsible for calling rpc.disconnect() when done.
        """
        try:
            rpc = NXCRPCConnection(connection)
            dce = rpc.connect(r"\lsarpc", lsat.MSRPC_UUID_LSAT)
            policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
        except Exception as e:
            context.log.debug(f"LSARPC unavailable, SIDs will not be resolved: {e}")
            return None, None

        def lookup(sid):
            try:
                res = lsat.hLsarLookupSids(dce, policy, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException:
                # SID could not be mapped (e.g. STATUS_NONE_MAPPED for an orphaned SID).
                # Return None so the resolver caches the raw SID and keeps resolving others.
                return None
            translated = res["TranslatedNames"]["Names"][0]
            domains = res["ReferencedDomains"]["Domains"]
            name = translated["Name"]
            dom_index = translated["DomainIndex"]
            if dom_index >= 0 and name:
                domain = domains[dom_index]["Name"]
                return f"{domain}\\{name}" if domain else name
            return name or None

        return lookup, rpc

    def _get_security_descriptor(self, connection, tree_id, path):
        """Open `path`, query its security descriptor, close, and return parsed SD."""
        smb = connection.conn.getSMBServer()
        # An empty path ("") opens the share root directory (standard SMB2 behavior).
        file_id = smb.create(
            tree_id, path,
            desiredAccess=READ_CONTROL,
            shareMode=FILE_SHARE_READ,
            creationOptions=0,
            creationDisposition=FILE_OPEN,
            fileAttributes=0,
        )
        try:
            blob = smb.queryInfo(
                tree_id, file_id,
                infoType=SMB2_0_INFO_SECURITY,
                fileInfoClass=0,
                additionalInformation=OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            )
        finally:
            smb.close(tree_id, file_id)
        return ldaptypes.SR_SECURITY_DESCRIPTOR(data=blob)

    def _print_path(self, context, connection, tree_id, resolver, path):
        display = f"\\\\{connection.conn.getRemoteHost()}\\{self.share}\\{path}"
        try:
            sd = self._get_security_descriptor(connection, tree_id, path)
        except SessionError as e:
            msg = str(e)
            if "STATUS_ACCESS_DENIED" in msg:
                context.log.fail(f"Access denied reading SD: {display}")
            elif "STATUS_OBJECT_NAME_NOT_FOUND" in msg or "STATUS_OBJECT_PATH_NOT_FOUND" in msg:
                context.log.fail(f"Path not found: {display}")
            else:
                context.log.fail(f"Failed to read SD for {display}: {e}")
            return
        context.log.highlight(display)
        for line in render_security_descriptor(sd, resolver):
            context.log.highlight(f"    {line}")

    def on_login(self, context, connection):
        if not self.share:
            context.log.fail("SHARE option is required (e.g. -o SHARE=C$)")
            return

        try:
            tree_id = connection.conn.connectTree(self.share)
        except SessionError as e:
            context.log.fail(f"Could not connect to share '{self.share}': {e}")
            return

        smb = connection.conn.getSMBServer()
        if not hasattr(smb, "queryInfo"):
            context.log.fail("smbcacls requires SMB2 or later (server negotiated SMB1)")
            return

        if self.resolve_sids:
            lookup, rpc = self._make_lsa_lookup(context, connection)
        else:
            lookup, rpc = None, None
        resolver = SIDResolver(lookup_func=lookup)

        try:
            self._print_path(context, connection, tree_id, resolver, self.path)
            if self.recurse:
                self._walk(context, connection, tree_id, resolver, self.path)
        finally:
            if rpc is not None:
                rpc.disconnect()

    def _walk(self, context, connection, tree_id, resolver, folder):
        listing_path = (folder + "\\*") if folder else "*"
        try:
            entries = connection.conn.listPath(self.share, listing_path)
        except SessionError as e:
            context.log.debug(f"Cannot list '{folder}': {e}")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            child = f"{folder}\\{name}" if folder else name
            self._print_path(context, connection, tree_id, resolver, child)
            if entry.is_directory():
                self._walk(context, connection, tree_id, resolver, child)
