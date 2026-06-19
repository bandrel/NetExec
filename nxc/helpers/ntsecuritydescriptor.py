from impacket.ldap import ldaptypes
from impacket.smb3structs import (
    FILE_READ_DATA, FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_READ_EA, FILE_WRITE_EA,
    FILE_EXECUTE, FILE_DELETE_CHILD, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
    DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE,
    GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE,
    SMB2_0_INFO_SECURITY, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    DACL_SECURITY_INFORMATION, FILE_SHARE_READ, FILE_OPEN,
)
from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from nxc.helpers.rpc import NXCRPCConnection

# Standard (0x1F0000) + specific file rights (0x1FF) all set.
FULL_CONTROL = 0x1F01FF

_FILE_RIGHTS = [
    (FILE_READ_DATA, "READ_DATA"),
    (FILE_WRITE_DATA, "WRITE_DATA"),
    (FILE_APPEND_DATA, "APPEND_DATA"),
    (FILE_READ_EA, "READ_EA"),
    (FILE_WRITE_EA, "WRITE_EA"),
    (FILE_EXECUTE, "EXECUTE"),
    (FILE_DELETE_CHILD, "DELETE_CHILD"),
    (FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"),
    (FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"),
    (DELETE, "DELETE"),
    (READ_CONTROL, "READ_CONTROL"),
    (WRITE_DAC, "WRITE_DAC"),
    (WRITE_OWNER, "WRITE_OWNER"),
    (SYNCHRONIZE, "SYNCHRONIZE"),
]

_GENERIC_RIGHTS = [
    (GENERIC_ALL, "GENERIC_ALL"),
    (GENERIC_READ, "GENERIC_READ"),
    (GENERIC_WRITE, "GENERIC_WRITE"),
    (GENERIC_EXECUTE, "GENERIC_EXECUTE"),
]


def decode_file_access_mask(mask):
    """Decode an ACE access mask into a list of file-specific right names.

    Collapses the all-bits-set case to ["FULL_CONTROL"]. Generic bits are
    reported alongside any specific rights. Bits with no known meaning are
    ignored (callers fall back to hex when the result is empty).
    """
    generic = [name for bit, name in _GENERIC_RIGHTS if mask & bit == bit]
    specific_mask = mask & FULL_CONTROL
    if specific_mask == FULL_CONTROL:
        return ["FULL_CONTROL", *generic]
    specific = [name for bit, name in _FILE_RIGHTS if mask & bit == bit]
    return specific + generic


# Universal + builtin SIDs. Copied verbatim from nxc/modules/daclread.py.
WELL_KNOWN_SIDS = {
    "S-1-0": "Null Authority",
    "S-1-0-0": "Nobody",
    "S-1-1": "World Authority",
    "S-1-1-0": "Everyone",
    "S-1-2": "Local Authority",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3": "Creator Authority",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-2": "Creator Owner Server",
    "S-1-3-3": "Creator Group Server",
    "S-1-3-4": "Owner Rights",
    "S-1-5-80-0": "All Services",
    "S-1-4": "Non-unique Authority",
    "S-1-5": "NT Authority",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "This Organization",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority",
    "S-1-5-20": "NT Authority",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authority",
    "S-1-5-80": "NT Service",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
    "S-1-16-28672": "Secure Process Mandatory Level",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575": "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576": "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577": "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}


class SIDResolver:
    """Resolves SID strings to names.

    Order: well-known table -> cache -> injected lookup_func (e.g. LSARPC).
    `lookup_func` is a callable taking a SID string and returning a name (or
    None). It is injected so the resolver stays unit-testable without a network.
    On the first lookup failure, network resolution is disabled and raw SID
    strings are returned thereafter.
    """

    def __init__(self, lookup_func=None):
        self._lookup = lookup_func
        self._cache = {}
        self._enabled = lookup_func is not None

    def resolve(self, sid):
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        if sid in self._cache:
            return self._cache[sid]
        if not self._enabled:
            return sid
        try:
            name = self._lookup(sid)
        except Exception:
            self._enabled = False
            return sid
        result = name or sid
        self._cache[sid] = result
        return result


def render_security_descriptor(sd, resolver):
    """Render a parsed SR_SECURITY_DESCRIPTOR into a list of display lines.

    `sd` is an impacket ldaptypes.SR_SECURITY_DESCRIPTOR. `resolver` is a
    SIDResolver. Only ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE are rendered;
    object ACEs (rare on filesystems) are skipped.
    """
    lines = []
    owner = sd["OwnerSid"]
    group = sd["GroupSid"]
    if owner:
        lines.append(f"OWNER: {resolver.resolve(owner.formatCanonical())}")
    if group:
        lines.append(f"GROUP: {resolver.resolve(group.formatCanonical())}")

    dacl = sd["Dacl"]
    if dacl is None:
        lines.append("DACL: (none present - owner has implicit full control)")
        return lines

    verbs = {
        ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE: "ALLOWED",
        ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE: "DENIED",
    }
    for ace in dacl["Data"]:
        verb = verbs.get(ace["AceType"])
        if verb is None:
            continue
        sid_str = ace["Ace"]["Sid"].formatCanonical()
        mask = ace["Ace"]["Mask"]["Mask"]
        rights = ",".join(decode_file_access_mask(mask)) or f"0x{mask:x}"
        inherited = " [INHERITED]" if ace["AceFlags"] & ldaptypes.ACE.INHERITED_ACE else ""
        trustee = resolver.resolve(sid_str)
        lines.append(f"{verb:<7} {trustee:<35} {rights}{inherited}")
    return lines


def fetch_security_descriptor(connection, tree_id, path):
    """Open `path` on `tree_id`, query its security descriptor, close, return parsed SD.

    `connection` is an NXC connection (uses connection.conn.getSMBServer()).
    An empty `path` ("") targets the share root directory (standard SMB2 behavior).
    Raises impacket SessionError on failure (caller decides how to record it).
    """
    smb = connection.conn.getSMBServer()
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


def security_descriptor_to_dict(sd, resolver):
    """Convert a parsed SR_SECURITY_DESCRIPTOR into a JSON-serializable dict.

    Only ACCESS_ALLOWED / ACCESS_DENIED ACEs are emitted; object ACEs are skipped.
    """
    result = {"owner": None, "group": None, "dacl": []}
    if sd["OwnerSid"]:
        result["owner"] = resolver.resolve(sd["OwnerSid"].formatCanonical())
    if sd["GroupSid"]:
        result["group"] = resolver.resolve(sd["GroupSid"].formatCanonical())
    dacl = sd["Dacl"]
    if dacl is None:
        return result
    verbs = {
        ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE: "ALLOWED",
        ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE: "DENIED",
    }
    for ace in dacl["Data"]:
        verb = verbs.get(ace["AceType"])
        if verb is None:
            continue
        result["dacl"].append({
            "type": verb,
            "trustee": resolver.resolve(ace["Ace"]["Sid"].formatCanonical()),
            "rights": decode_file_access_mask(ace["Ace"]["Mask"]["Mask"]),
            "inherited": bool(ace["AceFlags"] & ldaptypes.ACE.INHERITED_ACE),
        })
    return result


def make_lsa_lookup(connection):
    """Return (lookup_func(sid)->name|None, rpc) backed by LSARPC, or (None, None).

    The caller must call rpc.disconnect() when done. A DCERPCException for an
    unmappable SID returns None for that SID rather than disabling resolution.
    """
    try:
        rpc = NXCRPCConnection(connection)
        dce = rpc.connect(r"\lsarpc", lsat.MSRPC_UUID_LSAT)
        policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
    except Exception:
        return None, None

    def lookup(sid):
        try:
            res = lsat.hLsarLookupSids(dce, policy, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException:
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
