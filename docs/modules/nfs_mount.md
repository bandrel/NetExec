# NFS Mount Module

## Overview

The `nfs_mount` module automatically discovers NFS exports on target systems and generates resilient mount commands with configurable mount points. This module is designed for penetration testing scenarios where you need to mount NFS shares while ensuring stability when target systems go offline.

## Features

- **Auto-discovery**: Automatically finds NFS exports via established NFS connections
- **Manual shares**: Accept manually specified shares as additional input  
- **Resilient mounts**: Generate commands with stability options for network failures
- **Configurable paths**: Support custom mount point base directories
- **Directory creation**: Optionally create mount point directories automatically

## Usage

### Basic Usage
```bash
nxc nfs 192.168.1.100 -M nfs_mount
```

### With Custom Mount Base
```bash
nxc nfs 192.168.1.100 -M nfs_mount -o MOUNT_BASE=/tmp/nfs
```

### With Directory Creation
```bash
nxc nfs 192.168.1.100 -M nfs_mount -o CREATE_DIRS=true
```

### With Manual Shares
```bash
nxc nfs 192.168.1.100 -M nfs_mount -o SHARES="server2:/backup,server3:/data"
```

### Combined Options
```bash
nxc nfs 192.168.1.100 -M nfs_mount -o MOUNT_BASE=/opt/mounts USE_HOSTNAME=false CREATE_DIRS=true SHARES="backup:/important"
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `MOUNT_BASE` | string | `/mnt` | Base directory for mount points |
| `USE_HOSTNAME` | boolean | `true` | Include hostname in mount path |
| `CREATE_DIRS` | boolean | `false` | Create mount point directories |
| `SHARES` | string | _(empty)_ | Manual shares: `server1:/path1,server2:/path2` |
| `OUTFILE` | string | `~/.nxc/modules/nfs_mount/<host>.sh` | Destination path for generated shell script (created executable) |

## Mount Command Options

All generated commands use hardcoded resilient options for stability:

```bash
mount -t nfs -o soft,timeo=30,retry=2,intr server:/path /mount/point
```

**Option Details:**
- `soft` - Return errors instead of hanging when server unreachable
- `timeo=30` - 3-second timeout (30 deciseconds) for operations  
- `retry=2` - Limited retry attempts to avoid excessive delays
- `intr` - Allow interrupting hung mount operations

## Security Considerations

- Module runs with user privileges (no admin access needed)
- Only discovers exports already accessible via NFS
- Input sanitization via shlex.quote() prevents command injection
- No credential extraction or privilege escalation attempted

## Author

Module by @user
