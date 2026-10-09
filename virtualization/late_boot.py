#!/usr/bin/python3
"""Skip the physical MDIO workaround that issues unsupported SMCs on QEMU."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile

if __package__:
    from .hal_guest import require_guest, RUNTIME
else:
    from hal_guest import require_guest, RUNTIME


HOOK = Path('/usr/lib/ubnt/hooks/system/bootup-bottom/01-phy-diag-wa')
ORIGINAL_SHA256 = 'afae996b8acc32340e315fb7ab66252073b963b4fbad77d9e6f7bfce4c7ef97c'
REPLACEMENT = b'''#!/bin/sh
# QEMU virt has VirtIO ports, no CN10K RJ45 PHYs or MDIO firmware.
# The original phy_diag module issues a physical-platform SMC during init.
# Other original bootup-bottom hooks are preserved.
echo UDM_VIRTUAL_PHY_DIAG_SKIPPED
'''
MODULE = Path('/sys/module/phy_diag')


def adapt_hook(path=HOOK):
    options = require_guest()
    if (RUNTIME / 'ready').is_symlink() or not (RUNTIME / 'ready').is_file():
        raise ValueError('Virtual HAL must be ready before adapting late boot')
    blocked = [option.split('=', 1)[1] for option in options
               if option.startswith('module_blacklist=')]
    if len(blocked) != 1 or 'phy_diag' not in blocked[0].split(','):
        raise ValueError('Requires module_blacklist=phy_diag in the guest kernel command line')
    if MODULE.exists():
        raise ValueError('Physical phy_diag module is already loaded')
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Original physical PHY hook must be an ordinary file')
    content = path.read_bytes()
    if content == REPLACEMENT:
        return False
    if hashlib.sha256(content).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('Unsupported physical PHY hook SHA256; refusing to replace it')
    descriptor, temporary = tempfile.mkstemp(prefix='.udm-phy-hook-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(REPLACEMENT)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o755)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return True


def main():
    try:
        adapt_hook()
    except (OSError, ValueError) as error:
        print('UDM_VIRTUAL_LATE_BOOT_FAILURE: ' + str(error), file=sys.stderr, flush=True)
        return 1
    print('UDM_VIRTUAL_LATE_BOOT_READY: physical PHY diagnostic disabled', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
