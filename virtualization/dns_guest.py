"""Keep the original UDAPI DNS owner in the mounted guest, before systemd."""
import os
from pathlib import Path
import posixpath
import tempfile


RESOLVED_FILES = {
    '/run/systemd/resolve/stub-resolv.conf',
    '/run/systemd/resolve/resolv.conf',
}


def configure(root=Path('/')):
    root = Path(root)
    units = root / 'etc/systemd/system'
    masks = [units / (name + '.service') for name in ('dnsmasq', 'systemd-resolved')]
    # The factory image has only vendor units under /lib. Do not overwrite a
    # replacement administrator unit under /etc during an existing-VM upgrade.
    for path in masks:
        if path.exists() and not path.is_symlink():
            raise ValueError('Refusing to replace custom DNS unit: ' + str(path))
        if path.is_symlink():
            target = posixpath.normpath(posixpath.join('/etc/systemd/system', os.readlink(path)))
            allowed = {'/dev/null', '/lib/systemd/system/' + path.name,
                       '/usr/lib/systemd/system/' + path.name}
            if target not in allowed:
                raise ValueError('Refusing to replace custom DNS unit: ' + str(path))

    resolver = root / 'etc/resolv.conf'
    replace_resolver = not resolver.exists() and not resolver.is_symlink()
    if resolver.is_symlink():
        target = posixpath.normpath(posixpath.join('/etc', os.readlink(resolver)))
        replace_resolver = target in RESOLVED_FILES

    units.mkdir(parents=True, exist_ok=True)
    for path in masks:
        if path.is_symlink() and os.readlink(path) == '/dev/null':
            continue
        temporary = path.with_name(path.name + '.udm-dns-tmp')
        # Exclusive creation also avoids replacing an unrelated leftover file.
        temporary.symlink_to('/dev/null')
        try:
            os.replace(temporary, path)
        finally:
            if temporary.is_symlink():
                temporary.unlink()

    if replace_resolver:
        # Never follow the old stub symlink: /run belongs to the guest systemd
        # instance and is empty before it starts. UDAPI independently manages
        # upstream DNS in /etc/resolv.dnsmasq, avoiding a forwarding loop.
        descriptor, name = tempfile.mkstemp(prefix='.resolv.conf.udm-', dir=resolver.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
                stream.write('nameserver 127.0.0.1\n')
                os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, resolver)
        finally:
            if temporary.exists():
                temporary.unlink()
    return replace_resolver


if __name__ == '__main__':
    changed = configure()
    print('UDM_VIRTUAL_DNS_READY resolver=' + ('native' if changed else 'preserved'))
