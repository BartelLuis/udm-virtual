#!/bin/bash
# Runs in the mounted original guest before systemd, never on the host.
set -euo pipefail
payload=/usr/lib/udm-virtual
/usr/bin/python3 "$payload/hal_guest.py" --nics 14
/usr/bin/python3 "$payload/late_boot.py"
/usr/bin/python3 "$payload/controller_guest.py"

original=ccdda14e798184b7e10c8385c6b85d46df82695a4c9a0ec50e849bfab00416ec
adapted=d2460e19ea0e2fc883e2393f0312822a260dd301a01344adc70d763e860c5e7b
previous=3d154393382d5eed4b3483b16e7b6da39e2ddbd4b28d8892dc5e56d54ca50e0d
current=$(sha256sum /usr/bin/ubios-udapi-server | cut -d' ' -f1)
[[ $current == "$original" || $current == "$adapted" || $current == "$previous" ]] || {
    echo 'UDM_VIRTUAL_FAILURE: unsupported installed network daemon' >&2; exit 1;
}
[[ $(sha256sum "$payload/ubios-udapi-server.virtual" | cut -d' ' -f1) == "$adapted" ]]
install -m 0755 "$payload/ubios-udapi-server.virtual" /usr/bin/ubios-udapi-server
install -m 0644 "$payload/virtual-board.json" /usr/share/ubios-udapi-server/config-board/udm-beast-ea4c.json
install -m 0644 "$payload/virtual.default" /usr/share/ubios-udapi-server/udm-beast-ea4c.default
install -m 0644 "$payload/virtual.fallback" /usr/share/ubios-udapi-server/udm-beast-ea4c.fallback
state=/data/udapi-config/ubios-udapi-server/ubios-udapi-server.state
if [[ ! -e $state ]]; then
    install -d -m 0700 "$(dirname "$state")"
    install -m 0600 "$payload/virtual.default" "$state"
fi
if grep -qw 'udm.validation=firewall' /proc/cmdline; then
    # Only the explicit validation runner selects this mode and always uses a
    # disposable QEMU snapshot. Normal boots keep UniFi's factory/setup policy.
    install -m 0600 "$payload/validation.default" "$state"
    echo UDM_VIRTUAL_VALIDATION_POLICY
fi

# Native Linux networking remains enabled. These units require absent ASICs.
for unit in marvell-cpss cpss-app cm lagd led-gpio-init rpsd lighttpd; do
    ln -sfn /dev/null "/etc/systemd/system/$unit.service"
done
install -d -m 0755 /etc/systemd/system/udapi-server.service.d
ln -sfn /dev/null /etc/systemd/system/udapi-server.service.d/cpss.conf
# Preserve the original RequiredBy/Requires dependency. The original helper's
# existence-only check accepts empty files left behind by its 20-second timeout.
install -d -m 0755 /etc/systemd/system/freeradius-dh-key.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/bin/python3 /usr/lib/udm-virtual/freeradius_dh.py\nTimeoutStartSec=600s\n' > /etc/systemd/system/freeradius-dh-key.service.d/90-virtual-dh.conf
# The firmware update omits the local snakeoil pair normally created by the
# ssl-cert package postinst. Initialize it as root before FreeRADIUS's original
# freerad-user configuration check. Existing valid keys/certificates survive.
install -m 0644 "$payload/freeradius-cert.service" /etc/systemd/system/udm-virtual-freeradius-cert.service
install -d -m 0755 /etc/systemd/system/freeradius.service.d
install -m 0644 "$payload/freeradius-cert.conf" /etc/systemd/system/freeradius.service.d/90-virtual-local-cert.conf
install -d -m 0755 /etc/systemd/system/unifi-core.service.d
printf '[Service]\nTimeoutStartSec=600s\n' > /etc/systemd/system/unifi-core.service.d/90-virtual-start-timeout.conf
for unit in unifi rabbitmq-server; do
    install -d -m 0755 "/etc/systemd/system/$unit.service.d"
    printf '[Service]\nTimeoutStartSec=3600s\n' > "/etc/systemd/system/$unit.service.d/90-virtual-start-timeout.conf"
done
install -m 0644 "$payload/unifi-tcg.conf" /etc/systemd/system/unifi.service.d/91-virtual-tcg.conf
echo UDM_VIRTUAL_ADAPTATION_READY
