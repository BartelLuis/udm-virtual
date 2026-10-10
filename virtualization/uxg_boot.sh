#!/bin/bash
# Runs only inside the mounted UXGENT guest before its original systemd.
set -euo pipefail
payload=/usr/lib/udm-virtual
/usr/bin/python3 "$payload/hal_guest.py" --model UXGENT --nics 6
/usr/bin/python3 "$payload/uxg_guest.py"
/usr/bin/python3 "$payload/dns_guest.py"

# Keep the firmware's gateway, setup, discovery and external-controller services.
# Fresh firmware overlays need valid local FreeRADIUS initialization under TCG.
install -d -m 0755 /etc/systemd/system/freeradius-dh-key.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/bin/python3 /usr/lib/udm-virtual/freeradius_dh.py\nTimeoutStartSec=600s\n' > /etc/systemd/system/freeradius-dh-key.service.d/90-virtual-dh.conf
install -m 0644 "$payload/freeradius-cert.service" /etc/systemd/system/udm-virtual-freeradius-cert.service
install -d -m 0755 /etc/systemd/system/freeradius.service.d
install -m 0644 "$payload/freeradius-cert.conf" /etc/systemd/system/freeradius.service.d/90-virtual-local-cert.conf
for unit in uxgpro-setup udapi-server udapi-bridge; do
    install -d -m 0755 "/etc/systemd/system/$unit.service.d"
    printf '[Service]\nTimeoutStartSec=600s\n' > "/etc/systemd/system/$unit.service.d/90-virtual-start-timeout.conf"
done
echo UXG_VIRTUAL_ADAPTATION_READY
