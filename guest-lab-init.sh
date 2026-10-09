#!/bin/sh
# Experimental UDM Beast initramfs entry point.
# The firmware's BusyBox and libraries remain in the initramfs.
# /dev/vda: original SquashFS, always mounted read-only.
# /dev/vdb: an existing, preformatted ext4 guest state disk.
# Kernel option: udm.mode=shell (default), selftest, or systemd.
# This script never formats disks or configures network interfaces.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
BB=/bin/busybox
ROOT=/root
MODE=shell

rescue() {
    echo "UDM_LAB_INIT_FAILURE: $*"
    echo "Experimental initramfs rescue shell; original gateway services are not running."
    while :; do
        "$BB" sh -i
        echo "Rescue shell exited; use 'poweroff -f' to stop the guest."
    done
}

must() {
    "$@" || rescue "Command failed: $*"
}

must "$BB" mkdir -p /proc /sys /dev /run /mnt/.rofs /mnt/.rwfs "$ROOT"
must "$BB" mount -t proc proc /proc
must "$BB" mount -t sysfs sysfs /sys
must "$BB" mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
must "$BB" mkdir -p /dev/pts
must "$BB" mount -t devpts -o mode=0620,gid=5 devpts /dev/pts
must "$BB" mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run

for option in $("$BB" cat /proc/cmdline); do
    case "$option" in
        udm.mode=*) MODE=${option#udm.mode=} ;;
    esac
done
case "$MODE" in
    shell|selftest|systemd) ;;
    *) rescue "Unknown udm.mode '$MODE'; expected shell, selftest, or systemd." ;;
esac

echo "UDM_LAB_INIT_BEGIN mode=$MODE"
echo "Experimental ARM guest: this boot does not establish a working UniFi firewall."

# Allow asynchronous VirtIO probing; never guess another disk if either is absent.
attempt=0
while [ ! -b /dev/vda ] || [ ! -b /dev/vdb ]; do
    [ "$attempt" -lt 30 ] || rescue "Required guest disks /dev/vda and /dev/vdb not found."
    attempt=$((attempt + 1))
    "$BB" sleep 1
done

must "$BB" mount -t squashfs -o ro /dev/vda /mnt/.rofs
must "$BB" mount -t ext4 -o rw,noatime /dev/vdb /mnt/.rwfs
must "$BB" mkdir -p /mnt/.rwfs/data /mnt/.rwfs/.workdir
must "$BB" mount -t overlay overlay \
    -o lowerdir=/mnt/.rofs,upperdir=/mnt/.rwfs/data,workdir=/mnt/.rwfs/.workdir "$ROOT"

# Preserve the original /data and /var/log trees, ownership and initial files.
# They become persistent through the overlay; do not hide them with empty mounts.
must "$BB" mkdir -p "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/run" \
    "$ROOT/tmp" "$ROOT/data" "$ROOT/persistent" "$ROOT/var/log" \
    "$ROOT/mnt/.rofs" "$ROOT/mnt/.rwfs"
must "$BB" chmod 1777 "$ROOT/tmp"
must "$BB" mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs "$ROOT/tmp"

if [ "$MODE" = selftest ]; then
    # The test runs after switch_root with the original userspace binaries.
    # Its script resides in the transient /run mount, not in the firmware image.
    "$BB" cat > /run/udm-lab-selftest.sh <<'SELFTEST'
#!/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
result=0
echo UDM_LAB_SELFTEST_BEGIN
uname -a || result=1
cat /proc/version || result=1
echo UDM_LAB_ROOTFS_VERSION
cat /usr/lib/version || result=1
echo
echo UDM_LAB_LINKS_BEGIN
ip -o link || result=1
echo UDM_LAB_LINKS_END
expected=2
for option in $(cat /proc/cmdline); do
    case "$option" in udm.nics=*) expected=${option#udm.nics=} ;; esac
done
case "$expected" in ''|*[!0-9]*) expected=2; result=1 ;; esac
index=0
while [ "$index" -lt "$expected" ]; do
    driver=$(readlink "/sys/class/net/eth$index/device/driver")
    [ "${driver##*/}" = virtio_net ] || result=1
    index=$((index + 1))
done
echo "UDM_LAB_EXPECTED_VIRTIO_PORTS=$expected"
awk '$2=="/mnt/.rofs" && $3=="squashfs" && $4 ~ /(^|,)ro(,|$)/ {found=1} END {exit !found}' /proc/mounts || result=1
awk '$2=="/mnt/.rwfs" && $3=="ext4" && $4 ~ /(^|,)rw(,|$)/ {found=1} END {exit !found}' /proc/mounts || result=1
awk '$2=="/" && $3=="overlay" {found=1} END {exit !found}' /proc/mounts || result=1
probe=$(mktemp /persistent/.udm-lab-selftest.XXXXXX) || result=1
if [ -n "$probe" ]; then
    printf 'overlay-write-test' > "$probe" || result=1
    [ "$(cat "$probe")" = overlay-write-test ] || result=1
    rm -f "$probe" || result=1
fi
echo UDM_LAB_MOUNT_AND_WRITE_CHECK_COMPLETE
if [ -b /dev/vda ] && [ -b /dev/vdb ] && [ -d /data ] && [ -d /persistent ]; then
    echo UDM_LAB_DISKS_PRESENT
else
    result=1
fi
if [ "$result" -eq 0 ]; then
    echo UDM_LAB_SELFTEST_PASS
else
    echo UDM_LAB_SELFTEST_FAIL
fi
echo 'Gateway services and firewall forwarding were not tested or started.'
sync
/bin/busybox poweroff -f
while :; do /bin/busybox sleep 60; done
SELFTEST
    [ "$?" -eq 0 ] || rescue "Could not create the transient selftest script."
    must "$BB" chmod 0755 /run/udm-lab-selftest.sh
fi

# Keep backing mounts reachable after switch_root, with no host paths exposed.
must "$BB" mount --move /mnt/.rofs "$ROOT/mnt/.rofs"
must "$BB" mount --move /mnt/.rwfs "$ROOT/mnt/.rwfs"
must "$BB" mount --move /run "$ROOT/run"
must "$BB" mount --move /sys "$ROOT/sys"
must "$BB" mount --move /proc "$ROOT/proc"
must "$BB" mount --move /dev "$ROOT/dev"

# Optional, version-guarded virtual hardware adaptation built from this firmware.
# The payload resides in the initramfs; it cannot read or change any host files.
if [ -f /udm-virtual/boot.sh ]; then
    must "$BB" mkdir -p "$ROOT/usr/lib/udm-virtual"
    must "$BB" cp -a /udm-virtual/. "$ROOT/usr/lib/udm-virtual/"
    must "$BB" chroot "$ROOT" /bin/bash /usr/lib/udm-virtual/boot.sh
fi

case "$MODE" in
    shell)
        echo UDM_LAB_ROOTFS_VERSION
        "$BB" cat "$ROOT/usr/lib/version"
        echo
        echo 'UDM_LAB_SHELL_READY: isolated root console; interfaces have no configured addresses.'
        echo 'The original systemd services have not been started.'
        HOME=/root
        TERM=vt100
        PS1='[UDM LAB - no gateway services] \w # '
        export HOME TERM PS1
        exec "$BB" switch_root -c /dev/console "$ROOT" /bin/bash --noprofile --norc -i
        ;;
    selftest)
        exec "$BB" switch_root -c /dev/console "$ROOT" /bin/sh /run/udm-lab-selftest.sh
        ;;
    systemd)
        echo 'UDM_LAB_SYSTEMD_START: original hardware-dependent services may fail.'
        exec "$BB" switch_root -c /dev/console "$ROOT" /sbin/init
        ;;
esac
rescue 'switch_root did not start the requested guest process.'
