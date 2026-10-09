#!/bin/bash
# Keep original JVM options, selecting C1 and the configured controller layout.
set -euo pipefail
options=()
for argument in "$@"; do
    if [[ $argument == -XX:-TieredCompilation ]]; then
        options+=(-XX:+TieredCompilation -XX:TieredStopAtLevel=1)
    else
        options+=("$argument")
    fi
done
case ${UDM_UNIFI_LAUNCH-nested} in
    nested)
        exec /usr/bin/java "${options[@]}"
        ;;
    flat)
        exec /usr/bin/python3 /usr/lib/udm-virtual/controller_flat.py launch -- "${options[@]}"
        ;;
    *)
        printf '%s\n' 'UDM_VIRTUAL_CONTROLLER_FLAT_FAILURE: unknown UDM_UNIFI_LAUNCH mode' >&2
        exit 64
        ;;
esac
