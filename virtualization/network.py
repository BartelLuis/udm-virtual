"""Adapt the original ea4c board/defaults to fourteen native VirtIO ports.

The UniFi model retains its original interface numbering: WAN is eth8, WAN2 is
eth12. All other ports belong to the initial LAN bridge. The original UDAPI
daemon continues to own IP configuration, DHCP, routing and firewall rules.
Pair this profile with patch_cpss.py; its inert CPSS object has no ASIC ports.
"""
from copy import deepcopy


NIC_COUNT = 14
NATIVE_INTERFACES = tuple(f"eth{index}" for index in range(NIC_COUNT))
WAN_INTERFACES = ("eth8", "eth12")
LAN_INTERFACES = tuple(name for name in NATIVE_INTERFACES if name not in WAN_INTERFACES)
BOARD_FILENAME = "udm-beast-ea4c.json"
DEFAULT_FILENAME = "udm-beast-ea4c.default"
FALLBACK_FILENAME = "udm-beast-ea4c.fallback"


def _interfaces(document):
    """Reject ambiguous interface lists before altering a firmware profile."""
    if not isinstance(document, dict):
        raise ValueError("Expected a firmware JSON object")
    try:
        interfaces = document["interfaces"]
        names = [item["identification"]["id"] for item in interfaces]
    except (KeyError, TypeError) as exc:
        raise ValueError("Expected an interface list with identification.id") from exc
    if not isinstance(interfaces, list) or any(not isinstance(name, str) for name in names):
        raise ValueError("Expected an interface list with string identifiers")
    if len(names) != len(set(names)):
        raise ValueError("Duplicate interface identifiers")
    if not set(NATIVE_INTERFACES).issubset(names):
        raise ValueError("The ea4c profile requires eth0 through eth13")
    return {name: item for name, item in zip(names, interfaces)}


def generate_board(original):
    """Return an independent virtual board dictionary from the firmware JSON.

    The compiled daemon builds its switch map from CPU-port interfaces, not
    merely from the number of JSON switch descriptors. Keep one CPU descriptor
    and an empty Linux bridge named switch0, so its C++ switch object remains
    valid while all fourteen guest Ethernet devices use native Linux netdevs.
    """
    interfaces = _interfaces(original)
    if original.get("identification", {}).get("board-id") != "ea4c":
        raise ValueError("Only the original ea4c board profile is supported")
    if "lo" not in interfaces:
        raise ValueError("Board profile requires its loopback interface")
    switches = original.get("switches", [])
    if len(switches) != 1 or switches[0].get("id") != "0" or switches[0].get("driver") != "cpss":
        raise ValueError("Expected the ea4c single CPSS switch descriptor")
    cpu_ports = switches[0].get("cpu-ports", [])
    if cpu_ports != [{"interface": {"id": "switch0"}, "cpu-port": 10}]:
        raise ValueError("Expected the ea4c switch0 CPU-port descriptor")
    if original.get("wan_ports") != [{"id": "wan0", "interface": "eth8"},
                                      {"id": "wan1", "interface": "eth12"}]:
        raise ValueError("Expected original ea4c WAN numbering")
    capabilities = original.get("capabilities", {})
    if not any(item.get("udapi-type") == "switch" for item in capabilities.get("interfaces", [])):
        raise ValueError("Expected the original switch capability")

    board = deepcopy(original)
    board["capabilities"]["hardware-offload-mode"] = "not_supported"
    board["switches"][0]["edge-ports"] = []
    board["interfaces"] = [deepcopy(interfaces["lo"])]
    board["interfaces"].extend(
        {"identification": {"init-type": "ethernet", "udapi-type": "ethernet",
                            "id": name, "media": "GE"}}
        for name in NATIVE_INTERFACES
    )
    board["interfaces"].append({
        "identification": {"init-type": "bridge", "udapi-type": "switch", "id": "switch0"},
        "bridge": {"interfaces": []},
    })
    for name in ("temperatures", "fan-speeds", "sfp-outlets"):
        board.setdefault("descriptors", {})[name] = []
    return board


def transform_state(original):
    """Copy an original default/fallback state, replacing the ASIC LAN topology.

    Preserve all service, firewall, NAT, addressing and WAN configuration.
    This is an initial firmware-default conversion, not a controller provisioning
    translator for arbitrary later VLAN/switch configurations.
    """
    interfaces = _interfaces(original)
    if "br0" not in interfaces or not isinstance(interfaces["br0"].get("bridge"), dict):
        raise ValueError("Expected the original br0 LAN bridge")
    state = deepcopy(original)
    state["interfaces"] = [item for item in state["interfaces"]
                           if not item["identification"]["id"].startswith("switch")]
    for interface in state["interfaces"]:
        name = interface["identification"]["id"]
        if name in NATIVE_INTERFACES:
            interface.pop("ethernet", None)
        elif name == "br0":
            interface["bridge"]["interfaces"] = [{"id": name} for name in LAN_INTERFACES]
    return state
