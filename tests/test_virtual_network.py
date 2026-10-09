from copy import deepcopy
import unittest

from virtualization.network import generate_board, transform_state


def board_fixture():
    return {
        "identification": {"board-id": "ea4c", "model-short": "UDMEA4C"},
        "capabilities": {"hardware-offload-mode": "cm", "max-networks": 500,
                         "interfaces": [{"udapi-type": "switch", "id": "^switch[0-9]+$"}]},
        "switches": [{"id": "0", "driver": "cpss", "builtin-vlan": 4085,
                      "cpu-ports": [{"interface": {"id": "switch0"}, "cpu-port": 10}],
                      "edge-ports": [{"interface": {"id": "eth2"}, "edge-port": 0, "cpu-port": 10}]}],
        "interfaces": [{"identification": {"id": "lo", "init-type": "ethernet", "udapi-type": "loopback"}}]
                      + [{"identification": {"id": f"eth{i}", "init-type": "vlan",
                                             "alias": f"hardware{i}", "link-manager": "cpss-shim"}}
                         for i in range(14)],
        "wan_ports": [{"id": "wan0", "interface": "eth8"}, {"id": "wan1", "interface": "eth12"}],
        "descriptors": {"storage": [{"id": "original-storage"}], "temperatures": [{"id": "asic"}]},
    }


def state_fixture():
    return {
        "version": 48,
        "interfaces": [
            {"identification": {"id": f"eth{i}", "type": "ethernet"},
             "status": {"enabled": True}, "ethernet": {"speed": "hardware-specific"}}
            for i in range(14)
        ] + [
            {"identification": {"id": "switch0"}},
            {"identification": {"id": "switch0.1"}},
            {"identification": {"id": "br0"}, "addresses": ["192.168.1.1/24"],
             "bridge": {"interfaces": [{"id": "eth0"}, {"id": "eth1"}, {"id": "eth13"}, {"id": "switch0.1"}]}}
        ],
        "services": {"dhcp-server": {"enabled": True}},
        "firewall/filter": [{"id": "wan-policy", "action": "drop"}],
        "firewall/nat": [{"id": "original-masquerade"}],
        "system": {"hostname": "fixture"},
    }


class VirtualNetworkTests(unittest.TestCase):
    def test_runtime_switch_map_has_one_cpu_interface_with_no_asic_ports(self):
        original = board_fixture()
        snapshot = deepcopy(original)
        board = generate_board(original)
        self.assertEqual(original, snapshot)
        # UDAPI builds its runtime switch map from these CPU entries. A switch
        # object without one caused the observed fatal get_switch_id exception.
        cpu_ids = [port["interface"]["id"] for switch in board["switches"] for port in switch["cpu-ports"]]
        self.assertEqual(cpu_ids, ["switch0"])
        interfaces = {item["identification"]["id"]: item for item in board["interfaces"]}
        self.assertEqual(interfaces["switch0"]["identification"]["init-type"], "bridge")
        self.assertEqual(interfaces["switch0"]["bridge"]["interfaces"], [])
        self.assertEqual(board["switches"][0]["edge-ports"], [])
        for index in range(14):
            identification = interfaces[f"eth{index}"]["identification"]
            self.assertEqual(identification["init-type"], "ethernet")
            self.assertNotIn("alias", identification)
            self.assertNotIn("link-manager", identification)
        self.assertEqual(board["capabilities"]["hardware-offload-mode"], "not_supported")
        self.assertEqual(board["descriptors"]["storage"], original["descriptors"]["storage"])

    def test_lan_excludes_both_wans_and_preserves_firewall_and_addressing(self):
        original = state_fixture()
        original["interfaces"][8]["addresses"] = ["dhcp"]
        snapshot = deepcopy(original)
        state = transform_state(original)
        self.assertEqual(original, snapshot)
        by_id = {item["identification"]["id"]: item for item in state["interfaces"]}
        members = {item["id"] for item in by_id["br0"]["bridge"]["interfaces"]}
        self.assertEqual(members, {f"eth{i}" for i in range(14)} - {"eth8", "eth12"})
        self.assertFalse(any(name.startswith("switch") for name in by_id))
        self.assertEqual(by_id["br0"]["addresses"], ["192.168.1.1/24"])
        self.assertEqual(by_id["eth8"]["addresses"], ["dhcp"])
        for key in original.keys() - {"interfaces"}:
            self.assertEqual(state[key], original[key])
        state["services"]["dhcp-server"]["enabled"] = False
        self.assertTrue(original["services"]["dhcp-server"]["enabled"])

    def test_already_transformed_profiles_are_stable(self):
        board = generate_board(board_fixture())
        state = transform_state(state_fixture())
        self.assertEqual(generate_board(board), board)
        self.assertEqual(transform_state(state), state)

    def test_wrong_model_or_missing_cpu_descriptor_is_rejected(self):
        board = board_fixture()
        board["identification"]["board-id"] = "other"
        with self.assertRaisesRegex(ValueError, "ea4c"):
            generate_board(board)
        board = board_fixture()
        board["switches"][0]["cpu-ports"] = []
        with self.assertRaisesRegex(ValueError, "CPU-port"):
            generate_board(board)

    def test_missing_or_duplicate_ports_cannot_silently_change_mapping(self):
        for transform, fixture in [(generate_board, board_fixture), (transform_state, state_fixture)]:
            document = fixture()
            document["interfaces"].append(deepcopy(document["interfaces"][0]))
            with self.subTest(transform=transform.__name__), self.assertRaisesRegex(ValueError, "Duplicate"):
                transform(document)
            document = fixture()
            document["interfaces"] = [item for item in document["interfaces"] if item["identification"]["id"] != "eth8"]
            with self.subTest(transform=transform.__name__), self.assertRaisesRegex(ValueError, "eth0 through eth13"):
                transform(document)


if __name__ == "__main__":
    unittest.main()
