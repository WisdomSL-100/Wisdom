import pathlib
import sys
import unittest


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "vehicle-network_Simulator"))

from network_service import build_topology


class VehicleTopologyTests(unittest.TestCase):
    def setUp(self):
        self.topology = build_topology()
        self.nodes = {node["id"]: node for node in self.topology["nodes"]}

    def test_topology_contains_all_vehicle_node_roles(self):
        roles = {}
        for node in self.nodes.values():
            roles[node["role"]] = roles.get(node["role"], 0) + 1

        self.assertEqual(len(self.nodes), 15)
        self.assertEqual(roles, {"hpc": 3, "zone_controller": 4, "ecu": 8})
        self.assertNotIn("central-gateway", self.nodes)

    def test_safety_ecus_connect_directly_and_other_ecus_use_their_local_zcu(self):
        safety_domains = {
            "ecu-powertrain": "hpc-vehicle",
            "ecu-battery": "hpc-vehicle",
            "ecu-adas-radar": "hpc-adas",
            "ecu-front-camera": "hpc-adas",
            "ecu-rear-camera": "hpc-adas",
        }
        for node in self.nodes.values():
            if node["role"] != "ecu":
                continue
            parent_id = node["connected_to"]
            self.assertIn(parent_id, self.nodes, node["id"])
            parent = self.nodes[parent_id]
            if node["safety_critical"]:
                self.assertEqual(parent["role"], "hpc", node["id"])
                self.assertEqual(parent_id, safety_domains[node["id"]])
            else:
                self.assertEqual(parent["role"], "zone_controller", node["id"])
                self.assertEqual(parent["zone"], node["zone"], node["id"])

    def test_zone_controllers_link_to_relevant_domain_hpcs(self):
        expected_domains = {
            "zcu-front-left": {"hpc-vehicle", "hpc-adas"},
            "zcu-front-right": {"hpc-vehicle", "hpc-adas", "hpc-cockpit"},
            "zcu-rear-left": {"hpc-vehicle", "hpc-cockpit"},
            "zcu-rear-right": {"hpc-vehicle", "hpc-adas", "hpc-cockpit"},
        }
        for zcu_id, domain_ids in expected_domains.items():
            with self.subTest(zcu=zcu_id):
                zcu = self.nodes[zcu_id]
                self.assertEqual(set(zcu["connected_to"]), domain_ids)
                self.assertTrue(all(self.nodes[node_id]["role"] == "hpc" for node_id in domain_ids))

    def test_vehicle_hpc_is_gateway_and_all_hpcs_share_backbone(self):
        self.assertEqual(set(self.nodes["hpc-vehicle"]["backbone_peers"]), {"hpc-adas", "hpc-cockpit"})
        self.assertEqual(set(self.nodes["hpc-adas"]["backbone_peers"]), {"hpc-vehicle", "hpc-cockpit"})
        self.assertEqual(set(self.nodes["hpc-cockpit"]["backbone_peers"]), {"hpc-vehicle", "hpc-adas"})
        self.assertEqual(self.topology["hpc_vehicle_data"]["aggregator_id"], "hpc-vehicle")
        scanner_link = self.topology["integrations"][0]
        self.assertEqual(scanner_link["source"], "vehicle-network.socket")
        self.assertEqual(scanner_link["target"], "vehicle-central-compute.container")
        self.assertEqual(scanner_link["status"], "implemented_simulated_authenticated_socket")
        self.assertIn("UDS", scanner_link["data"])

    def test_vehicle_hpc_aggregates_all_zone_and_direct_safety_inputs(self):
        aggregate = self.topology["hpc_vehicle_data"]
        self.assertEqual(aggregate["aggregator_id"], "hpc-vehicle")
        self.assertEqual(aggregate["node_count"], 12)
        self.assertEqual(set(aggregate["source_zcu_ids"]), {"zcu-front-left", "zcu-front-right", "zcu-rear-left", "zcu-rear-right"})
        self.assertEqual(set(aggregate["direct_safety_ecu_ids"]), {"ecu-powertrain", "ecu-battery", "ecu-adas-radar", "ecu-front-camera", "ecu-rear-camera"})

    def test_every_vehicle_node_declares_uds_security_and_its_dtcs(self):
        for node in self.nodes.values():
            with self.subTest(node=node["id"]):
                self.assertIn("0x19", node["uds_supported_services"])
                self.assertIn("0x27", node["uds_supported_services"])
                self.assertIn("0x31", node["uds_supported_services"])
                self.assertIn("0x34", node["uds_supported_services"])
                self.assertIn("secure_diagnostics", node["secure_features"])
                self.assertIn("signed_firmware_policy", node["secure_features"])
                self.assertTrue(node["dtc_catalog"])
                self.assertEqual(len(node["message_catalog"]), 30)
                self.assertTrue(all(item["signal_layout"]["bit_length"] == 64 for item in node["message_catalog"]))
                self.assertTrue(node["uds_dids"])
                self.assertTrue(node["uds_rids"])
            self.assertEqual(len({tuple(sorted(node["uds_dids"].items())) for node in self.nodes.values()}), len(self.nodes))
            self.assertEqual(len({tuple(sorted(node["uds_rids"].items())) for node in self.nodes.values()}), len(self.nodes))

    def test_node_message_transports_and_identifiers_match_hierarchy(self):
        ecu_can_ids = []
        controller_services = []
        controller_can_ids = []
        for node in self.nodes.values():
            if node["role"] == "ecu":
                self.assertIn(node["protocol"], {"CAN", "CAN-FD"})
                self.assertIsNone(node["someip_service_id"])
                ecu_can_ids.extend(entry["can_id"] for entry in node["message_catalog"])
            else:
                self.assertIn("SOME/IP", node["protocol"])
                self.assertTrue(node["someip_service_id"])
                controller_services.append(node["message_catalog"][0]["someip_service_id"])
                controller_can_ids.extend(entry["can_control_id"] for entry in node["message_catalog"])
            self.assertEqual(len(node["message_catalog"]), 30)
            self.assertTrue(node["rx_message_catalog"])
        self.assertEqual(len(ecu_can_ids), len(set(ecu_can_ids)))
        self.assertEqual(len(controller_can_ids), len(set(controller_can_ids)))
        self.assertEqual(len(controller_services), len(set(controller_services)))


if __name__ == "__main__":
    unittest.main()
