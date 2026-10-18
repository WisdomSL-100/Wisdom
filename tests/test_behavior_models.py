import pathlib
import sys
import unittest


CENTRAL_DIR = pathlib.Path(__file__).resolve().parents[1] / "vehicle-central-compute"
sys.path.insert(0, str(CENTRAL_DIR))

from behavior_analysis.models import (
    FEATURE_NAMES,
    BehaviorModelSuite,
    make_node_features,
)


class BehaviorModelTests(unittest.TestCase):
    def test_baseline_isolation_forest_scores_post_scan_deviations(self):
        models = BehaviorModelSuite()
        baseline = [
            [0, 0, 0, 2.4, 2.4, 0, 0, 0, 0, *([0] * (len(FEATURE_NAMES) - 9))],
            [0, 0, 0, 2.7, 2.7, 0, 0, 0, 0, *([0] * (len(FEATURE_NAMES) - 9))],
            [0, 0, 0, 2.9, 2.9, 0, 0, 0, 0, *([0] * (len(FEATURE_NAMES) - 9))],
            [0, 0, 0, 3.1, 3.1, 0, 0, 0, 0, *([0] * (len(FEATURE_NAMES) - 9))],
        ]
        before = models.score(baseline)
        after = models.score(
            [
                [
                    5,
                    1,
                    1,
                    2.4,
                    2.4,
                    1,
                    1,
                    2.2,
                    1,
                    *([0] * (len(FEATURE_NAMES) - 9)),
                ],
                *baseline[1:],
            ]
        )

        self.assertGreater(
            after["isolation_forest_max_anomaly_score"],
            before["isolation_forest_max_anomaly_score"],
        )
        self.assertEqual(after["isolation_forest_deviation_node_count"], 1)
        self.assertEqual(models.baseline_training_summary()["synthetic_training_samples"], 0)

    def test_constant_observed_baseline_still_scores_changed_features(self):
        models = BehaviorModelSuite()
        baseline = [[0.0] * len(FEATURE_NAMES) for _ in range(4)]

        before = models.score(baseline)
        changed = [0.0] * len(FEATURE_NAMES)
        changed[1] = 1
        after = models.score([changed, *baseline[1:]])

        self.assertGreater(
            after["isolation_forest_max_anomaly_score"],
            before["isolation_forest_max_anomaly_score"],
        )
        self.assertEqual(after["isolation_forest_deviation_node_count"], 1)

    def test_ids_counters_are_included_in_each_node_model_feature_vector(self):
        behavior = {
            "tx_generated": 10,
            "tx_delivered": 10,
            "rx_accepted": 10,
            "behavior_state": "within_declared_contract",
            "ids_flood_event_count": 2,
            "ids_freshness_failure_count": 1,
            "ids_diagnostic_access_bypass_count": 1,
            "ids_firmware_signature_bypass_count": 1,
            "software_profile_message_authentication_enabled": False,
        }

        features = make_node_features({}, behavior, 3)

        self.assertEqual(len(features), len(FEATURE_NAMES))
        self.assertGreater(features[FEATURE_NAMES.index("ids_flood_event_count_log")], 0)
        self.assertGreater(features[FEATURE_NAMES.index("ids_freshness_failure_count_log")], 0)
        self.assertGreater(
            features[FEATURE_NAMES.index("ids_diagnostic_access_bypass_count_log")],
            0,
        )
        self.assertGreater(
            features[FEATURE_NAMES.index("ids_firmware_signature_bypass_count_log")],
            0,
        )
        self.assertEqual(
            features[
                FEATURE_NAMES.index("software_profile_message_authentication_enabled")
            ],
            0.0,
        )

    def test_node_scores_identify_only_the_node_with_changed_features(self):
        models = BehaviorModelSuite()
        baseline = {
            f"node-{index}": [0.0] * len(FEATURE_NAMES)
            for index in range(4)
        }
        models.score_nodes(baseline)

        changed = dict(baseline)
        changed["node-2"] = [0.0] * len(FEATURE_NAMES)
        changed["node-2"][0] = 5.0

        scores = models.score_nodes(changed)

        self.assertEqual(set(scores), set(baseline))
        self.assertGreater(scores["node-2"], scores["node-0"])


if __name__ == "__main__":
    unittest.main()
