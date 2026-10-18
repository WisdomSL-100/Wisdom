from typing import Dict, List, Sequence

import numpy as np
from sklearn.ensemble import IsolationForest


FEATURE_NAMES = (
    "active_dtc_count",
    "security_unlocked",
    "uds_session_deviation",
    "messages_sent_log",
    "tx_generated_log",
    "tx_delivery_gap",
    "rx_acceptance_gap",
    "security_event_count_log",
    "behavior_variation",
    "ids_flood_event_count_log",
    "ids_timing_violation_count_log",
    "ids_malformed_data_count_log",
    "ids_range_violation_count_log",
    "ids_message_id_mismatch_count_log",
    "ids_authentication_failure_count_log",
    "ids_freshness_failure_count_log",
    "ids_replay_failure_count_log",
    "ids_secure_flash_failure_count_log",
    "ids_security_access_failure_count_log",
    "ids_route_policy_bypass_count_log",
    "ids_diagnostic_access_bypass_count_log",
    "ids_firmware_signature_bypass_count_log",
    "ids_downgrade_protection_bypass_count_log",
    "ids_logging_bypass_count_log",
    "software_profile_security_access_required_enabled",
    "software_profile_message_authentication_enabled",
    "software_profile_replay_protection_enabled",
    "software_profile_freshness_protection_enabled",
    "software_profile_rate_limiting_enabled",
    "software_profile_timing_validation_enabled",
    "software_profile_range_validation_enabled",
    "software_profile_message_id_validation_enabled",
    "software_profile_diagnostic_access_control_enabled",
    "software_profile_zonal_segmentation_enabled",
    "software_profile_firmware_signature_required_enabled",
    "software_profile_anti_downgrade_enabled",
    "software_profile_ids_logging_enabled",
)


def _bounded_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return min(1.0, max(0.0, (denominator - numerator) / denominator))


def make_node_features(
    diagnostic: Dict[str, object],
    behavior: Dict[str, object],
    security_event_count: int,
) -> List[float]:
    """Convert private node records into the fixed numeric model feature vector."""
    tx_generated = max(0, int(behavior.get("tx_generated", 0) or 0))
    tx_delivered = max(0, int(behavior.get("tx_delivered", 0) or 0))
    rx_accepted = max(0, int(behavior.get("rx_accepted", 0) or 0))
    uds_session = diagnostic.get("uds_session", 1)

    return [
        float(len(diagnostic.get("active_dtcs", []))),
        float(bool(diagnostic.get("security_unlocked", False))),
        float(uds_session != 1),
        float(np.log1p(max(0, int(diagnostic.get("messages_sent", 0) or 0)))),
        float(np.log1p(tx_generated)),
        _bounded_ratio(tx_delivered, tx_generated),
        _bounded_ratio(rx_accepted, tx_delivered),
        float(np.log1p(max(0, security_event_count))),
        float(behavior.get("behavior_state") != "within_declared_contract"),
        *(
            float(np.log1p(max(0, int(behavior.get(name, 0) or 0))))
            for name in (
                "ids_flood_event_count",
                "ids_timing_violation_count",
                "ids_malformed_data_count",
                "ids_range_violation_count",
                "ids_message_id_mismatch_count",
                "ids_authentication_failure_count",
                "ids_freshness_failure_count",
                "ids_replay_failure_count",
                "ids_secure_flash_failure_count",
                "ids_security_access_failure_count",
                "ids_route_policy_bypass_count",
                "ids_diagnostic_access_bypass_count",
                "ids_firmware_signature_bypass_count",
                "ids_downgrade_protection_bypass_count",
                "ids_logging_bypass_count",
            )
        ),
        *(
            float(behavior.get(f"software_profile_{name}_enabled", True))
            for name in (
                "security_access_required",
                "message_authentication",
                "replay_protection",
                "freshness_protection",
                "rate_limiting",
                "timing_validation",
                "range_validation",
                "message_id_validation",
                "diagnostic_access_control",
                "zonal_segmentation",
                "firmware_signature_required",
                "anti_downgrade",
                "ids_logging",
            )
        ),
    ]


class BehaviorModelSuite:
    def __init__(self) -> None:
        self.isolation_forest: IsolationForest | None = None
        self._baseline_decisions = np.array([], dtype=float)
        self._baseline_center = np.array([], dtype=float)
        self._baseline_scale = np.array([], dtype=float)
        self._baseline_sample_count = 0

    def _fit_isolation_forest(self, baseline_features: np.ndarray) -> None:
        if len(baseline_features) == 0:
            return
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,
        )
        self.isolation_forest.fit(baseline_features)
        self._baseline_sample_count = len(baseline_features)
        self._baseline_center = np.mean(baseline_features, axis=0)
        self._baseline_scale = np.maximum(
            np.std(baseline_features, axis=0), 0.25
        )
        self._baseline_decisions = self.isolation_forest.decision_function(
            baseline_features
        )

    def baseline_training_summary(self) -> Dict[str, str | int]:
        return {
            "algorithm": "IsolationForest",
            "training_phase": "before_attack_observed_network_baseline",
            "training_node_count": self._baseline_sample_count,
            "feature_count": len(FEATURE_NAMES),
            "synthetic_training_samples": 0,
            "status": "trained" if self.isolation_forest is not None else "unavailable",
        }

    def _isolation_scores(self, features: np.ndarray) -> np.ndarray:
        if self.isolation_forest is None:
            return np.zeros(len(features), dtype=float)

        decisions = self.isolation_forest.decision_function(features)
        if len(self._baseline_decisions) == 0:
            return np.zeros(len(features), dtype=float)

        spread = float(np.std(self._baseline_decisions))
        if spread < 1e-9:
            threshold = float(np.mean(self._baseline_decisions))
            isolation_scores = np.where(
                decisions < threshold - 1e-9, 1.0, 0.0
            )
        else:
            threshold = float(np.percentile(self._baseline_decisions, 10))
            normalized = np.clip(
                (threshold - decisions) / (2.0 * spread), -30, 30
            )
            isolation_scores = 1.0 / (1.0 + np.exp(-normalized))

        # Small, low-variance baselines can produce nearly identical tree
        # scores even for changed features. Calibrate deviations against the
        # observed baseline so those cases remain visible without synthetic
        # training samples.
        standardized_deviation = np.max(
            np.abs((features - self._baseline_center) / self._baseline_scale),
            axis=1,
        )
        baseline_deviation_scores = 1.0 - np.exp(
            -standardized_deviation / 3.0
        )
        return np.maximum(isolation_scores, baseline_deviation_scores)

    def score_nodes(
        self, node_features: Dict[str, Sequence[float]]
    ) -> Dict[str, float]:
        if not node_features:
            return {}

        node_ids = list(node_features)
        matrix = np.asarray([node_features[node_id] for node_id in node_ids], dtype=float)
        if self.isolation_forest is None:
            self._fit_isolation_forest(matrix)

        scores = self._isolation_scores(matrix)
        return {
            node_id: float(score)
            for node_id, score in zip(node_ids, scores)
        }

    def score(
        self, node_features: Sequence[Sequence[float]]
    ) -> Dict[str, float | int]:
        if len(node_features) == 0:
            return {
                "isolation_forest_mean_anomaly_score": 0.0,
                "isolation_forest_max_anomaly_score": 0.0,
                "isolation_forest_deviation_node_count": 0,
            }

        node_scores = self.score_nodes(
            {str(index): features for index, features in enumerate(node_features)}
        )
        isolation_scores = np.asarray(list(node_scores.values()), dtype=float)
        max_isolation = float(np.max(isolation_scores))

        return {
            "isolation_forest_mean_anomaly_score": round(
                float(np.mean(isolation_scores)), 3
            ),
            "isolation_forest_max_anomaly_score": round(max_isolation, 3),
            "isolation_forest_deviation_node_count": int(
                np.sum(isolation_scores >= 0.65)
            ),
        }
