import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any


SIMULATOR_ROOT = Path(__file__).resolve().parents[1] / "vehicle-network_Simulator"
sys.path.insert(0, str(SIMULATOR_ROOT))

from ecus.ecu_adas_radar import AdasRadarECU
from ecus.ecu_battery import BatteryManagementECU
from ecus.ecu_body_front import FrontBodyECU
from ecus.ecu_body_rear import RearBodyECU
from ecus.ecu_front_camera import FrontCameraECU
from ecus.ecu_powertrain import PowertrainECU
from ecus.ecu_rear_camera import RearCameraECU
from ecus.ecu_telematics import TelematicsECU
from ecus.hpc_adas import AdasHPC
from ecus.hpc_cockpit import CockpitHPC
from ecus.hpc_vehicle_node import VehicleHPC
from ecus.zcu_front_left import ZcuFrontLeft
from ecus.zcu_front_right import ZcuFrontRight
from ecus.zcu_rear_left import ZcuRearLeft
from ecus.zcu_rear_right import ZcuRearRight


NODE_TYPES = (
    VehicleHPC,
    AdasHPC,
    CockpitHPC,
    ZcuFrontLeft,
    ZcuFrontRight,
    ZcuRearLeft,
    ZcuRearRight,
    PowertrainECU,
    BatteryManagementECU,
    AdasRadarECU,
    FrontCameraECU,
    RearCameraECU,
    FrontBodyECU,
    RearBodyECU,
    TelematicsECU,
)
PROFILE_CONTROLS = (
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
WEAKNESS_PACKAGE_NAMES = {
    "security_access_required": ("W3", "Diagnostic access control"),
    "message_authentication": ("W4", "Secure communication integrity"),
    "replay_protection": ("W1", "Replay validation"),
    "freshness_protection": ("W1", "Freshness validation"),
    "rate_limiting": ("W5", "Traffic rate limiting / DoS resilience"),
    "timing_validation": ("W5", "Timing / DoS resilience"),
    "range_validation": ("W6", "Data range validation"),
    "message_id_validation": ("W2", "Message ID validation"),
    "diagnostic_access_control": ("W3", "Unauthorized diagnostic access"),
    "zonal_segmentation": ("W7", "Gateway zonal segmentation"),
    "firmware_signature_required": ("W8", "Firmware signature verification"),
    "anti_downgrade": ("W9", "Firmware downgrade protection"),
    "ids_logging": ("W10", "IDS detection / audit logging"),
}
OUTPUT_ROOT = Path(__file__).resolve().parent
BASELINE_DIR = OUTPUT_ROOT / "BaselineSecure Packages"
ATTACK_DIR = OUTPUT_ROOT / "Attack Prone Packages"
PACKAGE_VERSION = "SIM-2.0.0"
IMAGE_PREFIX = b"SIMULATED-OTA-FIRMWARE-v1:"


def package_display_name(profile_name: str, node_id: str) -> str:
    weakness = WEAKNESS_PACKAGE_NAMES.get(profile_name)
    if weakness is None:
        return f"BASELINE - Secure profile - {node_id}"
    weakness_id, description = weakness
    return f"{weakness_id} - {description} - {node_id}"


def _node_role(node_type: type) -> str:
    return getattr(node_type, "ROLE", "ecu")


def _node_source_and_route(
    node_type: type, node_types_by_id: dict[str, type]
) -> tuple[str, str | None]:
    node_id = node_type.NODE_ID
    role = _node_role(node_type)
    trusted_sources = tuple(getattr(node_type, "TRUSTED_SOURCES", ()))
    connected_to = getattr(node_type, "CONNECTED_TO", None)
    connected = (
        tuple(connected_to)
        if isinstance(connected_to, (list, tuple, set))
        else (connected_to,)
    )
    hpc_sources = [
        source_id
        for source_id in trusted_sources
        if source_id in node_types_by_id
        and _node_role(node_types_by_id[source_id]) == "hpc"
    ]

    if role == "hpc":
        candidates = hpc_sources
        zcu_id = None
    elif role == "zone_controller":
        candidates = [
            source_id
            for source_id in connected
            if isinstance(source_id, str)
            and source_id in node_types_by_id
            and _node_role(node_types_by_id[source_id]) == "hpc"
            and source_id in trusted_sources
        ]
        zcu_id = None
    else:
        parent_id = connected[0] if connected else None
        parent = node_types_by_id.get(parent_id) if isinstance(parent_id, str) else None
        if parent is not None and _node_role(parent) == "zone_controller":
            zcu_id = parent_id
            candidates = [
                source_id
                for source_id in trusted_sources
                if source_id in node_types_by_id
                and _node_role(node_types_by_id[source_id]) == "hpc"
                and source_id in getattr(parent, "CONNECTED_TO", ())
            ]
        else:
            zcu_id = None
            candidates = [
                source_id
                for source_id in hpc_sources
                if source_id in connected
            ]

    if not candidates:
        raise ValueError(f"No valid trusted HPC OTA source for {node_id}")
    return sorted(candidates)[0], zcu_id


def _firmware_image(node_id: str, profile_name: str) -> bytes:
    image_digest = hashlib.sha256(
        f"{node_id}:{profile_name}:{PACKAGE_VERSION}".encode("utf-8")
    ).digest()
    return IMAGE_PREFIX + image_digest


def build_package(
    node_type: type,
    profile_name: str,
    profile: dict[str, bool],
    node_types_by_id: dict[str, type],
) -> dict[str, Any]:
    node_id = node_type.NODE_ID
    source_id, zcu_id = _node_source_and_route(node_type, node_types_by_id)
    image = _firmware_image(node_id, profile_name)
    manifest: dict[str, Any] = {
        "ecu_id": node_id,
        "version": PACKAGE_VERSION,
        "image_size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "software_profile": profile,
    }
    signed_data = {
        "ecu_id": manifest["ecu_id"],
        "version": manifest["version"],
        "image_size": manifest["image_size"],
        "sha256": manifest["sha256"],
        "software_profile": manifest["software_profile"],
    }
    signed = json.dumps(
        signed_data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest["signature"] = hmac.new(
        f"firmware-signature:{node_id}".encode("utf-8"),
        signed,
        hashlib.sha256,
    ).hexdigest()

    package: dict[str, Any] = {
        "package_name": package_display_name(profile_name, node_id),
        "source_hpc_id": source_id,
        "target_ecu_id": node_id,
        "image_hex": image.hex(),
        "manifest": manifest,
    }
    if zcu_id is not None:
        package["zcu_id"] = zcu_id
    return package


def _write_package(path: Path, package: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(package, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def generate_packages() -> int:
    node_types_by_id = {node_type.NODE_ID: node_type for node_type in NODE_TYPES}
    package_count = 0
    secure_profile = {control: True for control in PROFILE_CONTROLS}

    for node_type in NODE_TYPES:
        package = build_package(
            node_type, "baseline-secure", secure_profile, node_types_by_id
        )
        _write_package(BASELINE_DIR / f"{node_type.NODE_ID}.json", package)
        package_count += 1

    for control in PROFILE_CONTROLS:
        profile_dir = ATTACK_DIR / control
        for node_type in NODE_TYPES:
            profile = dict(secure_profile)
            profile[control] = False
            package = build_package(
                node_type, control, profile, node_types_by_id
            )
            _write_package(profile_dir / f"{node_type.NODE_ID}.json", package)
            package_count += 1
    return package_count


def validate_packages() -> int:
    node_types_by_id = {node_type.NODE_ID: node_type for node_type in NODE_TYPES}
    expected_paths = {
        BASELINE_DIR / f"{node_type.NODE_ID}.json"
        for node_type in NODE_TYPES
    }
    for control in PROFILE_CONTROLS:
        expected_paths.update(
            ATTACK_DIR / control / f"{node_type.NODE_ID}.json"
            for node_type in NODE_TYPES
        )

    missing = sorted(path for path in expected_paths if not path.is_file())
    if missing:
        raise FileNotFoundError(
            "Missing OTA packages: " + ", ".join(str(path) for path in missing)
        )

    for path in sorted(expected_paths):
        package = json.loads(path.read_text(encoding="utf-8"))
        node_id = package.get("target_ecu_id")
        node_type = node_types_by_id.get(node_id)
        if node_type is None or path.stem != node_id:
            raise ValueError(f"Package target does not match its file: {path}")
        expected_package_name = package_display_name(
            "baseline-secure" if path.is_relative_to(BASELINE_DIR) else path.parent.name,
            node_id,
        )
        if package.get("package_name") != expected_package_name:
            raise ValueError(f"Package name does not match its weakness: {path}")
        expected_source, expected_zcu = _node_source_and_route(
            node_type, node_types_by_id
        )
        if package.get("source_hpc_id") != expected_source:
            raise ValueError(f"Invalid trusted OTA source in {path}")
        if package.get("zcu_id") != expected_zcu:
            raise ValueError(f"Invalid ZCU route in {path}")
        image = bytes.fromhex(package["image_hex"])
        manifest = package["manifest"]
        profile = manifest["software_profile"]
        if len(image) != manifest["image_size"]:
            raise ValueError(f"Image size does not match manifest in {path}")
        if hashlib.sha256(image).hexdigest() != manifest["sha256"]:
            raise ValueError(f"Image digest does not match manifest in {path}")
        expected_profile = {control: True for control in PROFILE_CONTROLS}
        if path.is_relative_to(BASELINE_DIR):
            if profile != expected_profile:
                raise ValueError(f"Baseline package is not hardened: {path}")
        else:
            control = path.parent.name
            expected_profile[control] = False
            if profile != expected_profile:
                raise ValueError(f"Package must disable only {control}: {path}")
        signed_data = {
            key: manifest[key]
            for key in (
                "ecu_id",
                "version",
                "image_size",
                "sha256",
                "software_profile",
            )
        }
        signature_input = json.dumps(
            signed_data, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        expected_signature = hmac.new(
            f"firmware-signature:{node_id}".encode("utf-8"),
            signature_input,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(manifest.get("signature", ""), expected_signature):
            raise ValueError(f"Invalid simulator manifest signature in {path}")
    return len(expected_paths)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and verify simulator-only node OTA packages."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify generated package manifests and profile settings",
    )
    args = parser.parse_args()
    if not args.check:
        count = generate_packages()
        print(f"Generated {count} simulator OTA packages under {OUTPUT_ROOT}")
    count = validate_packages()
    print(f"Validated {count} simulator OTA packages.")


if __name__ == "__main__":
    main()
