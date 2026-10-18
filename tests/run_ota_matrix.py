import argparse
import importlib.util
import json
import os
import pathlib
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Any


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
NETWORK_TEST_PATH = PROJECT_ROOT / "tests" / "test_vehicle_network_socket.py"
PACKAGE_ROOT = PROJECT_ROOT / "ota packages"
BASELINE_ROOT = PACKAGE_ROOT / "BaselineSecure Packages"
ATTACK_ROOT = PACKAGE_ROOT / "Attack Prone Packages"


def _load_network_test_module():
    spec = importlib.util.spec_from_file_location(
        "ota_matrix_vehicle_network_tests", NETWORK_TEST_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the vehicle-network integration fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _package_paths_by_target() -> dict[str, list[pathlib.Path]]:
    packages = sorted(PACKAGE_ROOT.rglob("*.json"))
    grouped: dict[str, list[pathlib.Path]] = {}
    for path in packages:
        package = json.loads(path.read_text(encoding="utf-8"))
        target = package.get("target_ecu_id")
        if not isinstance(target, str) or not target:
            raise ValueError(f"OTA package has no target ECU ID: {path}")
        grouped.setdefault(target, []).append(path)
    if not grouped:
        raise RuntimeError(f"No generated OTA packages found under {PACKAGE_ROOT}")
    return grouped


def _record_failure(
    failures: list[dict[str, Any]],
    *,
    target: str,
    package: str,
    operation: str,
    details: str,
    attack_type: str | None = None,
) -> None:
    failure: dict[str, Any] = {
        "target_node_id": target,
        "package": package,
        "operation": operation,
        "details": details,
    }
    if attack_type is not None:
        failure["attack_type"] = attack_type
    failures.append(failure)


def _refresh_fixture_token(fixture: Any, test_module: Any) -> None:
    secret = os.environ["CENTRAL_SERVICE_JWT_SECRET"]
    fixture.client.environ_base["HTTP_AUTHORIZATION"] = (
        f"Bearer {test_module.cloud_service_token(secret)}"
    )


def _run_target(
    target: str,
    package_paths: list[pathlib.Path],
    selected_attack_types: list[str] | None,
) -> dict[str, Any]:
    network_tests = _load_network_test_module()
    fixture = network_tests.VehicleNetworkSocketTests(
        "test_central_signal_catalog_lists_signals_for_selected_someip_node"
    )
    fixture.setUp()
    failures: list[dict[str, Any]] = []
    flash_count = 0
    scan_count = 0
    weakness_coverage: dict[str, dict[str, int]] = {}
    try:
        central = fixture.central
        client = fixture.client
        from scanner.service import OTA_WEAKNESS_TESTS

        attacks = (
            sorted(central.ATTACK_TYPES)
            if selected_attack_types is None
            else sorted(set(selected_attack_types))
        )
        unknown_attacks = set(attacks) - central.ATTACK_TYPES
        if unknown_attacks:
            raise ValueError(
                "Unsupported attack types: " + ", ".join(sorted(unknown_attacks))
            )
        central.vehicle_network_request(
            "set_vehicle_service_state", service_state="in_service"
        )
        baseline_path = BASELINE_ROOT / f"{target}.json"
        if not baseline_path.is_file():
            raise FileNotFoundError(f"Missing secure baseline for {target}")
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

        for package_path in package_paths:
            package = json.loads(package_path.read_text(encoding="utf-8"))
            relative_path = package_path.relative_to(PACKAGE_ROOT).as_posix()
            if package.get("target_ecu_id") != target:
                raise ValueError(f"Package target does not match its matrix group: {package_path}")

            _refresh_fixture_token(fixture, network_tests)
            flash_response = client.post("/ota/flash", json=package)
            flash_count += 1
            flash_result = flash_response.get_json()
            if (
                flash_response.status_code != 200
                or not isinstance(flash_result, dict)
                or flash_result.get("status") != "completed"
                or flash_result.get("software_profile_activated") is not True
            ):
                _record_failure(
                    failures,
                    target=target,
                    package=relative_path,
                    operation="flash",
                    details=(
                        f"HTTP {flash_response.status_code}: "
                        f"{json.dumps(flash_result, sort_keys=True)}"
                    ),
                )
                continue

            behavior_change = flash_result.get("node_behavior_change", {})
            installed_firmware = (
                behavior_change.get("firmware_after", {})
                if isinstance(behavior_change, dict)
                else {}
            )
            installed_profile = (
                installed_firmware.get("software_profile", {})
                if isinstance(installed_firmware, dict)
                else {}
            )
            expected_profile = package.get("manifest", {}).get(
                "software_profile", {}
            )
            if installed_profile != expected_profile:
                _record_failure(
                    failures,
                    target=target,
                    package=relative_path,
                    operation="flash_profile_verification",
                    details=(
                        f"Expected installed profile {expected_profile!r}; "
                        f"received {installed_profile!r}"
                    ),
                )
                continue

            control = (
                package_path.parent.name
                if package_path.parent.parent == ATTACK_ROOT
                else None
            )
            weakness = OTA_WEAKNESS_TESTS.get(control) if control else None
            weakness_id = weakness[0] if weakness else None
            relevant_attacks = set(weakness[1]) if weakness else set()
            expected_test_ids = sorted(weakness[2]) if weakness else []

            for attack_type in attacks:
                _refresh_fixture_token(fixture, network_tests)
                scan_response = client.post(
                    "/scan/start",
                    json={
                        "attack_type": attack_type,
                        "severity": "low",
                        "duration_seconds": 1,
                        "target_node_ids": [target],
                        "scan_mode": "lab_penetration_test",
                        "run_baseline_checks": False,
                    },
                )
                scan_count += 1
                scan = scan_response.get_json()
                if (
                    scan_response.status_code != 200
                    or not isinstance(scan, dict)
                    or scan.get("status") != "completed"
                ):
                    _record_failure(
                        failures,
                        target=target,
                        package=relative_path,
                        operation="attack_scan",
                        attack_type=attack_type,
                        details=(
                            f"HTTP {scan_response.status_code}: "
                            f"{json.dumps(scan, sort_keys=True)}"
                        ),
                    )
                    continue

                after = scan.get("after_attack", {})
                findings = (
                    after.get("ota_weakness_findings", [])
                    if isinstance(after, dict)
                    else []
                )
                expected_coverage = (
                    "covered"
                    if attack_type in relevant_attacks
                    else "not_covered"
                )
                expected_findings = (
                    [
                        finding
                        for finding in findings
                        if isinstance(finding, dict)
                        and finding.get("weakness_id") == weakness_id
                    ]
                    if weakness_id
                    else []
                )
                valid_finding = (
                    not weakness_id
                    and not findings
                    or len(expected_findings) == 1
                    and expected_findings[0].get("test_coverage")
                    == expected_coverage
                    and expected_findings[0].get("affected_controls")
                    == [control]
                    and expected_findings[0].get("relevant_test_ids")
                    == expected_test_ids
                )
                expected_count = 1 if weakness_id else 0
                if (
                    not isinstance(after, dict)
                    or not valid_finding
                    or after.get("ota_weakness_count") != expected_count
                    or after.get("ota_tested_weakness_count")
                    != (1 if weakness_id and expected_coverage == "covered" else 0)
                ):
                    _record_failure(
                        failures,
                        target=target,
                        package=relative_path,
                        operation="dashboard_weakness_data",
                        attack_type=attack_type,
                        details=(
                            f"Expected {weakness_id or 'no weakness'} with "
                            f"{expected_coverage} coverage; received "
                            f"{json.dumps(after, sort_keys=True)}"
                        ),
                    )

                if weakness_id:
                    coverage = weakness_coverage.setdefault(
                        weakness_id, {"covered": 0, "not_covered": 0}
                    )
                    coverage[expected_coverage] += 1

        _refresh_fixture_token(fixture, network_tests)
        restore_response = client.post("/ota/flash", json=baseline)
        flash_count += 1
        restore_result = restore_response.get_json()
        if (
            restore_response.status_code != 200
            or not isinstance(restore_result, dict)
            or restore_result.get("status") != "completed"
            or restore_result.get("software_profile_activated") is not True
        ):
            _record_failure(
                failures,
                target=target,
                package=f"BaselineSecure Packages/{target}.json",
                operation="restore_baseline",
                details=(
                    f"HTTP {restore_response.status_code}: "
                    f"{json.dumps(restore_result, sort_keys=True)}"
                ),
            )
        return {
            "target_node_id": target,
            "flash_attempts": flash_count,
            "attack_scan_attempts": scan_count,
            "weakness_coverage": weakness_coverage,
            "failures": failures,
        }
    finally:
        fixture.tearDown()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Flash every generated simulator OTA package, test every supported "
            "attack type against its target, and verify dashboard weakness fields."
        )
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=6,
        help="isolated simulator processes to run in parallel (default: 6)",
    )
    parser.add_argument(
        "--report",
        type=pathlib.Path,
        help="optional path for a JSON summary report",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        help="optional target-node subset for a shorter smoke run",
    )
    parser.add_argument(
        "--attacks",
        nargs="+",
        help="optional attack-type subset for a shorter smoke run",
    )
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    packages_by_target = _package_paths_by_target()
    if args.targets:
        unknown_targets = set(args.targets) - packages_by_target.keys()
        if unknown_targets:
            parser.error(
                "unknown target nodes: " + ", ".join(sorted(unknown_targets))
            )
        packages_by_target = {
            target: packages_by_target[target] for target in args.targets
        }
    package_count = sum(map(len, packages_by_target.values()))
    target_results = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                _run_target, target, paths, args.attacks
            ): target
            for target, paths in packages_by_target.items()
        }
        for future in as_completed(futures):
            target = futures[future]
            result = future.result()
            target_results.append(result)
            print(
                f"Completed {target}: "
                f"{result['flash_attempts']} flash attempts, "
                f"{result['attack_scan_attempts']} attack scans, "
                f"{len(result['failures'])} failures",
                flush=True,
            )

    failures = [
        failure
        for result in target_results
        for failure in result["failures"]
    ]
    report = {
        "package_count": package_count,
        "target_count": len(packages_by_target),
        "flash_attempts": sum(
            result["flash_attempts"] for result in target_results
        ),
        "attack_scan_attempts": sum(
            result["attack_scan_attempts"] for result in target_results
        ),
        "failure_count": len(failures),
        "weakness_coverage": {
            weakness_id: {
                key: sum(
                    result["weakness_coverage"].get(weakness_id, {}).get(key, 0)
                    for result in target_results
                )
                for key in ("covered", "not_covered")
            }
            for weakness_id in sorted(
                {
                    weakness_id
                    for result in target_results
                    for weakness_id in result["weakness_coverage"]
                }
            )
        },
        "failures": failures,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.path.insert(0, str(PROJECT_ROOT))
    raise SystemExit(main())
