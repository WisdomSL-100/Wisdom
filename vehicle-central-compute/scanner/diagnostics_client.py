from typing import Any, Callable, Dict


def request_sovd_diagnostics(
    network_request: Callable[..., Dict[str, Any]], payload: Dict[str, Any]
) -> Dict[str, Any]:
    return network_request("sovd_request", **payload)


def request_signal(
    network_request: Callable[..., Dict[str, Any]], payload: Dict[str, Any]
) -> Dict[str, Any]:
    return network_request(
        "someip_request",
        target_node_id=payload.get("target_node_id"),
        signal_name=payload.get("signal_name"),
        requester_node_id=payload.get("requester_node_id", "hpc-vehicle"),
    )
