import psutil


def collect_network_connections() -> list[dict]:
    """Collect currently active network connections."""
    connections = []

    for connection in psutil.net_connections(kind="inet"):
        local_address = connection.laddr
        remote_address = connection.raddr

        connections.append(
            {
                "family": str(connection.family),
                "type": str(connection.type),
                "status": connection.status,
                "pid": connection.pid,
                "local_address": (
                    f"{local_address.ip}:{local_address.port}"
                    if local_address
                    else None
                ),
                "remote_address": (
                    f"{remote_address.ip}:{remote_address.port}"
                    if remote_address
                    else None
                ),
            }
        )

    return connections