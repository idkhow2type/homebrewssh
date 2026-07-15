from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from messages.packet import AlgoExchange
    from messages.primitives import NameList
    import proto_algorithms


class AlgoCollection:
    kex_algorithms: proto_algorithms.kex.Algorithm
    server_host_key_algorithms: proto_algorithms.server_host_key.Algorithm
    encryption_algorithms_client_to_server: proto_algorithms.encryption.Algorithm
    encryption_algorithms_server_to_client: proto_algorithms.encryption.Algorithm
    mac_algorithms_client_to_server: proto_algorithms.mac.Algorithm
    mac_algorithms_server_to_client: proto_algorithms.mac.Algorithm
    compression_algorithms_client_to_server: proto_algorithms.compression.Algorithm
    compression_algorithms_server_to_client: proto_algorithms.compression.Algorithm
    languages_client_to_server: proto_algorithms.language.Algorithm
    languages_server_to_client: proto_algorithms.language.Algorithm

    def __init__(
        self, client_payload: AlgoExchange, server_payload: AlgoExchange
    ) -> None:
        self._set(
            "kex_algorithms",
            "kex",
            client_payload.kex_algorithms,
            server_payload.kex_algorithms,
        )
        self._set(
            "server_host_key_algorithms",
            "server_host_key",
            client_payload.server_host_key_algorithms,
            server_payload.server_host_key_algorithms,
        )
        self._set(
            "encryption_algorithms_client_to_server",
            "encryption",
            client_payload.encryption_algorithms_client_to_server,
            server_payload.encryption_algorithms_client_to_server,
        )
        self._set(
            "encryption_algorithms_server_to_client",
            "encryption",
            client_payload.encryption_algorithms_server_to_client,
            server_payload.encryption_algorithms_server_to_client,
        )
        self._set(
            "mac_algorithms_client_to_server",
            "mac",
            client_payload.mac_algorithms_client_to_server,
            server_payload.mac_algorithms_client_to_server,
        )
        self._set(
            "mac_algorithms_server_to_client",
            "mac",
            client_payload.mac_algorithms_server_to_client,
            server_payload.mac_algorithms_server_to_client,
        )
        self._set(
            "compression_algorithms_client_to_server",
            "compression",
            client_payload.compression_algorithms_client_to_server,
            client_payload.compression_algorithms_client_to_server,
        )
        self._set(
            "compression_algorithms_server_to_client",
            "compression",
            client_payload.compression_algorithms_server_to_client,
            client_payload.compression_algorithms_server_to_client,
        )
        self._set(
            "languages_client_to_server",
            "language",
            client_payload.languages_client_to_server,
            server_payload.languages_client_to_server,
        )
        self._set(
            "languages_server_to_client",
            "language",
            client_payload.languages_server_to_client,
            client_payload.languages_server_to_client,
        )

    def _set(
        self,
        field: str,
        registry: str,
        client_list: NameList,
        server_list: NameList,
    ):
        import proto_algorithms
        for algo in client_list.names:
            if algo in server_list.names:
                setattr(self, field, getattr(proto_algorithms, registry).registry["proto_name"][algo])
