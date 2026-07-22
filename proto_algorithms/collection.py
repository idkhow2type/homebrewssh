from typing import TYPE_CHECKING
from dataclasses import dataclass, fields

if TYPE_CHECKING:
    from messages.kex import KexInit
    import proto_algorithms


class DefaultAlgoCollection:
    kex = None
    server_host_key = None
    encryption_ctos = None
    encryption_stoc = None
    mac_ctos = None
    mac_stoc = None
    compression_ctos = None
    compression_stoc = None
    languages_ctos = None
    languages_stoc = None


@dataclass
class AlgoCollection:
    kex: proto_algorithms.kex.Algorithm
    server_host_key: proto_algorithms.server_host_key.Algorithm
    encryption_ctos: proto_algorithms.encryption_ctos.Algorithm
    encryption_stoc: proto_algorithms.encryption_stoc.Algorithm
    mac_ctos: proto_algorithms.mac_ctos.Algorithm
    mac_stoc: proto_algorithms.mac_stoc.Algorithm
    compression_ctos: proto_algorithms.compression_ctos.Algorithm
    compression_stoc: proto_algorithms.compression_stoc.Algorithm
    languages_ctos: proto_algorithms.languages_ctos.Algorithm
    languages_stoc: proto_algorithms.languages_stoc.Algorithm

    def __init__(self, client_payload: KexInit, server_payload: KexInit) -> None:
        import proto_algorithms

        for field in fields(AlgoCollection):
            for algo in client_payload.name_lists[field.name].names:
                if algo in server_payload.name_lists[field.name].names:
                    setattr(
                        self,
                        field.name,
                        getattr(proto_algorithms, field.name).registry["proto_name"][
                            algo
                        ],
                    )
