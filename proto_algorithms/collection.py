from typing import TYPE_CHECKING
from dataclasses import dataclass, field, fields

if TYPE_CHECKING:
    from messages.packet import KexInit
    import proto_algorithms


@dataclass
class AlgoCollection:
    kex: proto_algorithms.kex.Algorithm = field(init=False)
    server_host_key: proto_algorithms.server_host_key.Algorithm = field(init=False)
    encr_ctos: proto_algorithms.encryption_ctos.Algorithm = field(init=False)
    encr_stoc: proto_algorithms.encryption_ctos.Algorithm = field(init=False)
    mac_ctos: proto_algorithms.mac_ctos.Algorithm = field(init=False)
    mac_stoc: proto_algorithms.mac_ctos.Algorithm = field(init=False)
    compression_ctos: proto_algorithms.compression_ctos.Algorithm = field(init=False)
    compression_stoc: proto_algorithms.compression_ctos.Algorithm = field(init=False)
    languages_ctos: proto_algorithms.languages_ctos.Algorithm = field(init=False)
    languages_stoc: proto_algorithms.languages_ctos.Algorithm = field(init=False)

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
