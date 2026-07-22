from registry import Registry
from typing import Protocol, TYPE_CHECKING, Callable, cast
from dataclasses import dataclass
import secrets
from hashlib import sha256 as _sha256

if TYPE_CHECKING:
    from main import Server
    from proto_algorithms.collection import AlgoCollection


class InputFunc(Protocol):
    __name__: str

    def __call__(self, server: Server[AlgoCollection]): ...


@dataclass
class Metadata:
    proto_name: bytes


class Algorithm(InputFunc, Metadata):
    pass


registry: Registry[InputFunc, Algorithm, Metadata] = Registry()


def pow_mod(g: int, x: int, p: int):
    ans = 1
    b = 1 << x.bit_length()
    while b:
        ans *= ans
        ans %= p
        if x & b:
            ans *= g
            ans %= p
        b >>= 1
    return ans


def make_key(
    HASH: Callable[[bytes], bytes], KH: bytes, X: bytes, sid: bytes, length: int
):
    ans = HASH(KH + X + sid)
    while len(ans) < length:
        next_K = HASH(KH + ans)
        ans += next_K
    return ans[:length]


def sha256(data: bytes) -> bytes:
    return _sha256(data).digest()


@registry.register(Metadata(proto_name=b"diffie-hellman-group14-sha256"))
def dh_g14_sha256(server: Server[AlgoCollection]):
    from messages.kex import KexDHInit, KexDHReply
    from messages.primitives import Mpint, String

    p = 0xFFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AACAA68_FFFFFFFF_FFFFFFFF
    g = 2
    q = p - 1
    high = q - 1
    low = 1
    x = secrets.randbelow(high - low) + low
    e = pow_mod(g, x, p)

    server.send(KexDHInit.build(e))
    server_payload = cast(KexDHReply,server.recv())

    # TODO: check if public key is valid

    K = Mpint(pow_mod(server_payload.f.num, x, p))
    server.K=K
    H = sha256(
        String.build(server.client_meta.ident_string)
        + String.build(server.ident_string)
        + String.build(server.I_C.to_bytes())
        + String.build(server.I_S.to_bytes())
        + server_payload.public_key
        + Mpint(e)
        + server_payload.f
        + K
    )
    if not server.session_id:
        server.session_id = H

    server.IV_ctos = sha256(K + H + b"A" + server.session_id)[
        : server.algos.encryption_ctos.block_size
    ]
    server.IV_stoc = sha256(K + H + b"B" + server.session_id)[
        : server.algos.encryption_stoc.block_size
    ]
    server.encryption_key_ctos = make_key(
        sha256, K + H, b"C", server.session_id, server.algos.encryption_ctos.block_size
    )
    server.encryption_key_stoc = make_key(
        sha256, K + H, b"D", server.session_id, server.algos.encryption_stoc.block_size
    )
    server.integrity_key_ctos = make_key(
        sha256, K + H, b"E", server.session_id, server.algos.mac_ctos.key_len
    )
    server.integrity_key_stoc = make_key(
        sha256, K + H, b"F", server.session_id, server.algos.mac_stoc.key_len
    )
