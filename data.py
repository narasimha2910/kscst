from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from utils.convert import b64e, b64d


__all__ = [
    "dump", "ZKParameters", "ZKSignature", "ZKProof", "ZKData"
]


def dump(dc):
    return dc.to_json(separators=(",", ":"))


@dataclass_json
@dataclass
class ZKParameters:
    alg: str                    # Hashing algorithm name
    curve: str                  # Standard Elliptic Curve name to use
    salt: bytes = field(        # Random salt for the state
        metadata=config(encoder=b64e, decoder=b64d),
    )                


@dataclass_json
@dataclass
class ZKSignature:
    params: ZKParameters        # Reference ZK Parameters
    signature: bytes = field(   # The public key derived from your original secret
        metadata=config(encoder=b64e, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZKProof:
    params: ZKParameters        # Reference ZK Parameters
    c: bytes = field(           # The hash of the signed data and random point, R
        metadata=config(encoder=b64e, decoder=b64d),
    )
    m: bytes = field(           # The offset from the secret `r` (`R=r*g`) from c * Hash(secret)
        metadata=config(encoder=b64e, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZKData:
    data: bytes = field(        # Signed data
        metadata=config(encoder=b64e, decoder=b64d),
    )
    proof: ZKProof
