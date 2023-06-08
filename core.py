from datetime import datetime as dt, timedelta as td
from random import SystemRandom
from typing import NamedTuple, Union

import hashlib
import json
import secrets
import traceback

from data import ZKParameters, ZKSignature, ZKProof, ZKData, dump
from utils import (
    to_bytes, to_str, bytes_to_int, int_to_bytes, b64e, b64d,
    hash_numeric, hash_data, mod, curve_by_name,
)

from ecpy.curves import Curve, Point

import jwt

# Secure random generation
random = SystemRandom()

__all__ = [
    "ZKParameters", "ZKSignature", "ZKProof", "ZKData", "ZK",
]

class ZK:
    def __init__(self,
                 parameters: ZKParameters,
                 jwt_secret: bytes = None,
                 jwt_alg: str = "HB2S",
                 jwt_iss: str = "noknow"):
        self._curve = curve_by_name(parameters.curve)
        if not self._curve:
            raise ValueError("The curve '{}' is invalid".format(parameters.curve))
        self._params = parameters
        self._bits = self._curve.field.bit_length()
        self._jwt_secret = jwt_secret
        self._jwt_alg = jwt_alg
        self._jwt_iss = jwt_iss
    
    def jwt(self, signature: ZKSignature, exp=td(seconds=10)):
        if self._jwt_secret:
            now = dt.utcnow()
            return to_str(jwt.encode({
                "signature": dump(signature),
                "iat": now, "nbf": now, "exp": now + exp, "iss": self._jwt_iss,
            }, self._jwt_secret, algorithm=self._jwt_alg))
        
    def verify_jwt(self, tok) -> Union[dict, None]:
        if self._jwt_secret:
            try:
                return jwt.decode(
                    to_str(tok), self._jwt_secret,
                    iss=self._jwt_iss, algorithms=[self._jwt_alg],
                )
            except (jwt.exceptions.ExpiredSignatureError, jwt.exceptions.DecodeError) as e:
                traceback.print_exc()
                pass
            except Exception as e:
                traceback.print_exc()

    @property
    def params(self) -> ZKParameters:
        return self._params

    @property
    def salt(self) -> bytes:
        return self._params.salt

    @property
    def curve(self) -> Curve:
        return self._curve

    @staticmethod
    def new(curve_name: str = "Ed25519", hash_alg: str = "blake2b",
            jwt_secret: bytes = None, jwt_alg = "HB2B",
            salt_size: int = 16):

        curve = curve_by_name(curve_name)
        if curve is None:
            raise ValueError("Invalid Curve Name")

        return ZK(
            ZKParameters(
                alg=hash_alg,
                curve=curve_name,
                salt=secrets.token_bytes(salt_size),
            ),
            jwt_secret=jwt_secret,
            jwt_alg=jwt_alg,
        )

    def _to_point(self, value: Union[int, bytes, ZKSignature]):
        point: Point = self.curve.decode_point(to_bytes(
            value.signature if isinstance(value, ZKSignature) else value
        ))
        # point.recover()
        return point

    def token(self) -> bytes:
        return secrets.token_bytes(
            (self._bits + 7) >> 3
        )

    def hash(self, *values) -> int:
        return mod(hash_numeric(*[
            v for v in values if v is not None
        ], self.salt, alg=self.params.alg), self.curve.order)
    
    def create_signature(self, secret: Union[str, bytes]) -> ZKSignature:
        return ZKSignature(
            params=self.params,
            signature=to_bytes(
             self.hash(secret) * self.curve.generator),
        )

    def create_proof(self, secret: Union[str, bytes], data: Union[int, str, bytes]=None) -> ZKProof:
        key = self.hash(secret)                     # Create private signing key
        r = secrets.randbits(self._bits)            # Generate a random number of size comparable to the curve
        R = r * self.curve.generator                # Random point whose discrete log, `r`, is known
        c = self.hash(data, R)                      # Hash the data and random point
        m = mod(r - (c * key), self.curve.order)    # Send offset between discrete log of R from c*x mod curve order
        return ZKProof(params=self.params, c=int_to_bytes(c), m=int_to_bytes(m))

    def sign(self, secret: Union[str, bytes], data: Union[int, str, bytes]) -> ZKData:
        data = to_str(data)
        return ZKData(
            data=data,
            proof=self.create_proof(secret, data),
        )
    
    @staticmethod
    def signature_is_valid(signature: ZKSignature) -> bool:
        try:
            zk = ZK(signature.params)
            return zk.curve.is_on_curve(zk._to_point(signature))
        except:
            return False

    def verify(self,
               challenge: Union[ZKData, ZKProof],
               signature: ZKSignature,
               data: Union[str, bytes, int]="") -> bool:
        if isinstance(challenge, ZKProof):
            data, proof = data, challenge
        elif isinstance(challenge, ZKData):
            data, proof = challenge.data, challenge.proof
        else:
            raise TypeError("Invalid challenge type provided")
        c = bytes_to_int(proof.c)
        p: Point = (bytes_to_int(proof.m) * self.curve.generator) \
                    + (c * self._to_point(signature))
        return c == self.hash(data, p)

    def login(self, login_data: ZKData) -> bool:
        data = self.verify_jwt(login_data.data)
        return data and self.verify(
            login_data,
            ZKSignature.from_json(data.get("signature")),
        )
