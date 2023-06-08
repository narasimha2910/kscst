from base64 import b64encode, b64decode
from dataclasses import dataclass, asdict, is_dataclass
from typing import Union

from ecpy.curves import Point


__all__ = [
    "to_bytes", "to_str", "bytes_to_int", "int_to_bytes", "b64e", "b64d",
]


def bytes_to_int(value: Union[str, bytes, bytearray, Point]) -> int:
    return int.from_bytes(to_bytes(value), byteorder="big")

def int_to_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")

def b64e(data, strip=True) -> str:
    return to_str(b64encode(to_bytes(data))).rstrip("=" if strip else None)

def b64d(data, pad=True) -> bytes:
    return b64decode(to_bytes(data) + b"===" if pad else b"")

def to_bytes(data, encoding="utf-8", errors="replace") -> bytes:
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode(encoding=encoding, errors=errors)
    if isinstance(data, int):
        return int_to_bytes(data)
    if isinstance(data, Point):
        c = data.curve
        from ecpy.curves import MontgomeryCurve, WeierstrassCurve, TwistedEdwardCurve
        if isinstance(c, (MontgomeryCurve, TwistedEdwardCurve)):
            return bytes(c.encode_point(data))
        if isinstance(c, WeierstrassCurve):
            return bytes(c.encode_point(data, compressed=True))
        raise TypeError("Unknown Curve Type")
    print("UNTYPED:", type(data), "\n", data)
    return bytes(data)


def to_str(data, encoding="utf-8", errors="ignore") -> str:
    if isinstance(data, str):
        return data
    if is_dataclass(data):
        return data.to_json(separators=(",", ":"))
    if isinstance(data, bytes):
        return data.decode(encoding=encoding, errors=errors)
    return str(data)
