#!/usr/bin/env python3

import base64
import json
import os
from pprint import pprint

import poseidon
from Crypto.Util.number import bytes_to_long, ceil_div, long_to_bytes
from jwt.api_jwt import decode_complete

jwt_max_len = 192 * 8
jwt_max_header_len = 300
jwt_max_payload_len = 192 * 8 - 64


def pad_string(string, max_len) -> list[str]:
    padded_string = [str(ord(c)) for c in string]
    padded_string += ["0"] * (max_len - len(string))
    return padded_string


def long_to_limbs(n: int) -> list[int]:
    MAX = 2048
    BASE = 64
    limbs = []
    for i in range(int(MAX / BASE)):  # split into 32 64-bit limbs
        idx = i * BASE
        limbs.append((n >> idx) & ((1 << BASE) - 1))
    return limbs


def handle_signature(signature_str):
    long = bytes_to_long(signature_str.encode("utf-8"))
    limbs = long_to_limbs(long)
    limbs = [str(limb) for limb in limbs]
    return limbs


def handle_aud(
    payload_dict: dict,
    maxKVPairLen: int,
    maxNameLen: int,
    maxValueLen: int,
) -> dict:
    res = handle_field(
        "aud",
        "aud",
        payload_dict,
        maxKVPairLen,
        maxNameLen,
        maxValueLen,
    )
    res["private_aud_value"] = res.pop("aud_value")
    res["private_aud_value_len"] = res.pop("aud_value_len")
    res["use_aud_override"] = 0
    res["override_aud_value"] = pad_string("", maxValueLen)
    res["override_aud_value_len"] = 0
    return res


def handle_extra_field() -> dict:
    res = {
        "extra_field": pad_string("", 350),
        "extra_field_len": 0,
        "extra_index": 0,
        "use_extra_field": 0,
    }
    return res


def handle_field(
    dict_key: str,
    field_name: str,
    payload_dict: dict,
    maxKVPairLen: int,
    maxNameLen: int,
    maxValueLen: int,
) -> dict:
    res = {}
    payload = json.dumps(payload_dict)
    field_value = str(payload_dict[field_name])
    field_full_str: str = f'"{field_name}": "{field_value}"'  # "aud": "aud_value"
    res[f"{dict_key}_field"] = pad_string(field_full_str, maxKVPairLen)
    res[f"{dict_key}_field_len"] = len(field_full_str)
    res[f"{dict_key}_index"] = payload.index(f'"{field_name}"')
    res[f"{dict_key}_name"] = pad_string(field_name, maxNameLen)
    res[f"{dict_key}_value"] = pad_string(field_value, maxValueLen)
    res[f"{dict_key}_value_len"] = len(field_value)
    res[f"{dict_key}_value_index"] = field_full_str.index(field_value)
    res[f"{dict_key}_colon_index"] = field_full_str.index(":")

    return res


def handle_sha256_padding(jwt_raw: str) -> dict:
    res = {
        "jwt_num_sha2_blocks": len(jwt_raw) * 8 // 512,
    }
    unsigned_jwt_str = jwt_raw[: jwt_raw.rfind(".")]
    unsigned_b64_jwt_bits = bin(
        int.from_bytes(unsigned_jwt_str.encode("utf-8"), byteorder="big")
    ).lstrip("0b")
    L = len(unsigned_b64_jwt_bits)
    L_bit_encoded = format(L, "b").zfill(64)
    L_byte_encoded = ""
    for i in range(8):
        idx = i * 8
        bits = L_bit_encoded[idx : idx + 8]
        ascii_char = chr(int(bits, 2))
        L_byte_encoded += ascii_char
    res["jwt_len_bit_encoded"] = pad_string(L_byte_encoded, 8)

    L_mod = L % 512
    # https://www.rfc-editor.org/rfc/rfc4634.html#section-4.1
    # 4.1.a append '1'
    unsigned_b64_jwt_bits += "1"
    # 4.1.b Append 'K' 0s where K is the smallest non-negative integer solution to L+1+K = 448 mod 512, and L is the length of the message in bits
    K = 448 - L_mod - 1
    padding_without_len = "1" + "0" * K
    padding_without_len = padding_without_len.ljust(512, "0")
    padding_without_len_bytes = ""
    for i in range(64):
        idx = i * 8
        bits = padding_without_len[idx : idx + 8]
        ascii_char = chr(int(bits, 2))
        padding_without_len_bytes += ascii_char
    res["padding_without_len"] = pad_string(padding_without_len_bytes, 64)
    return res


def compute_public_inputs_hash(
    pubkey: list[int], pepper: int, jwt_payload: dict, pubkey_modulus: list[int]
) -> int:
    # TODO: Implement this
    # signal computed_public_inputs_hash <== Poseidon(14)([temp_pubkey[0], temp_pubkey[1], temp_pubkey[2], temp_pubkey_len, addr_seed, exp_date, exp_delta, hashed_iss_value, use_extra_field, hashed_extra_field, hashed_jwt_header, hashed_pubkey_modulus, override_aud_val_hashed, use_aud_override]);
    poseidon_simple, t = poseidon.parameters.case_simple()
    res = int(poseidon_simple.run_hash([*pubkey, pepper]))
    return res


def get_inputs():
    with open("jwt.in", "r") as file:
        jwt_raw = file.read().strip()
    epk = [123, 456, 789]
    pepper = 42
    jwt_randomness = 42
    # Google RSA public key (n)
    google_pk_raw = "puQJMii881LWwQ_OY2pOZx9RJTtpmUhAn2Z4_zrbQ9WmQqld0ufKesvwIAmuFIswzfOWxv1-ijZWwWrVafZ3MOnoB_UJFgjCPwJyfQiwwNMK80MfEm7mDO0qFlvrmLhhrYZCNFXYKDRibujCPF6wsEKcb3xFwBCH4UFaGmzsO0iJiqD2qay5rqYlucV4-kAIj4A6yrQyXUWWTlYwedbM5XhpuP1WxqO2rjHVLmwECUWqEScdktVhXXQ2CW6zvvyzbuaX3RBkr1w-J2U07vLZF5-RgnNjLv6WUNUwMuh-JbDU3tvmAahnVNyIcPRCnUjMk03kTqbSkZfu6sxWF0qNgw"
    google_pk_n = int.from_bytes(google_pk_raw.encode("utf-8"), byteorder="big")
    pubkey_modulus = long_to_limbs(google_pk_n)

    return jwt_raw, epk, pepper, jwt_randomness, pubkey_modulus


def main():
    jwt_raw, epk, pepper, jwt_randomness, pubkey_modulus = get_inputs()

    header_raw, payload_raw, signature_raw = jwt_raw.split(".", 2)
    header_with_separator = header_raw + "."
    jwt_raw_unsigned = jwt_raw[: jwt_raw.rfind(".")]
    jwt_dict = decode_complete(
        jwt_raw, verify=False, options={"verify_signature": False}
    )
    pprint(jwt_dict["header"])
    pprint(jwt_dict["payload"])
    json_dict = {
        "jwt": pad_string(jwt_raw_unsigned, jwt_max_len),
        "jwt_header_with_separator": pad_string(
            header_with_separator, jwt_max_header_len
        ),
        "jwt_payload": pad_string(payload_raw, jwt_max_payload_len),
        "header_len_with_separator": len(header_with_separator),
        **handle_sha256_padding(jwt_raw_unsigned),
        "signature": handle_signature(signature_raw),
        "pubkey_modulus": pubkey_modulus,
        **handle_aud(jwt_dict["payload"], 140, 40, 120),
        **handle_field("uid", "sub", jwt_dict["payload"], 350, 30, 330),
        "uid_name_len": len("sub"),
        **handle_field("iss", "iss", jwt_dict["payload"], 140, 40, 120),
        **handle_field("nonce", "nonce", jwt_dict["payload"], 105, 10, 100),
        **handle_field("iat", "iat", jwt_dict["payload"], 50, 10, 45),
        **handle_field(
            "ev",
            "email_verified",
            jwt_dict["payload"],
            30,
            20,
            10,
        ),
        **handle_extra_field(),
        # TODO: Real ephemeral public key
        "temp_pubkey": epk,
        "temp_pubkey_len": len(epk),
        "jwt_randomness": jwt_randomness,
        "pepper": pepper,
        "exp_date": jwt_dict["payload"]["exp"],
        "exp_delta": jwt_dict["payload"]["exp"] - jwt_dict["payload"]["iat"],
        "b64_payload_len": len(payload_raw),
        "jwt_payload_without_sha_padding": pad_string(payload_raw, jwt_max_payload_len),
        "public_inputs_hash": compute_public_inputs_hash(
            epk, pepper, jwt_dict["payload"], pubkey_modulus
        ),
    }
    json_str = json.dumps(json_dict)
    # pprint(json_str)
    with open("google-input.json", "w") as f:
        f.write(json_str)


if __name__ == "__main__":
    main()
