#!/usr/bin/env python3

import base64
import binascii
import json
import os
from pprint import pprint

import Crypto
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Util.number import bytes_to_long, ceil_div, long_to_bytes
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# from google.auth import jwt
from jwt.api_jwt import decode_complete

jwt_max_len = 192 * 8
jwt_max_header_len = 300
jwt_max_payload_len = 192 * 8 - 64


def pad_string(string, max_len) -> list[str]:
    padded_string = [str(ord(c)) for c in string]
    padded_string += ["0"] * (max_len - len(string))
    return padded_string


def long_to_limbs(n):
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


if __name__ == "__main__":
    with open("jwt.in", "r") as file:
        raw = file.read().strip()
    header_str, payload_str, signature_str = raw.split(".", 2)

    jwt_decoded = decode_complete(
        raw, verify=False, options={"verify_signature": False}
    )
    pprint(jwt_decoded)
    json_dict = {
        "jwt": pad_string(raw, jwt_max_len),
        "jwt_header_with_separator": pad_string(header_str, jwt_max_header_len),
        "jwt_payload": pad_string(payload_str, jwt_max_payload_len),
        # "public_inputs_hash": public_inputs_hash_value,
        # "header_len_with_separator": header_len_with_separator_value,
        "signature": handle_signature(signature_str),
        # "pubkey_modulus": mod_value,
        # "aud_field": aud_field_value,
        # "aud_field_len": aud_field_len_value,
        # "aud_index": aud_index_value,
        # "aud_value_index": aud_value_index_value,
        # "aud_colon_index": aud_colon_index_value,
        # "aud_name": aud_name_value,
        # "uid_field": uid_field_value,
        # "uid_field_len": uid_field_len_value,
        # "uid_index": uid_index_value,
        # "uid_name_len": uid_name_len_value,
        # "uid_value_index": uid_value_index_value,
        # "uid_value_len": uid_value_len_value,
        # "uid_colon_index": uid_colon_index_value,
        # "uid_name": uid_name_value,
        # "uid_value": uid_value_value,
        # "ev_field": ev_field_value,
        # "ev_field_len": ev_field_len_value,
        # "ev_index": ev_index_value,
        # "ev_value_index": ev_value_index_value,
        # "ev_value_len": ev_value_len_value,
        # "ev_colon_index": ev_colon_index_value,
        # "ev_name": ev_name_value,
        # "ev_value": ev_value_value,
        # "iss_field": iss_field_value,
        # "iss_field_len": iss_field_len_value,
        # "iss_index": iss_index_value,
        # "iss_value_index": iss_value_index_value,
        # "iss_value_len": iss_value_len_value,
        # "iss_colon_index": iss_colon_index_value,
        # "iss_name": iss_name_value,
        # "iss_value": iss_value_value,
        # "nonce_field": nonce_field_value,
        # "nonce_field_len": nonce_field_len_value,
        # "nonce_index": nonce_index_value,
        # "nonce_value_index": nonce_value_index_value,
        # "nonce_value_len": nonce_value_len_value,
        # "nonce_colon_index": nonce_colon_index_value,
        # "nonce_name": nonce_name_value,
        # "nonce_value": nonce_value_value,
        # "temp_pubkey": temp_pubkey_value,
        # "jwt_randomness": jwt_randomness_value,
        # "pepper": pepper_value,
        # "jwt_num_sha2_blocks": jwt_num_sha2_blocks_value,
        # "iat_field": iat_field_value,
        # "iat_field_len": iat_field_len_value,
        # "iat_index": iat_index_value,
        # "iat_value_index": iat_value_index_value,
        # "iat_value_len": iat_value_len_value,
        # "iat_colon_index": iat_colon_index_value,
        # "iat_name": iat_name_value,
        # "iat_value": iat_value_value,
        # "exp_date": exp_date_value,
        # "exp_delta": exp_horizon_value,
        # "b64_payload_len": payload_len_value,
        # "jwt_len_bit_encoded": L_byte_encoded_value,
        # "padding_without_len": padding_without_len_bytes_value,
        # "temp_pubkey_len": temp_pubkey_len_value,
        # "private_aud_value": private_aud_value_value,
        # "override_aud_value": override_aud_value_value,
        # "private_aud_value_len": private_aud_value_len_value,
        # "override_aud_value_len": override_aud_value_len_value,
        # "use_aud_override": use_aud_override_value,
        # "extra_field": extra_field_value,
        # "extra_field_len": extra_field_len_value,
        # "extra_index": extra_index_value,
        # "jwt_payload_without_sha_padding": jwt_payload_string_no_padding_value,
        # "use_extra_field": use_extra_field_value,
    }
    json_str = json.dumps(json_dict)
    pprint(json_str)
    with open("google-input.json", "w") as f:
        f.write(json_str)
