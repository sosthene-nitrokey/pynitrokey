import os
import sys
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

import asn1crypto
import click
import cryptography
from asn1crypto import x509
from asn1crypto.algos import SignedDigestAlgorithm, SignedDigestAlgorithmId
from asn1crypto.core import Asn1Value, UTF8String
from asn1crypto.csr import CertificationRequest, CertificationRequestInfo
from asn1crypto.keys import PublicKeyInfo
from ber_tlv.tlv import Tlv
from click_aliases import ClickAliasedGroup
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from pynitrokey.cli.nk3 import nk3
from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3.piv_app import PivApp, find_by_id


@nk3.group(cls=ClickAliasedGroup)
def piv() -> None:
    """Nitrokey PIV App"""
    pass


@piv.command()
@click.argument(
    "admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
def admin_auth(admin_key: str) -> None:
    try:
        admin_key: bytes = bytearray.fromhex(admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(admin_key)
    local_print("Authenticated successfully")


@piv.command()
@click.option(
    "--current-admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
@click.argument(
    "new-admin-key",
    type=click.STRING,
)
def change_admin_key(current_admin_key: str, new_admin_key: str) -> None:
    try:
        current_admin_key: bytes = bytearray.fromhex(current_admin_key)
        new_admin_key: bytes = bytearray.fromhex(new_admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(current_admin_key)
    device.set_admin_key(new_admin_key)
    local_print("Changed key successfully")


@piv.command()
@click.option(
    "--current-pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
)
@click.option(
    "--new-pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
)
def change_pin(current_pin: str, new_pin: str) -> None:
    device = PivApp()
    device.change_pin(current_pin, new_pin)
    local_print("Changed pin successfully")


@piv.command()
@click.option(
    "--current-puk",
    type=click.STRING,
    prompt="Enter the PUK",
    hide_input=True,
)
@click.option(
    "--new-puk",
    type=click.STRING,
    prompt="Enter the PUK",
    hide_input=True,
)
def change_puk(current_puk: str, new_puk: str) -> None:
    device = PivApp()
    device.change_puk(current_puk, new_puk)
    local_print("Changed puk successfully")


KEY_TO_CERT_OBJ_ID_MAP = {
    "9A": "5FC105",
    "9C": "5FC10A",
    "9D": "5FC10B",
    "9E": "5FC101",
    "82": "5FC10D",
    "83": "5FC10E",
    "84": "5FC10F",
    "85": "5FC110",
    "86": "5FC111",
    "87": "5FC112",
    "88": "5FC113",
    "89": "5FC114",
    "8A": "5FC115",
    "8B": "5FC116",
    "8C": "5FC117",
    "8D": "5FC118",
    "8E": "5FC119",
    "8F": "5FC11A",
    "90": "5FC11B",
    "91": "5FC11C",
    "92": "5FC11D",
    "93": "5FC11E",
    "94": "5FC11F",
    "95": "5FC120",
}


@piv.command()
@click.option(
    "--admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
@click.option(
    "--key",
    type=click.Choice(
        [
            "9A",
            "9C",
            "9D",
            "9E",
            "82",
            "83",
            "84",
            "85",
            "86",
            "87",
            "88",
            "89",
            "8A",
            "8B",
            "8C",
            "8D",
            "8E",
            "8F",
            "90",
            "91",
            "92",
            "93",
            "94",
            "95",
        ]
    ),
    default="9A",
)
@click.option(
    "--algo",
    type=click.Choice(["rsa2048", "nistp256"]),
    default="nistp256",
)
@click.option(
    "--domain-component",
    type=click.STRING,
    multiple=True,
)
@click.option(
    "--subject-name",
    type=click.STRING,
    multiple=True,
)
@click.option(
    "--pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
)
@click.option(
    "--out-file",
    type=click.Path(allow_dash=True),
    default="-",
)
def generate_key(
    admin_key: str,
    key: str,
    algo: str,
    domain_component: Optional[Sequence[str]],
    subject_name: Optional[Sequence[str]],
    pin: str,
    out_file: str,
) -> None:
    try:
        admin_key: bytes = bytearray.fromhex(admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )
    key_ref = int(key, 16)

    device = PivApp()
    device.authenticate_admin(admin_key)
    device.login(pin)

    if algo == "rsa2048":
        algo_id = b"\x07"
        signature_algorithm = "sha256_rsa"
    elif algo == "nistp256":
        algo_id = b"\x11"
        signature_algorithm = "sha256_ecdsa"
    else:
        local_critical("Unimplemented algorithm", support_hint=False)

    body = Tlv.build({0xAC: {0x80: algo_id}})
    ins = 0x47
    p1 = 0
    p2 = key_ref
    response = device.send_receive(ins, p1, p2, body)

    data = Tlv.parse(response, recursive=False)
    data = Tlv.parse(find_by_id(0x7F49, data), recursive=False)

    if algo == "nistp256":
        key = find_by_id(0x86, data)[1:]
        public_x = int.from_bytes(key[:32], byteorder="big", signed=False)
        public_y = int.from_bytes(key[32:], byteorder="big", signed=False)
        public_numbers = ec.EllipticCurvePublicNumbers(
            public_x,
            public_y,
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
        )
        public_key = public_numbers.public_key()
        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    elif algo == "rsa2048":
        modulus = int.from_bytes(find_by_id(0x81, data), byteorder="big", signed=False)
        exponent = int.from_bytes(find_by_id(0x82, data), byteorder="big", signed=False)
        public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
        public_key = public_numbers.public_key()
        public_key_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        local_critical("Unimplemented algorithm")

    public_key_info = PublicKeyInfo.load(public_key_der, strict=True)

    if subject_name is None:
        rdns = []
    else:
        rdns = [
            x509.RelativeDistinguishedName(
                [
                    x509.NameTypeAndValue(
                        {
                            "type": x509.NameType.map("domain_component"),
                            "value": x509.DNSName(subject),
                        }
                    )
                ]
            )
            for subject in domain_component
        ] + [
            x509.RelativeDistinguishedName(
                [
                    x509.NameTypeAndValue(
                        {
                            "type": x509.NameType.map("common_name"),
                            "value": x509.DirectoryString(
                                name="utf8_string", value=subject
                            ),
                        }
                    )
                ]
            )
            for subject in subject_name
        ]

    extensions = [
        {
            "extn_id": "key_usage",
            "critical": True,
            "extn_value": x509.KeyUsage({"digital_signature", "non_repudiation"}),
        },
        {
            "extn_id": "extended_key_usage",
            "critical": False,
            "extn_value": x509.ExtKeyUsageSyntax(["microsoft_smart_card_logon"]),
        },
    ]

    csr_info = CertificationRequestInfo(
        {
            "version": "v1",
            "subject": x509.Name(name="", value=x509.RDNSequence(rdns)),
            "subject_pk_info": public_key_info,
            "attributes": [{"type": "extension_request", "values": [extensions]}],
        }
    )

    # To Be Signed
    tbs = csr_info.dump()

    if algo == "nistp256":
        signature = device.sign_p256(tbs, key_ref)
    elif algo == "rsa2048":
        signature = device.sign_rsa2048(tbs, key_ref)
    else:
        local_critical("Unimplemented algorithm")

    csr = CertificationRequest(
        {
            "certification_request_info": csr_info,
            "signature_algorithm": {
                "algorithm": signature_algorithm,
            },
            "signature": signature,
        }
    )

    with click.open_file(out_file, mode="wb") as file:
        file.write(csr.dump())


@piv.command()
@click.argument(
    "admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
@click.option("--format", type=click.Choice(["DER", "PEM"]), default="PEM")
@click.option(
    "--key",
    type=click.Choice(
        [
            "9A",
            " 9C",
            " 9D",
            " 9E",
            " 82",
            " 83",
            " 84",
            " 85",
            " 86",
            " 87",
            " 88",
            " 89",
            " 8A",
            " 8B",
            " 8C",
            " 8D",
            " 8E",
            " 8F",
            " 90",
            " 91",
            " 92",
            " 93",
            " 94",
            " 95",
        ]
    ),
    default="9A",
)
@click.option(
    "--path",
    type=click.Path(allow_dash=True),
    default="-",
)
def write_certificate(admin_key: str, format: str, key: str, path: str) -> None:
    try:
        admin_key: bytes = bytearray.fromhex(admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(admin_key)

    with click.open_file(path, mode="rb") as f:
        cert_bytes = f.read()
    if format == "DER":
        cert = cryptography.x509.load_der_x509_certificate(cert_bytes)
    elif format == "PEM":
        cert = cryptography.x509.load_pem_x509_certificate(cert_bytes)
    cert_serialized = cert.public_bytes(Encoding.DER)

    payload = Tlv.build(
        {
            0x5C: bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key])),
            0x53: cert_serialized,
        }
    )

    device.send_receive(0xDB, 0x3F, 0xFF, payload)
