import click
from click_aliases import ClickAliasedGroup
import os
import sys
from ber_tlv.tlv import Tlv

from asn1crypto.csr import CertificationRequest, CertificationRequestInfo
from asn1crypto.core import Asn1Value, UTF8String
from asn1crypto.keys import PublicKeyInfo
from asn1crypto.algos import SignedDigestAlgorithm,SignedDigestAlgorithmId
from asn1crypto import x509

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding
import cryptography

from pynitrokey.cli.nk3 import Context, nk3
from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3.piv_app import PivApp, find_by_id

@nk3.group(cls=ClickAliasedGroup)
@click.pass_context
def piv(ctx: click.Context) -> None:
    """Nitrokey PIV App"""
    pass


@piv.command()
@click.pass_obj
@click.argument(
    "admin-key",
    type = click.STRING, 
    default="010203040506070801020304050607080102030405060708",
)
def admin_auth(ctx: Context, admin_key: str) -> None:
    try:
        admin_key: bytes = bytearray.fromhex(admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    with ctx.connect_device() as device:
        device = PivApp(device)
        device.authenticate_admin(admin_key)
        local_print("Authenticated successfully")
    
    pass

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
@click.pass_obj
@click.option(
    "--admin-key",
    type = click.STRING, 
    default="010203040506070801020304050607080102030405060708",
)
@click.option(
    "--key",
    type = click.Choice(["9A", "9C", "9D", "9E", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92", "93", "94", "95"]), 
    default="9A",
)
@click.option(
    "--algo",
    type = click.Choice(["rsa2048", "nistp256"]),
    default="nistp256",
)
@click.option(
    "--subject-name",
    type = click.STRING, 
    required = True,
)
@click.option(
    "--pin",
    type = click.STRING,
    prompt = "Enter the PIN",
    hide_input = True,
)
@click.option(
    "--out-file",
    type = click.Path(allow_dash = True),
    default = "-",
)
def generate_key(ctx: Context, admin_key: str, key: str, algo: str, subject_name: str, pin: str, out_file: str) -> None:
    try:
        admin_key: bytes = bytearray.fromhex(admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )
    key_ref = int(key, 16)

    with ctx.connect_device() as device:
        device = PivApp(device)
        device.authenticate_admin(admin_key)
        device.login(pin)

        if algo ==  "rsa2048":
            algo_id = b"\x07"
            signature_algorithm = 'sha256_rsa'
        elif algo == "nistp256":
            algo_id = b"\x11"
            signature_algorithm = 'sha256_ecdsa'
        else:
            local_critical("Unimplemented algorithm", support_hint = False)

        body = Tlv.build({0xAC: {0x80: algo_id}})
        ins = 0x47
        p1 = 0
        p2 = key_ref
        response = device.send_receive(ins,p1,p2,body)

        data = Tlv.parse(response, recursive = False)
        data = Tlv.parse(find_by_id(0x7F49, data), recursive = False)
        

        if algo == "nistp256":
            key = find_by_id(0x86, data)[1:]
            public_x = int.from_bytes(key[:32], byteorder='big', signed=False)
            public_y = int.from_bytes(key[32:], byteorder='big', signed=False)
            public_numbers = ec.EllipticCurvePublicNumbers(public_x,public_y, cryptography.hazmat.primitives.asymmetric.ec.SECP256R1())
            public_key = public_numbers.public_key()
            public_key_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif algo == "rsa2048":
            modulus = int.from_bytes(find_by_id(0x81, data), byteorder="big", signed=False)
            exponent = int.from_bytes(find_by_id(0x82, data), byteorder="big", signed=False)
            public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
            public_key = public_numbers.public_key()
            public_key_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            local_critical("Unimplemented algorithm")

        public_key_info = PublicKeyInfo.load(public_key_der, strict = True)
        csr_info = CertificationRequestInfo({
            'version': 'v1',
            'subject': x509.Name.build({
                'country_name': '',
                'state_or_province_name': '',
                'locality_name': '',
                'organization_name': '',
                'common_name': subject_name,
             }),
            'subject_pk_info': public_key_info,
            'attributes': []
        })

        # To Be Signed
        tbs = csr_info.dump()

        if algo == "nistp256":
            signature = device.sign_p256(tbs, key_ref)
        elif algo == "rsa2048":
            signature = device.sign_rsa2048(tbs, key_ref)
        else:
            local_critical("Unimplemented algorithm")
            
        csr = CertificationRequest({
            'certification_request_info': csr_info,
            'signature_algorithm': {
                'algorithm': signature_algorithm,
            },
            'signature': signature
        })

        with click.open_file(out_file, mode = "w") as file:
            file.write(csr.dump())

@piv.command()
@click.pass_obj
@click.argument(
    "admin-key",
    type = click.STRING, 
    default="010203040506070801020304050607080102030405060708",
)
@click.option(
    "--format",
    type = click.Choice(["DER", "PEM"]),
    default = "PEM"
)
@click.option(
    "--key",
    type = click.Choice(["9A"," 9C"," 9D"," 9E"," 82"," 83"," 84"," 85"," 86"," 87"," 88"," 89"," 8A"," 8B"," 8C"," 8D"," 8E"," 8F"," 90"," 91"," 92"," 93"," 94"," 95"]),
    default="9A",
)
@click.option(
    "--path",
    type = click.Path(allow_dash = True),
    default = "-",
)
def write_certificate(ctx: Context, admin_key: str, format: str, key: str, path: str) -> None:
    try:
        admin_key: bytes = bytearray.fromhex(admin_key)
    except:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    with ctx.connect_device() as device:
        device = PivApp(device)
        device.authenticate_admin(admin_key)
        local_print("Authenticated successfully")

        with click.open_file(path, mode = 'rb') as f:
            cert_bytes = f.read()
        if format == "DER":
            cert = cryptography.x509.load_der_x509_certificate(cert_bytes)
        elif format == "PEM":
            cert = cryptography.x509.load_pem_x509_certificate(cert_bytes)
        cert_serialized = cert.public_bytes(Encoding.DER)

        payload = Tlv.build({0x5C: bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key])), 0x53: cert_serialized})

        device.send_receive(0xDB, 0x3F, 0xFF, payload)
    pass
