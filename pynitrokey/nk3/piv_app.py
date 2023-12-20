import logging
import os
import typing
from typing import Any, Callable, List, Optional, Sequence, Union

from ber_tlv.tlv import Tlv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from smartcard.CardRequest import CardRequest
from smartcard.CardService import CardService
from smartcard.CardType import ATRCardType

from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.start.gnuk_token import iso7816_compose

LogFn = Callable[[str], Any]


def find_by_id(tag: int, data: Sequence[tuple[int, bytes]]) -> Optional[bytes]:
    for t, b in data:
        if t == tag:
            return b


# size is in bytes
def prepare_for_pkcs1v15_sign_2048(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hashed = digest.finalize()

    prefix = bytearray.fromhex("3031300d060960864801650304020105000420")
    padding_len = 256 - 32 - 19 - 3
    padding = b"\x00\x01" + (b"\xFF" * padding_len) + b"\x00"
    total = padding + prefix + hashed
    assert len(total) == 256
    return total


class PivApp:
    log: logging.Logger
    logfn: LogFn
    card: CardService

    def __init__(self, logfn: Optional[LogFn] = None):
        self.log = logging.getLogger("pivapp")
        atr = bytes(
            [
                0x3B,
                0x8F,
                0x01,
                0x80,
                0x5D,
                0x4E,
                0x69,
                0x74,
                0x72,
                0x6F,
                0x6B,
                0x65,
                0x79,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x6A,
            ]
        )
        cardrequest = CardRequest(timeout=1, cardType=ATRCardType(atr))
        self.cardservice = cardrequest.waitforcard()
        self.cardservice.connection.connect()
        self.cardservice.connection.transmit(
            list(
                iso7816_compose(
                    0xA4,
                    0x04,
                    0x00,
                    bytes(
                        [
                            0xA0,
                            0x00,
                            0x00,
                            0x03,
                            0x08,
                            0x00,
                            0x00,
                            0x10,
                            0x00,
                            0x01,
                            0x00,
                        ]
                    ),
                )
            )
        )
        if logfn is not None:
            self.logfn = logfn
        else:
            self.logfn = self.log.info

    def send_receive(
        self,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
    ) -> bytes:
        bytes_data = iso7816_compose(ins, p1, p2, data)
        return self._send_receive_inner(bytes_data, log_info=f"{ins}")

    def _send_receive_inner(self, data: bytes, log_info: str = "") -> bytes:
        self.logfn(
            f"Sending {log_info if log_info else ''} {data.hex() if data else data!r}"
        )

        try:
            result, sw1, sw2 = self.cardservice.connection.transmit(list(data))
        except Exception as e:
            self.logfn(f"Got exception: {e}")
            raise

        l = len(result)
        status_bytes = bytes([sw1, sw2])
        self.logfn(
            f"Received [{status_bytes.hex()}] {result.hex() if result else result!r}"
        )

        log_multipacket = False
        data_final = bytes(result)
        MORE_DATA_STATUS_BYTE = 0x61
        while status_bytes[0] == MORE_DATA_STATUS_BYTE:
            if log_multipacket:
                self.logfn(
                    f"Got RemainingData status: [{status_bytes.hex()}] {result.hex() if result else result!r}"
                )
            log_multipacket = True
            ins = 0xC0
            p1 = 0
            p2 = 0
            bytes_data = iso7816_compose(ins, p1, p2, le=sw2)
            try:
                result, sw1, sw2 = self.cardservice.connection.transmit(
                    list(bytes_data)
                )
            except Exception as e:
                self.logfn(f"Got exception: {e}")
                raise
            # Data order is different here than in APDU - SW is first, then the data if any
            l = len(result)
            status_bytes = bytes([sw1, sw2])
            self.logfn(
                f"Received [{status_bytes.hex()}] {bytes(result).hex() if result else result!r}"
            )
            if status_bytes[0] in [0x90, MORE_DATA_STATUS_BYTE]:
                data_final += bytes(result)

        if status_bytes != b"\x90\x00" and status_bytes[0] != MORE_DATA_STATUS_BYTE:
            raise ValueError(f"{status_bytes.hex()}, Received error")

        if log_multipacket:
            self.logfn(
                f"Received final data: [{status_bytes.hex()}] {data_final.hex() if data_final else data_final!r}"
            )

        if data_final:
            try:
                self.logfn(f"Decoded received: {data_final.hex()}")
            except Exception:
                pass

        return data_final

    def authenticate_admin(self, admin_key: bytes) -> None:

        if len(admin_key) == 24:
            algorithm = algorithms.TripleDES(admin_key)
            algo = "tdes"
            algo_byte = 0x03
            expected_len = 8
        elif len(admin_key) == 16:
            algorithm = algorithms.AES128(admin_key)
            algo = "aes128"
            algo_byte = 0x08
            expected_len = 16
        elif len(admin_key) == 32:
            algorithm = algorithms.AES256(admin_key)
            algo = "aes256"
            algo_byte = 0x0C
            expected_len = 16
        else:
            local_critical(
                "Unsupported key length",
                support_hint=False,
            )

        challenge_body = Tlv.build({0x7C: {0x80: b""}})
        challenge_response = self.send_receive(0x87, algo_byte, 0x9B, challenge_body)
        challenge = find_by_id(
            0x80,
            Tlv.parse(
                find_by_id(0x7C, Tlv.parse(challenge_response, recursive=False)),
                recursive=False,
            ),
        )

        # challenge = decoded.first_by_id(0x7C).data.first_by_id(0x80).data
        if len(challenge) != expected_len:
            local_critical("Got unexpected authentication challenge length")

        our_challenge = os.urandom(expected_len)
        cipher = Cipher(algorithm, mode=modes.ECB())
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        response = encryptor.update(challenge) + encryptor.finalize()
        our_challenge_encrypted = decryptor.update(our_challenge) + decryptor.finalize()
        response_body = Tlv.build(
            {0x7C: {0x80: response, 0x81: our_challenge_encrypted}}
        )

        final_response = self.send_receive(0x87, algo_byte, 0x9B, response_body)
        decoded_challenge = find_by_id(
            0x82,
            Tlv.parse(
                find_by_id(0x7C, Tlv.parse(final_response, recursive=False)),
                recursive=False,
            ),
        )

        if decoded_challenge != our_challenge:
            local_critical(
                "Failed to authenticate with administrator key", support_hint=False
            )

    def set_admin_key(self, new_key: bytes) -> None:
        if len(new_key) == 24:
            algo = "tdes"
            algo_byte = 0x03
        elif len(new_key) == 16:
            algo = "aes128"
            algo_byte = 0x08
        elif len(new_key) == 32:
            algo = "aes256"
            algo_byte = 0x0C
        else:
            local_critical(
                "Unsupported key length",
                support_hint=False,
            )
        data = bytes([algo_byte, 0x9B, len(new_key)]) + new_key
        self.send_receive(0xFF, 0xFF, 0xFE, data)

    def login(self, pin: str):
        body = pin.encode("utf-8")
        body += bytes([0xFF for i in range(8 - len(body))])
        self.send_receive(0x20, 0x00, 0x80, body)

    def sign_p256(self, data: bytes, key: int) -> bytes:
        prepare_for_pkcs1v15_sign_2048(data)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        payload = digest.finalize()
        return self.raw_sign(payload, key, 0x11)

    def sign_rsa2048(self, data: bytes, key: int) -> bytes:
        payload = prepare_for_pkcs1v15_sign_2048(data)
        return self.raw_sign(payload, key, 0x07)

    def raw_sign(self, payload: bytes, key: int, algo: int) -> bytes:
        body = Tlv.build({0x7C: {0x81: payload, 0x82: b""}})
        result = self.send_receive(0x87, algo, key, body)
        return find_by_id(
            0x82,
            Tlv.parse(
                find_by_id(0x7C, Tlv.parse(result, recursive=False)), recursive=False
            ),
        )
