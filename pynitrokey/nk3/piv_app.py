import logging
import os
import typing
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ber_tlv.tlv import Tlv

from typing import Callable, List, Optional, Any, Sequence, Union


from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.start.gnuk_token import iso7816_compose
from pynitrokey.helpers import local_critical, local_print

LogFn = Callable[[str], Any]

def find_by_id(tag: int, data: Sequence[tuple[int, bytes]]) -> Optional[bytes]:
    for t, b in data:
        if t == tag:
            return b

class PivApp:
    log: logging.Logger
    logfn: LogFn
    dev: Nitrokey3Device

    def __init__(self, dev: Nitrokey3Device, logfn: Optional[LogFn] = None):
        self.log = logging.getLogger("otpapp")
        if logfn is not None:
            self.logfn = logfn
        else:
            self.logfn = self.log.info
        self.dev = dev
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
            result = self.dev.piv(data=data)
        except Exception as e:
            self.logfn(f"Got exception: {e}")
            raise

        l = len(result)
        result, status_bytes = result[:l-2], result[l-2:]
        self.logfn(
            f"Received [{status_bytes.hex()}] {result.hex() if result else result!r}"
        )

        log_multipacket = False
        data_final = result
        MORE_DATA_STATUS_BYTE = 0x61
        while status_bytes[0] == MORE_DATA_STATUS_BYTE:
            if log_multipacket:
                self.logfn(
                    f"Got RemainingData status: [{status_bytes.hex()}] {result.hex() if result else result!r}"
                )
            log_multipacket = True
            ins = 0xA5
            p1 = 0
            p2 = 0
            bytes_data = iso7816_compose(ins, p1, p2)
            try:
                result = self.dev.piv(data=bytes_data)
            except Exception as e:
                self.logfn(f"Got exception: {e}")
                raise
            # Data order is different here than in APDU - SW is first, then the data if any
            l = len(result)
            result, status_bytes = result[:l-2], result[l-2:]
            self.logfn(
                f"Received [{status_bytes.hex()}] {result.hex() if result else result!r}"
            )
            if status_bytes[0] in [0x90, MORE_DATA_STATUS_BYTE]:
                data_final += result

        if status_bytes != b"\x90\x00" and status_bytes[0] != MORE_DATA_STATUS_BYTE:
            raise ValueError(f"{status_bytes.hex()}, Received error")

        if log_multipacket:
            self.logfn(
                f"Received final data: [{status_bytes.hex()}] {data_final.hex() if data_final else data_final!r}"
            )

        if data_final:
            try:
                self.logfn(
                    f"Decoded received: {data_final.hex()}"
                )
            except Exception:
                pass

        return bytes(data_final)

    def authenticate_admin(self, admin_key: bytes) -> None:
        
        if len(admin_key) ==  24:
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

        challenge_body = Tlv.build({0x7C: {0x80: b''}})
        challenge_response = self.send_receive(0x87, algo_byte, 0x9B, challenge_body)
        challenge = find_by_id(0x80, Tlv.parse(find_by_id(0x7C, Tlv.parse(challenge_response, recursive = False)), recursive = False))

        # challenge = decoded.first_by_id(0x7C).data.first_by_id(0x80).data
        if len(challenge) != expected_len:
            local_critical("Got unexpected authentication challenge length")
            

        our_challenge = os.urandom(expected_len)
        cipher = Cipher(algorithm, mode=modes.ECB())
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        response = encryptor.update(challenge) + encryptor.finalize()
        our_challenge_encrypted = decryptor.update(our_challenge) + decryptor.finalize()
        response_body = Tlv.build({0x7C: {0x80: response, 0x81: our_challenge_encrypted}})

        final_response = self.send_receive(0x87, algo_byte, 0x9B, response_body)
        decoded_challenge = find_by_id(0x82, Tlv.parse(find_by_id(0x7C, Tlv.parse(final_response, recursive = False)), recursive = False))

        if decoded_challenge != our_challenge:
            local_critical("Failed to authenticate with administrator key", support_hint=False)


    def sign_p256(self, data: bytes) -> bytes:
        pass

    def sign_rsa2048(self, data: bytes) -> bytes:
        pass

    def  raw_sign(self, data: bytes, key: int, algo: int) -> bytes:
        pass        
