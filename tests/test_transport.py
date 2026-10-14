"""Exercises the SAME C transport and dispatcher used by the Cortex-M build.

Run: uv run --with ziglang --with pytest --with fido2 python -m pytest tests -q
No device opened, reset, programmed, or erased by this suite.
"""
import ctypes as C
from pathlib import Path
import random
import re
import hashlib
import secrets
import subprocess
import sys

import pytest
from fido2 import cbor
from fido2.ctap2 import Info
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
def valid_request(command):
    if command == 1:
        return {1: b'c' * 32, 2: {'id': 'example.com'},
                3: {'id': b'user'}, 4: [{'alg': -7, 'type': 'public-key'}]}
    return {1: 'example.com', 2: b'c' * 32}


@pytest.mark.parametrize('encoded', [
    b'', b'\x18\x00', b'\x19\x00\xff', b'\x9f\xff', b'\xc0\x00',
    b'\xa2\x01\x00\x01\x01', b'\xa2\x02\x00\x01\x00',
    b'\x62\xc0\x80', b'\x63\xed\xa0\x80', b'\x64\xf4\x90\x80\x80',
    b'\x01\x02', b'\x81'*5+b'\x00', b'\x9b'+b'\xff'*8,
    b'\xbb'+b'\xff'*8, b'\xa1\x80\x00', b'\xf8\x14',
])
def test_cbor_rejects_malformed(lib, encoded):
    assert lib.cbor_valid(encoded, len(encoded)) == 0


@pytest.mark.parametrize('value', [0, 23, 24, 255, 256, -7, b'bytes',
                                 '中文', {1: 'a', 2: [True, False]}, [[[[]]]]])
def test_cbor_accepts_canonical(lib, value):
    encoded = cbor.encode(value)
    assert lib.cbor_valid(encoded, len(encoded)) == 1


@pytest.mark.parametrize('command', [1, 2])
def test_request_valid_and_missing(lib, command):
    encoded = bytes([command]) + cbor.encode(valid_request(command))
    assert lib.request_status(encoded, len(encoded)) == 0
    assert lib.request_status(bytes([command, 0xa0]), 2) == 0x14


@pytest.mark.parametrize('command', [1, 2])
@pytest.mark.parametrize('hash_value,status', [(b'x'*31, 2), (b'x'*33, 2), ('text', 0x11)])
def test_request_hash_boundaries(lib, command, hash_value, status):
    request = valid_request(command)
    request[1 if command == 1 else 2] = hash_value
    encoded = bytes([command]) + cbor.encode(request)
    assert lib.request_status(encoded, len(encoded)) == status


@pytest.mark.parametrize('field,value,status', [
    (2, {'id': ''}, 2), (2, {'id': 'a\0b'}, 2),
    (3, {'id': b''}, 2), (3, {'id': b'x'*65}, 2),
    (4, [{'alg': -8, 'type': 'public-key'}], 0x26),
    (4, [], 2), (7, {'uv': 1}, 0x11), (8, 'pin', 0x11),
    (5, [{'id': b'a', 'type': 'public-key'}]*17, 0x15),
    (5, [{'id': b'a'*257, 'type': 'public-key'}], 2),
    (99, 'unknown fields are ignored', 0),
])
def test_make_request_schema(lib, field, value, status):
    request = valid_request(1)
    request[field] = value
    encoded = b'\x01' + cbor.encode(request)
    assert lib.request_status(encoded, len(encoded)) == status
BROADCAST = 0xFFFFFFFF
RNG = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)


@RNG
def secure_random(context, output, size):
    C.memmove(output, secrets.token_bytes(size), size)
    return 0


@RNG
def failed_random(context, output, size):
    return -1




@pytest.fixture
def device(lib):
    lib.reset()
    return lib


def initial(cid, command, payload=b"", length=None):
    n = len(payload) if length is None else length
    return (cid.to_bytes(4, "big") + bytes([command]) + n.to_bytes(2, "big")
            + payload[:57]).ljust(64, b"\x00")


def continuation(cid, sequence, data):
    return (cid.to_bytes(4, "big") + bytes([sequence]) + data[:59]).ljust(64, b"\x00")


def feed(d, p, now=0):
    d.receive(p, len(p), now)


def peek(d):
    p = (C.c_uint8 * 64)()
    ticket = C.c_uint32()
    d.peek(p, C.byref(ticket))
    return bytes(p), ticket.value


def packet(d):
    p, ticket = peek(d)
    assert ticket, "expected a pending response"
    d.ack(ticket)
    return p


def message(d):
    p = packet(d)
    cid = int.from_bytes(p[:4], "big")
    cmd = p[4]
    size = int.from_bytes(p[5:7], "big")
    payload = p[7:7 + min(57, size)]
    sequence = 0
    while len(payload) < size:
        p = packet(d)
        assert p[:4] == cid.to_bytes(4, "big")
        assert p[4] == sequence
        payload += p[5:5 + min(59, size - len(payload))]
        sequence += 1
    return cid, cmd, payload


def allocate(d, nonce=b"12345678"):
    feed(d, initial(BROADCAST, 0x86, nonce))
    cid, cmd, payload = message(d)
    assert (cid, cmd) == (BROADCAST, 0x86)
    assert payload[:8] == nonce and len(payload) == 17
    assert payload[12] == 2 and payload[16] == 0x0C
    return int.from_bytes(payload[8:12], "big")


def send_message(d, cid, cmd, payload, now=0):
    feed(d, initial(cid, cmd, payload), now)
    for seq, off in enumerate(range(57, len(payload), 59)):
        feed(d, continuation(cid, seq, payload[off:]), now)


@pytest.mark.parametrize("size", [0, 1, 56, 57, 58, 64, 116, 117, 255, 1024, 4095, 4096])
def test_ping_fragmentation(device, size):
    cid = allocate(device)
    data = bytes((i * 31 + 17) % 256 for i in range(size))
    send_message(device, cid, 0x81, data)
    assert message(device) == (cid, 0x81, data)
    assert device.idle() and peek(device)[1] == 0


def test_stable_peek_and_wrong_ack(device):
    cid = allocate(device)
    feed(device, initial(cid, 0x81, b"abc"))
    p, ticket = peek(device)
    assert peek(device) == (p, ticket)
    device.ack(ticket + 100)
    assert peek(device) == (p, ticket)
    assert not device.idle()
    device.ack(ticket)
    assert device.idle()


def test_channel_uniqueness(device):
    cids = [allocate(device, i.to_bytes(8, "big")) for i in range(512)]
    assert cids == list(range(1, 513))
    assert len(set(cids)) == len(cids)


@pytest.mark.parametrize("cid", [0, 1, 0xFFFFFFFF])
def test_invalid_channel(device, cid):
    feed(device, initial(cid, 0x81))
    assert message(device) == (cid, 0xBF, b"\x0b")


@pytest.mark.parametrize("cmd,length", [(0x86, 0), (0x86, 7), (0x86, 9)])
def test_invalid_init_length(device, cmd, length):
    feed(device, initial(BROADCAST, cmd, b"123456789", length))
    assert message(device) == (BROADCAST, 0xBF, b"\x03")


def test_max_length_rejected(device):
    cid = allocate(device)
    feed(device, initial(cid, 0x81, length=4097))
    assert message(device) == (cid, 0xBF, b"\x03")
    assert device.idle()


def test_busy_preserves_transaction(device):
    a, b = allocate(device), allocate(device)
    data = bytes(range(100))
    feed(device, initial(a, 0x81, data))
    feed(device, initial(b, 0x81, b"other"))
    assert message(device) == (b, 0xBF, b"\x06")
    feed(device, continuation(a, 0, data[57:]))
    assert message(device) == (a, 0x81, data)


def test_same_channel_busy(device):
    a = allocate(device)
    feed(device, initial(a, 0x81, b"x", length=100))
    feed(device, initial(a, 0x81, b"y"))
    assert message(device) == (a, 0xBF, b"\x06")


def test_invalid_sequence_then_recovery(device):
    a = allocate(device)
    feed(device, initial(a, 0x81, b"x", length=100))
    feed(device, continuation(a, 1, b"x" * 43))
    assert message(device) == (a, 0xBF, b"\x04")
    feed(device, initial(a, 0x81, b"ok"))
    assert message(device) == (a, 0x81, b"ok")


@pytest.mark.parametrize("start", [0, 0xFFFFFC00])
def test_timeout_including_tick_wrap(device, start):
    a = allocate(device)
    feed(device, initial(a, 0x81, b"x", length=100), start)
    device.tick((start + 2999) & 0xFFFFFFFF)
    assert peek(device)[1] == 0
    device.tick((start + 3000) & 0xFFFFFFFF)
    assert message(device) == (a, 0xBF, b"\x05")
    assert device.idle()


def test_resync_aborts_pending_and_stale_ack(device):
    a = allocate(device)
    send_message(device, a, 0x81, bytes(range(200)))
    old_packet, old_ticket = peek(device)
    feed(device, initial(a, 0x86, b"abcdefgh"))
    new_packet, new_ticket = peek(device)
    assert old_packet != new_packet and old_ticket != new_ticket
    device.ack(old_ticket)
    assert peek(device) == (new_packet, new_ticket)
    cid, cmd, payload = message(device)
    assert (cid, cmd, payload[:8]) == (a, 0x86, b"abcdefgh")
    assert int.from_bytes(payload[8:12], "big") == a


def test_idle_continuation_ignored(device):
    a = allocate(device)
    feed(device, continuation(a, 0, b"ignored"))
    assert peek(device)[1] == 0


@pytest.mark.parametrize("size", [0, 1, 4, 5, 7, 63, 65, 128])
def test_non_64_byte_reports_ignored(device, size):
    feed(device, b"\xff" * size)
    assert peek(device)[1] == 0


def test_unknown_command(device):
    a = allocate(device)
    feed(device, initial(a, 0x88))
    assert message(device) == (a, 0xBF, b"\x01")


def test_cancel_has_no_response(device):
    a = allocate(device)
    feed(device, initial(a, 0x91))
    assert peek(device)[1] == 0


def test_cbor_empty_is_transport_error(device):
    a = allocate(device)
    feed(device, initial(a, 0x90))
    assert message(device) == (a, 0xBF, b"\x03")


def test_get_info_independent_yubico_parser(device):
    a = allocate(device)
    feed(device, initial(a, 0x90, b"\x04"))
    cid, cmd, data = message(device)
    assert (cid, cmd, data[0]) == (a, 0x90, 0)
    decoded = cbor.decode(data[1:])
    assert cbor.encode(decoded) == data[1:], "must be canonical CBOR"
    info = Info.from_dict(decoded)
    assert info.versions == ["FIDO_2_0"]
    assert info.aaguid == b"\x00" * 16
    assert info.max_msg_size == 4096
    assert info.options == {"rk": False, "up": True}
    assert info.transports == ["usb"]
    assert info.algorithms == [{"alg": -7, "type": "public-key"}]


def test_get_info_trailing_data_rejected(device):
    a = allocate(device)
    feed(device, initial(a, 0x90, b"\x04\xa0"))
    assert message(device) == (a, 0x90, b"\x03")


@pytest.mark.parametrize("command", [1, 2, 7])
def test_unimplemented_sensitive_ops_fail_closed(device, command):
    a = allocate(device)
    payload = bytes([command]) + cbor.encode(valid_request(command)) if command != 7 else b'\x07'
    send_message(device, a, 0x90, payload)
    assert message(device) == (a, 0x90, b"\x27")


def test_error_fifo_is_bounded(device):
    for _ in range(10):
        feed(device, initial(0, 0x81))
    assert device.dropped_errors() == 6
    for _ in range(4):
        assert message(device) == (0, 0xBF, b"\x0b")
    assert peek(device)[1] == 0


def test_seeded_random_packet_stream_recovers(device):
    rng = random.Random(0xF1D0)
    allocate(device)
    for i in range(5000):
        p = rng.randbytes(rng.choice([0, 63, 64, 65, 128]))
        feed(device, p, i * 10)
        while peek(device)[1]:
            packet(device)
    device.tick(100000)
    while peek(device)[1]:
        packet(device)
    a = allocate(device)
    feed(device, initial(a, 0x81, b"recovered"))
    assert message(device) == (a, 0x81, b"recovered")


@pytest.fixture
def usb(lib):
    lib.usb_reset_test()
    return lib


def usb_read(d):
    p = (C.c_uint8 * 64)()
    d.usb_read(p)
    return bytes(p)


def usb_allocate(d):
    d.usb_receive(initial(BROADCAST, 0x86, b"12345678"))
    d.usb_poll(0)
    response = usb_read(d)
    assert response[4] == 0x86
    cid = int.from_bytes(response[15:19], "big")
    d.usb_complete()
    d.usb_poll(1)
    return cid


def test_adapter_retains_buffer_until_complete(usb):
    a = usb_allocate(usb)
    usb.usb_receive(initial(a, 0x81, b"pending"))
    usb.usb_poll(2)
    previous = usb_read(usb)
    assert usb.usb_sent() == 2
    usb.usb_receive(initial(a, 0x86, b"abcdefgh"))
    usb.usb_poll(3)
    assert usb_read(usb) == previous, "resync must not mutate hardware-owned buffer"
    assert usb.usb_sent() == 2
    usb.usb_complete()
    usb.usb_poll(4)
    assert usb.usb_sent() == 3
    assert usb_read(usb)[4:5] == b"\x86"
    assert usb_read(usb)[7:15] == b"abcdefgh"


def test_adapter_overflow_preserves_inflight_buffer(usb):
    a = usb_allocate(usb)
    usb.usb_receive(initial(a, 0x81, b"pending"))
    usb.usb_poll(2)
    previous = usb_read(usb)
    for _ in range(16):
        usb.usb_receive(initial(a, 0x81, b"flood"))
    assert usb.usb_overflows() == 1
    usb.usb_poll(3)
    assert usb_read(usb) == previous
    assert usb.usb_sent() == 2
    usb.usb_receive(initial(BROADCAST, 0x86, b"recovery"))
    usb.usb_poll(4)
    assert usb_read(usb) == previous
    usb.usb_complete()
    usb.usb_poll(5)
    assert usb_read(usb)[7:15] == b"recovery"


def test_adapter_retries_failed_submission(usb):
    usb.usb_reject(1)
    usb.usb_receive(initial(BROADCAST, 0x86, b"12345678"))
    usb.usb_poll(0)
    assert usb.usb_sent() == 0
    usb.usb_poll(1)
    assert usb.usb_sent() == 0
    usb.usb_reject(0)
    usb.usb_poll(2)
    assert usb.usb_sent() == 1
    assert usb_read(usb)[7:15] == b"12345678"
    assert usb.usb_masked() == 0


def test_adapter_disconnect_discards_previous_channels(usb):
    usb_allocate(usb)
    usb.usb_disconnect()
    usb.usb_poll(2)
    usb.usb_reconnect()
    usb.usb_poll(3)
    usb.usb_receive(initial(1, 0x81, b"stale"))
    usb.usb_poll(4)
    assert usb_read(usb)[4] == 0xBF
    assert usb_read(usb)[7] == 0x0B
    assert usb.usb_masked() == 0


@pytest.mark.parametrize("size", [0, 1, 55, 56, 63, 64, 65, 512, 4096])
def test_sha256_against_python_hashlib(lib, size):
    data = bytes(i % 256 for i in range(size))
    out = (C.c_uint8 * 32)()
    assert lib.key_crypto_sha256(data, size, out) == 0
    assert bytes(out) == hashlib.sha256(data).digest()


def seal(lib, key, nonce, aad, plaintext):
    out = (C.c_uint8 * len(plaintext))()
    tag = (C.c_uint8 * 16)()
    assert lib.key_crypto_seal(key, nonce, aad, len(aad), plaintext, len(plaintext),
                               out, len(out), tag) == 0
    return bytes(out) + bytes(tag)


def open_record(lib, key, nonce, aad, ciphertext_and_tag):
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    out = (C.c_uint8 * len(ciphertext))(*([0xA5] * len(ciphertext)))
    rc = lib.key_crypto_open(key, nonce, aad, len(aad), tag, ciphertext, len(ciphertext), out, len(out))
    return rc, bytes(out)


def test_rfc8439_chachapoly_known_answer(lib):
    # RFC 8439 section 2.8.2; public test-vector material only.
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c61737320"
        "6f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c7920"
        "6f6e652074697020666f7220746865206675747572652c2073756e73637265656e20"
        "776f756c642062652069742e")
    expected = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691")
    assert seal(lib, key, nonce, aad, plaintext) == expected
    assert open_record(lib, key, nonce, aad, expected) == (0, plaintext)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 63, 64, 65, 255, 1024, 4096])
def test_aead_cross_implementation_openssl(lib, size):
    key, nonce, aad = secrets.token_bytes(32), secrets.token_bytes(12), secrets.token_bytes(29)
    plaintext = secrets.token_bytes(size)
    expected = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    actual = seal(lib, key, nonce, aad, plaintext)
    assert actual == expected
    assert ChaCha20Poly1305(key).decrypt(nonce, actual, aad) == plaintext
    assert open_record(lib, key, nonce, aad, expected) == (0, plaintext)


@pytest.mark.parametrize("tampered", ["key", "nonce", "aad", "ciphertext", "tag"])
def test_aead_rejects_tamper_and_erases_plaintext(lib, tampered):
    key, nonce, aad = bytes(range(32)), bytes(range(12)), b"credential metadata"
    plaintext = b"secret scalar and identity" * 4
    record = seal(lib, key, nonce, aad, plaintext)
    flip = lambda b: bytes([b[0] ^ 1]) + b[1:]
    if tampered == "key": key = flip(key)
    elif tampered == "nonce": nonce = flip(nonce)
    elif tampered == "aad": aad = flip(aad)
    elif tampered == "ciphertext": record = flip(record)
    elif tampered == "tag": record = record[:-1] + bytes([record[-1] ^ 1])
    rc, output = open_record(lib, key, nonce, aad, record)
    assert rc != 0 and output == b"\x00" * len(plaintext)


def test_aead_capacity_error_does_not_overwrite_guard(lib):
    key, nonce, aad = b"k" * 32, b"n" * 12, b"aad"
    data = b"private plaintext"
    record = seal(lib, key, nonce, aad, data)
    out = (C.c_uint8 * 32)(*([0xA5] * 32))
    rc = lib.key_crypto_open(key, nonce, aad, len(aad), record[-16:], record[:-16], len(data), out, 8)
    assert rc == -1
    assert bytes(out[:8]) == b"\x00" * 8
    assert bytes(out[8:]) == b"\xa5" * 24


def test_hkdf_against_openssl_and_domain_separation(lib):
    key, salt = bytes(range(32)), bytes(range(13))
    outputs = []
    for info in [b"STM32-FIDO2 credential wrap v1", b"STM32-FIDO2 resident record v1"]:
        out = (C.c_uint8 * 32)()
        assert lib.key_crypto_hkdf(key, salt, len(salt), info, len(info), out) == 0
        expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(key)
        assert bytes(out) == expected
        outputs.append(bytes(out))
    assert outputs[0] != outputs[1]
    assert lib.key_crypto_init() == 0


P256_ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)


def sign(lib, private, digest, random=secure_random):
    out = (C.c_uint8 * 80)(*([0xA5] * 80))
    length = C.c_size_t(80)
    rc = lib.key_crypto_p256_sign(private, digest, out, 80, C.byref(length), random, None)
    return rc, bytes(out[:length.value]), bytes(out)


@pytest.mark.parametrize("scalar", [1, 17, P256_ORDER - 1])
def test_p256_public_and_signature_against_openssl(lib, scalar):
    # Public fixture scalars are never used for real credentials.
    private = scalar.to_bytes(32, "big")
    reference = ec.derive_private_key(scalar, ec.SECP256R1())
    public = (C.c_uint8 * 65)()
    assert lib.key_crypto_p256_public(private, public, secure_random, None) == 0
    assert bytes(public) == reference.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    digest = hashlib.sha256(b"authenticatorData" + b"clientDataHash" * 2).digest()
    rc, signature, _ = sign(lib, private, digest)
    assert rc == 0
    reference.public_key().verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    assert sign(lib, private, digest)[1] == signature, "RFC6979 signature must be deterministic"
    assert lib.key_crypto_init() == 0


def test_rfc6979_p256_known_answer(lib):
    private = bytes.fromhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
    digest = hashlib.sha256(b"sample").digest()
    rc, der, _ = sign(lib, private, digest)
    assert rc == 0
    r, s = utils.decode_dss_signature(der)
    assert r == int("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", 16)
    assert s == int("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", 16)


@pytest.mark.parametrize("scalar", [0, P256_ORDER, (1 << 256) - 1])
def test_invalid_p256_scalar_fails_closed(lib, scalar):
    private = scalar.to_bytes(32, "big")
    public = (C.c_uint8 * 65)(*([0xA5] * 65))
    assert lib.key_crypto_p256_public(private, public, secure_random, None) != 0
    assert bytes(public) == b"\x00" * 65
    rc, signature, storage = sign(lib, private, b"h" * 32)
    assert rc != 0 and signature == b"" and storage == b"\x00" * 80


@pytest.mark.parametrize("random", [RNG(), failed_random])
def test_blinding_rng_required_and_failure_propagates(lib, random):
    private = (1).to_bytes(32, "big")
    public = (C.c_uint8 * 65)()
    assert lib.key_crypto_p256_public(private, public, random, None) != 0
    assert bytes(public) == b"\x00" * 65
    rc, signature, storage = sign(lib, private, b"h" * 32, random)
    assert rc != 0 and signature == b"" and storage == b"\x00" * 80


def test_crypto_repeated_operations_preserve_arena(lib):
    private = (12345).to_bytes(32, "big")
    public = (C.c_uint8 * 65)()
    for i in range(30):
        assert lib.key_crypto_p256_public(private, public, secure_random, None) == 0
        assert sign(lib, private, hashlib.sha256(i.to_bytes(4, "big")).digest())[0] == 0
        assert lib.key_crypto_init() == 0
