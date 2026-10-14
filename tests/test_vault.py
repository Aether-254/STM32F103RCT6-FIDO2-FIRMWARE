"""Actual C 512B codec, independent HKDF/AEAD oracle and cold-process reload.

All roots/scalars below are PUBLIC test vectors, never provisioned to hardware.
"""
import ctypes as C
import hashlib
import subprocess
import sys
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from test_transport import ROOT

ROOT_KEY = bytes(range(1, 33))
CONTEXT = b"device000001"
RP = hashlib.sha256(b"example.test").digest()
ID = bytes(range(32))
USER = b"public-test-user"
PRIVATE = bytes(31) + b"\x01"
INFO = b"stm32-fido2/credential-record/v1"


class Record(C.Structure):
    _fields_ = [("private_key", C.c_ubyte * 32), ("rp_hash", C.c_ubyte * 32),
                ("id", C.c_ubyte * 256), ("user_id", C.c_ubyte * 64),
                ("id_length", C.c_size_t), ("user_length", C.c_size_t)]


def configure(dll):
    dll.key_vault_seal.argtypes = [C.c_void_p, C.c_void_p, C.c_uint64,
                                 C.POINTER(Record), C.c_void_p]
    dll.key_vault_open.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p,
                                 C.c_void_p, C.c_size_t, C.c_void_p,
                                 C.c_size_t, C.POINTER(Record)]
    return dll


@pytest.fixture
def vault(lib):
    return configure(lib)


def record(identifier=ID, user=USER):
    r = Record()
    r.private_key[:] = PRIVATE
    r.rp_hash[:] = RP
    r.id[:len(identifier)] = identifier
    r.user_id[:len(user)] = user
    r.id_length = len(identifier)
    r.user_length = len(user)
    return r


def seal(vault, r=None, sequence=1, root=ROOT_KEY, context=CONTEXT):
    block = C.create_string_buffer(b"\xa5" * 512, 512)
    r = record() if r is None else r
    status = vault.key_vault_seal(root, context, sequence, C.byref(r), block)
    return status, block.raw


def opened(vault, block, root=ROOT_KEY, context=CONTEXT, rp=RP, identifier=ID):
    r = Record()
    C.memset(C.byref(r), 0xA5, C.sizeof(r))
    status = vault.key_vault_open(root, context, rp, identifier,
                                 len(identifier), block, len(block), C.byref(r))
    if status:
        assert bytes(r) == bytes(C.sizeof(r)), "failed open must wipe all output"
    return status, r


def oracle_key(root=ROOT_KEY, context=CONTEXT):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=context,
                info=INFO).derive(root)


def aad(header, identifier=ID, rp=RP):
    return header + rp + len(identifier).to_bytes(2, "big") + identifier


def plain(r):
    return (bytes(r.private_key) + bytes(r.rp_hash) +
            r.id_length.to_bytes(2, "big") + bytes([r.user_length, 0]) +
            bytes(r.id) + bytes(r.user_id) + bytes(76))


@pytest.mark.parametrize("sequence", [1, 0x123456789ABCDEF0, 2**64 - 1])
@pytest.mark.parametrize("id_size,user_size", [(1, 1), (32, 16), (255, 63), (256, 64)])
def test_oracle_roundtrip(vault, sequence, id_size, user_size):
    identifier = bytes(i % 256 for i in range(id_size))
    user = bytes(range(user_size))
    r = record(identifier, user)
    status, block = seal(vault, r, sequence)
    assert status == 0
    header = (b"F2CR\x01\x01\0\0" + sequence.to_bytes(8, "big") +
              b"CRED" + sequence.to_bytes(8, "big") + bytes(4))
    assert block[:32] == header
    expected = ChaCha20Poly1305(oracle_key()).encrypt(
        header[16:28], plain(r), aad(header, identifier))
    assert block[32:] == expected
    status, restored = opened(vault, block, identifier=identifier)
    assert status == 0
    assert bytes(restored) == bytes(r)


@pytest.mark.parametrize("offset", range(512))
def test_every_block_byte_tamper_rejected_and_wiped(vault, offset):
    _, block = seal(vault)
    damaged = bytearray(block)
    damaged[offset] ^= 1
    assert opened(vault, bytes(damaged))[0] < 0


@pytest.mark.parametrize("argument,value", [
    ("root", bytes(range(32))), ("root", bytes(32)),
    ("context", b"device000002"), ("rp", bytes(32)),
    ("identifier", bytes(range(1, 33))), ("identifier", ID + b"x"),
    ("identifier", b""), ("identifier", bytes(257)),
])
def test_wrong_binding(vault, argument, value):
    _, block = seal(vault)
    assert opened(vault, block, **{argument: value})[0] < 0


@pytest.mark.parametrize("length", [0, 1, 31, 32, 495, 496, 511, 513, 1024])
def test_exact_block_length(vault, length):
    _, block = seal(vault)
    assert opened(vault, (block + bytes(1024))[:length])[0] < 0


@pytest.mark.parametrize("offset,value", [
    (64, 1), (65, 0), (66, 0), (66, 65), (67, 1),
    (100, 1), (340, 1), (388, 1), (463, 1), (32, 1), (68, 1),
])
def test_authenticated_but_noncanonical_plaintext(vault, offset, value):
    _, block = seal(vault)
    p = bytearray(plain(record()))
    p[offset] = value
    encrypted = ChaCha20Poly1305(oracle_key()).encrypt(
        block[16:28], bytes(p), aad(block[:32]))
    assert opened(vault, block[:32] + encrypted)[0] < 0


def test_authenticated_zero_private_rejected(vault):
    _, block = seal(vault)
    p = bytes(32) + plain(record())[32:]
    encrypted = ChaCha20Poly1305(oracle_key()).encrypt(block[16:28], p, aad(block[:32]))
    assert opened(vault, block[:32] + encrypted)[0] < 0


@pytest.mark.parametrize("field,value", [
    ("id_length", 0), ("id_length", 257), ("user_length", 0), ("user_length", 65),
])
def test_seal_shape_validation(vault, field, value):
    r = record()
    setattr(r, field, value)
    status, block = seal(vault, r)
    assert status < 0 and block == bytes(512)


def test_unprovisioned_or_unreserved_seal(vault):
    for kwargs in [{"sequence": 0}, {"root": bytes(32)}, {"root": None}, {"context": None}]:
        status, block = seal(vault, **kwargs)
        assert status < 0 and block == bytes(512)
    r = record()
    r.private_key[:] = bytes(32)
    assert seal(vault, r)[0] < 0


def test_nonce_sequence_changes_ciphertext(vault):
    _, first = seal(vault, sequence=1)
    _, second = seal(vault, sequence=2)
    assert first[16:28] != second[16:28]
    assert first[32:] != second[32:]
    # Codec intentionally cannot stop nonce reuse/replay: allocator/journal MUST.
    assert seal(vault, sequence=1)[1] == first
    assert opened(vault, first)[0] == 0


def test_file_reload_in_new_process(vault, tmp_path):
    _, block = seal(vault, sequence=73)
    path = tmp_path / "test-public-vector.bin"
    path.write_bytes(block)
    script = '''
import ctypes as C, sys
from test_vault import configure, opened, PRIVATE, USER
dll = configure(C.CDLL(sys.argv[1]))
assert dll.key_crypto_init() == 0
status, record = opened(dll, open(sys.argv[2], 'rb').read())
assert status == 0 and bytes(record.private_key) == PRIVATE
assert bytes(record.user_id[:record.user_length]) == USER
print('cold-process C credential decrypt verified')
'''
    result = subprocess.run([sys.executable, "-c", script,
                             str(ROOT / "build/host/ctaphid.dll"), str(path)],
                            cwd=ROOT / "tests", capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "decrypt verified" in result.stdout
