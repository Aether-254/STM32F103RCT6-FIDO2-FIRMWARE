"""Public vectors ONLY. Actual root codec + journal-backed HMAC-DRBG C API."""
import ctypes as C
import hashlib
import hmac
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from test_journal import api, Flash, Journal, attach, reserve
from test_vault import ROOT_KEY, CONTEXT
from test_transport import RNG


@pytest.fixture
def provider(api):
    api.key_root_encode.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
    api.key_root_decode.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
    api.key_journal_matches.argtypes = [C.POINTER(Journal), C.c_void_p, C.c_void_p]
    api.key_journal_matches.restype = C.c_bool
    api.key_random_boot.argtypes = [C.POINTER(Journal), C.c_void_p, C.c_void_p]
    api.key_random_ready.restype = C.c_bool
    api.key_random_epoch.restype = C.c_uint64
    api.key_random_remaining.restype = C.c_uint32
    api.key_random_bytes.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
    api.key_random_private.argtypes = [C.c_void_p]
    api.key_random_test_private.argtypes = [RNG, C.c_void_p, C.c_void_p]
    api.key_random_stop.restype = None
    api.key_random_stop()
    yield api
    api.key_random_stop()


def root_block(provider, root=ROOT_KEY, device=CONTEXT):
    output = C.create_string_buffer(b"\xa5" * 128, 128)
    status = provider.key_root_encode(root, device, output)
    if status:
        assert output.raw == bytes(128)
    return status, output.raw


def root_read(provider, block, device=CONTEXT):
    output = C.create_string_buffer(b"\xa5" * 32, 32)
    status = provider.key_root_decode(block, len(block), device, output)
    if status:
        assert output.raw == bytes(32)
    return status, output.raw


class Oracle:
    """Independent HMAC-DRBG instantiate/generate, no reseed/additional input."""
    def __init__(self, root, device, epoch):
        self.k, self.v = bytes(32), b"\x01" * 32
        seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=device,
                    info=b"stm32-fido2/boot-drbg/v1" + epoch.to_bytes(8, "big")).derive(root)
        self.update(seed)

    def update(self, seed=b""):
        self.k = hmac.digest(self.k, self.v + b"\0" + seed, "sha256")
        self.v = hmac.digest(self.k, self.v, "sha256")
        if seed:
            self.k = hmac.digest(self.k, self.v + b"\1" + seed, "sha256")
            self.v = hmac.digest(self.k, self.v, "sha256")

    def generate(self, size):
        output = b""
        while len(output) < size:
            self.v = hmac.digest(self.k, self.v, "sha256")
            output += self.v
        self.update()
        return output[:size]


def random_bytes(provider, size):
    output = C.create_string_buffer(b"\xa5" * size, max(size, 1))
    status = provider.key_random_bytes(None, output, size)
    if status and size <= 1024:
        assert output.raw[:size] == bytes(size)
    return status, output.raw[:size]


def boot(provider, root=ROOT_KEY, device=CONTEXT):
    f = Flash()
    assert attach(provider, f, provision=True, root=root, context=device)[0] == 0
    _, j = attach(provider, f, root=root, context=device)
    assert provider.key_random_boot(C.byref(j), root, device) == 0
    return f, j


def test_root_format_oracle_and_roundtrip(provider):
    status, block = root_block(provider)
    assert status == 0
    body = b"F2RT\x01\0\0\0" + CONTEXT + ROOT_KEY
    assert block == body + hashlib.sha256(body).digest() + bytes(42) + b"\xa5\x5a"
    assert root_read(provider, block) == (0, ROOT_KEY)


@pytest.mark.parametrize("offset", range(128))
def test_root_every_byte_tamper_and_wipe(provider, offset):
    _, block = root_block(provider)
    damaged = bytearray(block)
    damaged[offset] ^= 1
    assert root_read(provider, bytes(damaged))[0] < 0


@pytest.mark.parametrize("size", [0, 1, 51, 52, 125, 126, 127, 129, 2048])
def test_root_exact_size(provider, size):
    _, block = root_block(provider)
    assert root_read(provider, (block + bytes(2048))[:size])[0] < 0


def test_root_absent_partial_wrong_binding_and_public_checksum_limit(provider):
    _, block = root_block(provider)
    assert root_read(provider, b"\xff" * 128)[0] < 0
    assert root_read(provider, block[:-2] + b"\xff\xff")[0] < 0
    assert root_read(provider, block, b"device000002")[0] < 0
    assert root_block(provider, bytes(32))[0] < 0
    assert root_block(provider, None)[0] < 0
    assert root_block(provider, device=None)[0] < 0
    # Honest boundary: someone who can rewrite root+checksum can construct a
    # different valid root. This checksum does NOT authenticate a physical owner.
    modified = bytearray(block)
    modified[20:52] = bytes(range(32))
    modified[52:84] = hashlib.sha256(modified[:52]).digest()
    assert root_read(provider, bytes(modified)) == (0, bytes(range(32)))


def test_generator_requires_bound_ready_journal(provider):
    assert not provider.key_random_ready()
    assert random_bytes(provider, 32)[0] == -2
    f = Flash()
    _, j = attach(provider, f)
    assert provider.key_random_boot(C.byref(j), ROOT_KEY, CONTEXT) == -2
    _, j = attach(provider, f, provision=True)
    before = bytes(f.image)
    for root, device in [(bytes(32), CONTEXT), (bytes(range(32)), CONTEXT),
                         (ROOT_KEY, b"device000002"), (None, CONTEXT), (ROOT_KEY, None)]:
        assert provider.key_random_boot(C.byref(j), root, device) == -2
        assert bytes(f.image) == before
    assert provider.key_random_boot(C.byref(j), ROOT_KEY, CONTEXT) == 0
    assert provider.key_random_epoch() == 1 and j.state.nonce == 1
    assert provider.key_random_ready()
    assert provider.key_random_boot(C.byref(j), ROOT_KEY, CONTEXT) == -4
    assert j.state.nonce == 1  # Busy restart must not consume or replace state.


@pytest.mark.parametrize("root,device", [(ROOT_KEY, CONTEXT),
    (bytes(range(32)), CONTEXT), (ROOT_KEY, b"device000002")])
def test_drbg_independent_oracle_and_reboot_epoch(provider, root, device):
    f, j = boot(provider, root, device)
    oracle = Oracle(root, device, 1)
    first = None
    for size in [1, 31, 32, 33, 64, 256, 1024]:
        status, output = random_bytes(provider, size)
        assert status == 0 and output == oracle.generate(size)
        first = first or output
    assert provider.key_random_remaining() == 65536-7
    provider.key_random_stop()
    status, j = attach(provider, f, root=root, context=device)
    assert status == 0
    assert provider.key_random_boot(C.byref(j), root, device) == 0
    assert provider.key_random_epoch() == 2
    status, second = random_bytes(provider, 1)
    assert status == 0 and second == Oracle(root, device, 2).generate(1)
    assert second != first  # Fixed public vectors, not a statistical RNG test.


@pytest.mark.parametrize("cut", range(80))
def test_boot_reservation_failure_never_exposes_randomness(provider, cut):
    f = Flash()
    _, j = attach(provider, f, provision=True)
    f.remaining = cut
    assert provider.key_random_boot(C.byref(j), ROOT_KEY, CONTEXT) == -2
    assert not provider.key_random_ready() and random_bytes(provider, 32)[0] == -2
    f.remaining = None
    assert attach(provider, f)[0] == 0


def test_empty_oversized_and_stop(provider):
    f, j = boot(provider)
    assert provider.key_random_bytes(None, None, 0) == 0
    assert provider.key_random_remaining() == 65536
    output = C.create_string_buffer(b"\xa5" * 1025, 1025)
    assert provider.key_random_bytes(None, output, 1025) == -1
    assert output.raw == b"\xa5" * 1025 and provider.key_random_remaining() == 65536
    assert provider.key_random_bytes(None, None, 1) == -1
    provider.key_random_stop()
    assert provider.key_random_epoch() == provider.key_random_remaining() == 0
    assert random_bytes(provider, 32)[0] == -2
    assert j.state.nonce == 1


def test_quota_fail_closed_and_explicit_new_epoch(provider):
    f, j = boot(provider)
    output = C.create_string_buffer(1)
    for _ in range(65536):
        assert provider.key_random_bytes(None, output, 1) == 0
    assert not provider.key_random_ready() and provider.key_random_remaining() == 0
    assert random_bytes(provider, 32)[0] == -2
    assert provider.key_random_epoch() == 0
    assert provider.key_random_boot(C.byref(j), ROOT_KEY, CONTEXT) == 0
    assert provider.key_random_epoch() == 2 and random_bytes(provider, 32)[0] == 0


def test_actual_private_key_generation_and_restartable_signing(provider):
    f, j = boot(provider)
    callback = RNG(("key_random_bytes", provider))
    keys = set()
    for _ in range(100):
        private = C.create_string_buffer(32)
        assert provider.key_random_private(private) == 0
        assert private.raw not in keys
        keys.add(private.raw)
        scalar = int.from_bytes(private.raw, "big")
        independent = ec.derive_private_key(scalar, ec.SECP256R1())
        public = C.create_string_buffer(65)
        assert provider.key_crypto_p256_public(private, public, callback, None) == 0
        numbers = independent.public_key().public_numbers()
        assert public.raw == b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    digest = hashlib.sha256(b"public DRBG integration signing test").digest()
    owner = 0x524e47
    assert provider.key_crypto_job_begin(owner, 2, private, digest, callback, None) == 0
    for _ in range(2000):
        status = provider.key_crypto_job_poll(owner)
        if status != 1:
            break
    assert status == 0
    signature, length = C.create_string_buffer(72), C.c_size_t()
    assert provider.key_crypto_job_take(owner, signature, 72, C.byref(length)) == 0
    independent.public_key().verify(signature.raw[:length.value], digest,
                                    ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    provider.key_random_stop()
    assert provider.key_random_private(private) == -2 and private.raw == bytes(32)


def test_scalar_rejection_zero_order_overflow_then_one(provider):
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    candidates = [0, order, order+1, 2**256-1, 1]
    calls = 0
    @RNG
    def controlled(ctx, out, size):
        nonlocal calls
        assert size == 32 and calls < len(candidates)
        C.memmove(out, candidates[calls].to_bytes(32, "big"), 32)
        calls += 1
        return 0
    private = C.create_string_buffer(32)
    assert provider.key_random_test_private(controlled, None, private) == 0
    assert private.raw == bytes(31) + b"\1" and calls == 5


def test_scalar_rejection_bounded_and_callback_error_wipes(provider):
    calls = 0
    @RNG
    def always_zero(ctx, out, size):
        nonlocal calls
        calls += 1
        C.memset(out, 0, size)
        return 0
    private = C.create_string_buffer(b"\xa5" * 32, 32)
    assert provider.key_random_test_private(always_zero, None, private) == -3
    assert private.raw == bytes(32) and calls == 16
    @RNG
    def partial_then_error(ctx, out, size):
        C.memset(out, 0xab, size)
        return -1
    assert provider.key_random_test_private(partial_then_error, None, private) == -2
    assert private.raw == bytes(32)


def test_many_boot_stop_cycles_preserve_crypto_arena(provider):
    f = Flash()
    _, j = attach(provider, f, provision=True)
    for epoch in range(1, 101):
        assert provider.key_random_boot(C.byref(j), ROOT_KEY, CONTEXT) == 0
        assert provider.key_random_epoch() == epoch
        assert random_bytes(provider, 32)[0] == 0
        provider.key_random_stop()
        assert provider.key_crypto_init() == 0
    assert j.state.nonce == 100
