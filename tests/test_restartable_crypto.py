"""Actual restartable C ECC, checked against independent OpenSSL backend."""
import ctypes as C
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from test_transport import RNG, secure_random, failed_random

OWNER = 0x12345678
PRIVATE = (17).to_bytes(32, 'big')
HASH = hashlib.sha256(b'authenticatorData || clientDataHash fixture').digest()


@pytest.fixture
def crypto_job(lib):
    yield lib
    lib.key_crypto_job_cancel(OWNER)


def run(d):
    pending = 0
    for _ in range(10000):
        result = d.key_crypto_job_poll(OWNER)
        if result != 1:
            return result, pending
        pending += 1
    pytest.fail('ECC job failed to terminate within bounded host steps')


def take(d, capacity=72):
    output = C.create_string_buffer(capacity)
    length = C.c_size_t(999)
    rc = d.key_crypto_job_take(OWNER, output, capacity, C.byref(length))
    return rc, bytes(output)[:length.value], length.value


@pytest.mark.parametrize('mode', [1, 2])
@pytest.mark.parametrize('scalar', [1, 17, 2**128+73])
def test_restartable_matches_sync_and_openssl(crypto_job, mode, scalar):
    d = crypto_job
    private = scalar.to_bytes(32, 'big')
    assert d.key_crypto_job_begin(OWNER, mode, private, HASH, secure_random, None) == 0
    rc, pending = run(d)
    assert rc == 0 and pending > 1, 'must genuinely yield, not a synchronous wrapper'
    rc, output, length = take(d)
    assert rc == 0
    independent = ec.derive_private_key(scalar, ec.SECP256R1())
    if mode == 1:
        assert length == 65
        assert output == independent.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    else:
        independent.public_key().verify(output, HASH, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        sync = C.create_string_buffer(72)
        used = C.c_size_t()
        assert d.key_crypto_p256_sign(private, HASH, sync, 72, C.byref(used), secure_random, None) == 0
        assert output == bytes(sync)[:used.value]  # RFC6979 deterministic signature
    assert d.key_crypto_job_poll(OWNER) < 0
    assert take(d)[0] < 0  # Single-use result.


def test_input_buffers_copied_and_no_partial_output(crypto_job):
    d = crypto_job
    private = C.create_string_buffer(PRIVATE)
    hash_buffer = C.create_string_buffer(HASH)
    assert d.key_crypto_job_begin(OWNER, 2, private, hash_buffer, secure_random, None) == 0
    C.memset(private, 0, 32)
    C.memset(hash_buffer, 0, 32)
    assert d.key_crypto_job_poll(OWNER) == 1
    output = C.create_string_buffer(b'Z'*72)
    length = C.c_size_t(99)
    assert d.key_crypto_job_take(OWNER, output, 72, C.byref(length)) < 0
    assert length.value == 0 and bytes(output)[:72] == bytes(72)
    assert run(d)[0] == 0
    rc, signature, _ = take(d)
    assert rc == 0
    ec.derive_private_key(17, ec.SECP256R1()).public_key().verify(
        signature, HASH, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def test_wrong_owner_cannot_progress_cancel_or_take(crypto_job):
    d = crypto_job
    assert d.key_crypto_job_begin(OWNER, 1, PRIVATE, None, secure_random, None) == 0
    assert d.key_crypto_job_poll(OWNER+1) < 0
    assert d.key_crypto_job_cancel(OWNER+1) < 0
    output = C.create_string_buffer(72)
    size = C.c_size_t()
    assert d.key_crypto_job_take(OWNER+1, output, 72, C.byref(size)) < 0
    assert run(d)[0] == 0 and take(d)[0] == 0


@pytest.mark.parametrize('mode', [1, 2])
def test_busy_no_replacement_and_sync_ecc_rejected(crypto_job, mode):
    d = crypto_job
    assert d.key_crypto_job_begin(OWNER, mode, PRIVATE, HASH, secure_random, None) == 0
    assert d.key_crypto_job_begin(OWNER+1, mode, PRIVATE, HASH, secure_random, None) == -4
    public = C.create_string_buffer(65)
    assert d.key_crypto_p256_public(PRIVATE, public, secure_random, None) == -4
    assert bytes(public) == bytes(65)
    signature = C.create_string_buffer(72)
    length = C.c_size_t(999)
    assert d.key_crypto_p256_sign(PRIVATE, HASH, signature, 72, C.byref(length), secure_random, None) == -4
    assert length.value == 0
    assert d.key_crypto_job_cancel(OWNER) == 0
    assert d.key_crypto_p256_public(PRIVATE, public, secure_random, None) == 0


@pytest.mark.parametrize('mode', [1, 2])
@pytest.mark.parametrize('steps', [0, 1, 10])
def test_cancel_in_progress_releases_arena_and_result(crypto_job, mode, steps):
    d = crypto_job
    for _ in range(40):
        assert d.key_crypto_job_begin(OWNER, mode, PRIVATE, HASH, secure_random, None) == 0
        for _ in range(steps):
            assert d.key_crypto_job_poll(OWNER) == 1
        assert d.key_crypto_job_cancel(OWNER) == 0
        assert take(d)[0] < 0
        assert d.key_crypto_init() == 0
    assert d.key_crypto_job_begin(OWNER, mode, PRIVATE, HASH, secure_random, None) == 0
    assert run(d)[0] == 0 and take(d)[0] == 0


@pytest.mark.parametrize('mode', [1, 2])
def test_rng_failure_has_no_result_and_can_recover(crypto_job, mode):
    d = crypto_job
    assert d.key_crypto_job_begin(OWNER, mode, PRIVATE, HASH, RNG(), None) == -2
    assert d.key_crypto_job_begin(OWNER, mode, PRIVATE, HASH, failed_random, None) == 0
    assert run(d)[0] < 0
    assert take(d)[0] < 0
    assert d.key_crypto_job_cancel(OWNER) == 0
    assert d.key_crypto_job_begin(OWNER, mode, PRIVATE, HASH, secure_random, None) == 0
    assert run(d)[0] == 0 and take(d)[0] == 0


@pytest.mark.parametrize('scalar', [0, 2**256-1])
def test_invalid_scalar_does_not_leave_busy_state(crypto_job, scalar):
    d = crypto_job
    assert d.key_crypto_job_begin(OWNER, 1, scalar.to_bytes(32, 'big'), None, secure_random, None) < 0
    assert d.key_crypto_job_begin(OWNER, 1, PRIVATE, None, secure_random, None) == 0


def test_capacity_failure_preserves_complete_result_for_retry(crypto_job):
    d = crypto_job
    assert d.key_crypto_job_begin(OWNER, 1, PRIVATE, None, secure_random, None) == 0
    assert run(d)[0] == 0
    assert take(d, 64)[0] < 0
    assert take(d, 65)[0] == 0


def test_cancel_completed_job_revokes_result(crypto_job):
    d = crypto_job
    assert d.key_crypto_job_begin(OWNER, 2, PRIVATE, HASH, secure_random, None) == 0
    assert run(d)[0] == 0
    assert d.key_crypto_job_cancel(OWNER) == 0
    assert take(d)[0] < 0


@pytest.mark.parametrize('owner,mode,private,hash_value', [
    (0, 1, PRIVATE, None), (OWNER, 0, PRIVATE, None),
    (OWNER, 99, PRIVATE, HASH), (OWNER, 1, None, None),
    (OWNER, 2, PRIVATE, None),
])
def test_invalid_job_parameters_leave_idle(crypto_job, owner, mode, private, hash_value):
    d = crypto_job
    assert d.key_crypto_job_begin(owner, mode, private, hash_value, secure_random, None) == -1
    assert d.key_crypto_job_begin(OWNER, 1, PRIVATE, None, secure_random, None) == 0
