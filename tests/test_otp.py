"""Public RFC fixture secrets only; actual C code, no board/SD access."""
import ctypes as C
import hashlib
import hmac
import pytest


class Parameters(C.Structure):
    _fields_ = [('algorithm', C.c_uint32), ('digits', C.c_uint32),
                ('period', C.c_uint32), ('epoch', C.c_uint64)]


class View(C.Structure):
    _fields_ = [('counter', C.c_uint64), ('remaining', C.c_uint32),
                ('current', C.c_char * 9), ('next', C.c_char * 9),
                ('next_valid', C.c_bool)]


def totp(lib, secret, now, algorithm=1, digits=8, period=30, epoch=0, trusted=True):
    lib.key_otp_totp.argtypes = [C.POINTER(Parameters), C.c_void_p, C.c_size_t,
                                C.c_uint64, C.c_bool, C.POINTER(View)]
    lib.key_otp_totp.restype = C.c_int
    params = Parameters(algorithm, digits, period, epoch)
    view = View()
    C.memset(C.byref(view), 0x58, C.sizeof(view))
    rc = lib.key_otp_totp(C.byref(params), secret, len(secret), now, trusted, C.byref(view))
    return rc, view


def hotp(lib, secret, counter, algorithm=1, digits=6, capacity=9):
    lib.key_otp_hotp.argtypes = [C.c_uint, C.c_uint, C.c_void_p, C.c_size_t,
                                C.c_uint64, C.c_void_p, C.c_size_t]
    lib.key_otp_hotp.restype = C.c_int
    out = C.create_string_buffer(b'X' * 9, 10)
    rc = lib.key_otp_hotp(algorithm, digits, secret, len(secret), counter, out, capacity)
    return rc, out


def test_rfc4226_first_hotp(lib):
    rc, out = hotp(lib, b'12345678901234567890', 0)
    assert rc == 0
    assert out.value == b'755224'


def test_rfc6238_first_totp(lib):
    rc, view = totp(lib, b'12345678901234567890', 59)
    assert rc == 0
    assert view.current == b'94287082'
    assert view.counter == 1
    assert view.remaining == 1


@pytest.mark.parametrize('counter,expected', list(enumerate([
    '755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489'])))
def test_rfc4226_vectors(lib, counter, expected):
    rc, out = hotp(lib, b'12345678901234567890', counter)
    assert rc == 0 and out.value.decode() == expected


# RFC 6238 Appendix B: SHA1 uses 20B, SHA256 32B, SHA512 64B secrets.
@pytest.mark.parametrize('now,expected', [
    (59, ('94287082', '46119246', '90693936')),
    (1111111109, ('07081804', '68084774', '25091201')),
    (1111111111, ('14050471', '67062674', '99943326')),
    (1234567890, ('89005924', '91819424', '93441116')),
    (2000000000, ('69279037', '90698825', '38618901')),
    (20000000000, ('65353130', '77737706', '47863826')),
])
@pytest.mark.parametrize('algorithm,length', [(1, 20), (2, 32), (3, 64)])
def test_rfc6238_all_algorithms(lib, now, expected, algorithm, length):
    secret = (b'1234567890' * 7)[:length]
    rc, view = totp(lib, secret, now, algorithm)
    assert rc == 0
    assert view.current.decode() == expected[algorithm - 1]
    assert view.counter == now // 30
    assert view.remaining == 30 - now % 30
    assert view.next_valid
    assert view.next.decode() == oracle(secret, view.counter + 1, algorithm, 8)


def oracle(secret, counter, algorithm, digits):
    fn = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha512}[algorithm]
    mac = hmac.digest(secret, counter.to_bytes(8, 'big'), fn)
    offset = mac[-1] & 15
    number = int.from_bytes(mac[offset:offset + 4], 'big') & 0x7fffffff
    return str(number % (10 ** digits)).zfill(digits)


@pytest.mark.parametrize('algorithm', [1, 2, 3])
@pytest.mark.parametrize('digits', [6, 7, 8])
@pytest.mark.parametrize('length', [16, 20, 32, 64, 65, 128])
@pytest.mark.parametrize('counter', [0, 1, 2**32, 2**63, 2**64 - 1])
def test_hotp_independent_hmac_oracle(lib, algorithm, digits, length, counter):
    secret = bytes((i * 73 + 11) % 256 for i in range(length))
    rc, out = hotp(lib, secret, counter, algorithm, digits)
    assert rc == 0
    assert out.value.decode() == oracle(secret, counter, algorithm, digits)
    assert out.raw[9] == 0  # extra byte beyond the declared capacity unchanged


@pytest.mark.parametrize('now', [0, 29, 30, 31, 59, 60, 2**32, 2**64 - 1])
@pytest.mark.parametrize('period', [1, 30, 60, 86400])
def test_totp_boundary_countdown_and_next(lib, now, period):
    secret = bytes(range(32))
    rc, view = totp(lib, secret, now, algorithm=2, period=period)
    assert rc == 0
    assert view.remaining == period - now % period
    assert view.current.decode() == oracle(secret, now // period, 2, 8)
    if now // period == 2**64 - 1:
        assert not view.next_valid and view.next == b''
    else:
        assert view.next_valid
        assert view.next.decode() == oracle(secret, now // period + 1, 2, 8)


def test_nonzero_epoch_and_post_2038(lib):
    secret = bytes(range(32))
    rc, view = totp(lib, secret, 20000000000, algorithm=3, epoch=1234567890, period=60)
    assert rc == 0
    assert view.counter == (20000000000 - 1234567890) // 60
    assert view.current.decode() == oracle(secret, view.counter, 3, 8)


@pytest.mark.parametrize('kwargs', [
    {'trusted': False}, {'epoch': 61}, {'period': 0}, {'period': 86401},
    {'algorithm': 0}, {'algorithm': 4}, {'digits': 0}, {'digits': 5}, {'digits': 9},
])
def test_totp_rejects_invalid_or_untrusted_and_clears_view(lib, kwargs):
    rc, view = totp(lib, bytes(range(32)), 60, **kwargs)
    assert rc == (-2 if kwargs.get('trusted') is False else -1)
    assert bytes(view) == bytes(C.sizeof(view))


@pytest.mark.parametrize('length', [0, 1, 15, 129])
def test_invalid_secret_length_wipes_output(lib, length):
    secret = b'A' * length
    rc, out = hotp(lib, secret, 0)
    assert rc == -1 and out.raw[:9] == bytes(9)
    rc, view = totp(lib, secret, 60)
    assert rc == -1 and bytes(view) == bytes(C.sizeof(view))


@pytest.mark.parametrize('capacity', range(7))
def test_small_output_capacity_never_writes_beyond_it(lib, capacity):
    rc, out = hotp(lib, bytes(range(32)), 0, capacity=capacity)
    assert rc == -1
    assert out.raw[:capacity] == bytes(capacity)
    assert out.raw[capacity:9] == b'X' * (9 - capacity)


@pytest.mark.parametrize('digits', [6, 7, 8])
def test_exact_output_capacity_and_secret_unchanged(lib, digits):
    secret = C.create_string_buffer(bytes(range(32)), 32)
    original = secret.raw
    out = C.create_string_buffer(b'Z' * 12, 12)
    hotp(lib, original, 0)  # establish the public ctypes signature
    assert lib.key_otp_hotp(1, digits, secret, 32, 0, out, digits + 1) == 0
    assert out.value.decode() == oracle(original, 0, 1, digits)
    assert out.raw[digits + 1:] == b'Z' * (11 - digits)
    assert secret.raw == original


def test_null_inputs_fail_closed(lib):
    secret = bytes(range(32))
    hotp(lib, secret, 0)
    out = C.create_string_buffer(b'X' * 9, 9)
    assert lib.key_otp_hotp(1, 6, None, 32, 0, out, 9) == -1
    assert out.raw == bytes(9)
    assert lib.key_otp_hotp(1, 6, secret, 32, 0, None, 9) == -1
    totp(lib, secret, 60)
    view = View()
    C.memset(C.byref(view), 0x58, C.sizeof(view))
    assert lib.key_otp_totp(None, secret, 32, 60, True, C.byref(view)) == -1
    assert bytes(view) == bytes(C.sizeof(view))
    params = Parameters(1, 6, 30, 0)
    assert lib.key_otp_totp(C.byref(params), secret, 32, 60, True, None) == -1


def test_repeated_hmac_does_not_exhaust_shared_crypto_arena(lib):
    secret = bytes(range(128))
    for counter in range(1000):
        algorithm = 1 + counter % 3
        rc, out = hotp(lib, secret, counter, algorithm)
        assert rc == 0 and out.value.decode() == oracle(secret, counter, algorithm, 6)


@pytest.mark.parametrize('with_service', [False, True])
def test_actual_startup_selftest_snapshot(lib, with_service):
    class Snapshot(C.Structure):
        _fields_ = [('magic', C.c_uint32), ('sequence', C.c_uint32),
                    ('tested', C.c_uint32), ('passed', C.c_uint32),
                    ('failed_case', C.c_uint32), ('error', C.c_int32)]
    calls = []
    callback = C.CFUNCTYPE(None)(lambda: calls.append(1))
    lib.key_otp_selftest_run.argtypes = [C.c_void_p]
    lib.key_otp_selftest_run(callback if with_service else None)
    status = Snapshot.in_dll(lib, 'key_otp_snapshot')
    assert status.magic == 0x4f545031 and status.sequence == 2
    assert status.tested == status.passed == 18
    assert status.failed_case == status.error == 0
    assert len(calls) == (18 if with_service else 0)
