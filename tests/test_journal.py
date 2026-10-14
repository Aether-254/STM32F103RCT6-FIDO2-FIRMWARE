"""Portable C journal on a 1->0 / halfword host flash model; no hardware I/O."""
import ctypes as C
import hashlib
import hmac
import random
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from test_vault import ROOT_KEY, CONTEXT

READ = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t)
PROGRAM = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t)
ERASE = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint)


class IO(C.Structure):
    _fields_ = [("read", READ), ("program", PROGRAM), ("erase", ERASE)]


class State(C.Structure):
    _fields_ = [("serial", C.c_uint64), ("nonce", C.c_uint64), ("sign_count", C.c_uint32)]


class Journal(C.Structure):
    _fields_ = [("io", C.POINTER(IO)), ("context", C.c_void_p), ("key", C.c_ubyte * 32),
                ("state", State), ("page_state", State * 2),
                ("next_slot", C.c_uint * 2), ("healthy", C.c_bool * 2), ("ready", C.c_bool)]


class Flash:
    def __init__(self, image=None):
        self.image = bytearray(b"\xff" * 4096 if image is None else image)
        self.remaining = None
        self.read_fail = False
        self.program_calls = 0
        self.erase_calls = 0
        self.events = 0
        self.invalid = []
        self.callbacks = READ(self.read), PROGRAM(self.program), ERASE(self.erase)
        self.io = IO(*self.callbacks)

    def event(self):
        if self.remaining is not None:
            if self.remaining == 0:
                return False
            self.remaining -= 1
        self.events += 1
        return True

    def read(self, ctx, offset, output, length):
        if self.read_fail or offset + length > 4096:
            return -1
        C.memmove(output, bytes(self.image[offset:offset+length]), length)
        return 0

    def program(self, ctx, offset, source, length):
        self.program_calls += 1
        if offset % 2 or length % 2 or offset + length > 4096:
            self.invalid.append("unaligned/out-of-range")
            return -1
        data = C.string_at(source, length)
        for i in range(0, length, 2):
            if not self.event():
                return -1
            for k in range(2):
                old, new = self.image[offset+i+k], data[i+k]
                if old & new != new:
                    self.invalid.append("0->1")
                    return -1
                self.image[offset+i+k] = new
        return 0

    def erase(self, ctx, page):
        self.erase_calls += 1
        if page not in (0, 1):
            self.invalid.append("bad page")
            return -1
        # Conservative interrupted erase model; real voltage faults may have
        # different bit patterns and require board fault injection later.
        for i in range(0, 2048, 2):
            if not self.event():
                return -1
            self.image[page*2048+i:page*2048+i+2] = b"\xff\xff"
        return 0


@pytest.fixture
def api(lib):
    for name in ["recover", "provision"]:
        getattr(lib, "key_journal_" + name).argtypes = [C.POINTER(Journal), C.POINTER(IO),
                                                      C.c_void_p, C.c_void_p, C.c_void_p]
    lib.key_journal_reserve.argtypes = [C.POINTER(Journal), C.c_uint64, C.c_uint32,
                                      C.POINTER(C.c_uint64), C.POINTER(C.c_uint32)]
    lib.key_journal_dispose.argtypes = [C.POINTER(Journal)]
    lib.key_journal_dispose.restype = None
    lib.key_crypto_hmac.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p]
    return lib


def attach(api, flash, provision=False, root=ROOT_KEY, context=CONTEXT):
    j = Journal()
    fn = api.key_journal_provision if provision else api.key_journal_recover
    status = fn(C.byref(j), C.byref(flash.io), None, root, context)
    assert not flash.invalid
    return status, j


def reserve(api, flash, j, nonce=1, sign=1):
    nf, sf = C.c_uint64(999), C.c_uint32(999)
    status = api.key_journal_reserve(C.byref(j), nonce, sign, C.byref(nf), C.byref(sf))
    assert not flash.invalid
    if status:
        assert nf.value == sf.value == 0
    return status, nf.value, sf.value


def journal_key(root=ROOT_KEY, context=CONTEXT):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=context,
                info=b"stm32-fido2/high-water-journal/v2").derive(root)


def encoded(serial, nonce, count, marker=b"\xa5\x5a"):
    header = (b"F2JW\x02\0\0\0" + serial.to_bytes(8, "big") +
              nonce.to_bytes(8, "big") + count.to_bytes(4, "big") + bytes(4))
    return header + hmac.digest(journal_key(), header, "sha256") + bytes(14) + marker


def same_state(a, b):
    return (a.serial, a.nonce, a.sign_count) == (b.serial, b.nonce, b.sign_count)


def test_hmac_independent_oracle(api):
    for message in [b"", b"test", bytes(range(256)) * 16]:
        output = C.create_string_buffer(32)
        assert api.key_crypto_hmac(ROOT_KEY, message, len(message), output) == 0
        assert output.raw == hmac.digest(ROOT_KEY, message, hashlib.sha256)


def test_empty_read_only_and_explicit_genesis(api):
    f = Flash()
    assert attach(api, f)[0] == -2
    assert f.program_calls == f.erase_calls == 0
    status, j = attach(api, f, provision=True)
    assert status == 0 and j.ready
    assert f.image[:80] == encoded(1, 0, 0)
    assert f.image[2048:2128] == encoded(1, 0, 0)
    assert f.erase_calls == 0
    before = bytes(f.image)
    assert attach(api, f, provision=True)[0] < 0
    assert bytes(f.image) == before


def test_allocations_batch_and_reboot_burn(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 64, 32) == (0, 1, 1)
    assert f.image[80:160] == encoded(2, 64, 32)
    assert f.image[2128:2208] == encoded(2, 64, 32)
    # All unused cached values are deliberately discarded on restart.
    _, recovered = attach(api, f)
    assert reserve(api, f, recovered, 3, 5) == (0, 65, 33)
    assert reserve(api, f, recovered, 0, 1) == (0, 0, 38)
    assert reserve(api, f, recovered, 1, 0) == (0, 68, 0)
    assert reserve(api, f, recovered, 0, 0)[0] == -1


def test_many_rollovers(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    for i in range(150):
        assert reserve(api, f, j, 64, 32) == (0, i*64+1, i*32+1)
        status, j = attach(api, f)
        assert status == 0
    assert j.state.serial == 151 and f.erase_calls == 12


@pytest.mark.parametrize("cut", range(81))
def test_append_power_cut_every_halfword(api, cut):
    f = Flash()
    _, j = attach(api, f, provision=True)
    f.remaining = cut
    status, _, _ = reserve(api, f, j, 64, 32)
    if status:
        assert not j.ready
        assert reserve(api, f, j)[0] < 0
    f.remaining = None
    status, recovered = attach(api, f)
    assert status == 0
    # May burn an authenticated prepared range; must never reuse an issued one.
    assert recovered.state.nonce in (0, 64)
    if cut >= 32:
        assert recovered.state.nonce == 64  # complete HMAC despite missing padding/marker
    result = reserve(api, f, recovered, 64, 32)
    assert result == (0, recovered.state.nonce-63, recovered.state.sign_count-31)
    if cut >= 32:
        assert result == (0, 65, 33)
    assert min(recovered.next_slot) >= 2


@pytest.mark.parametrize("cut", range(81))
def test_genesis_power_cut_no_automatic_reset(api, cut):
    f = Flash()
    f.remaining = cut
    attach(api, f, provision=True)
    f.remaining = None
    status, j = attach(api, f)
    if cut == 0:
        assert status == -2
    elif cut < 32:
        assert status == -3
        before = bytes(f.image)
        assert attach(api, f, provision=True)[0] == -3
        assert bytes(f.image) == before
    else:
        assert status == 0
        assert reserve(api, f, j) == (0, 1, 1)


@pytest.fixture
def rollover_image(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    # Fill both mirrors; each page is erased only while the other retains state.
    for _ in range(24):
        assert reserve(api, f, j, 64, 32)[0] == 0
    assert list(j.next_slot) == [25, 25]
    return bytes(f.image)


@pytest.mark.parametrize("cut", range(2129))
def test_rollover_power_cut_every_erase_and_program_halfword(api, rollover_image, cut):
    f = Flash(rollover_image)
    _, j = attach(api, f)
    f.remaining = cut
    status, _, _ = reserve(api, f, j, 64, 32)
    f.remaining = None
    recovered_status, restored = attach(api, f)
    # EVERY interruption in this model must recover, not merely fail closed.
    assert recovered_status == 0
    assert restored.state.nonce >= 24*64
    if status == 0:
        assert restored.state.nonce >= 25*64
    assert reserve(api, f, restored, 64, 32)[1] >= 24*64+1
    _, again = attach(api, f)
    assert same_state(again.page_state[0], again.page_state[1])


@pytest.mark.parametrize("offset", range(80))
def test_committed_entry_corruption_never_rolls_back(api, offset):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 64, 32)[0] == 0
    f.image[80+offset] ^= 1
    status, recovered = attach(api, f)
    assert status == 0 and recovered.state.nonce >= 64
    assert reserve(api, f, recovered, 64, 32) == (0, 65, 33)
    _, again = attach(api, f)
    assert all(again.healthy) and same_state(again.page_state[0], again.page_state[1])


@pytest.mark.parametrize("case", ["root", "context", "decreasing", "zero-serial"])
def test_recovery_rejects_wrong_key_and_invalid_histories(api, case):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 64, 32)[0] == 0
    kwargs = {}
    if case == "root":
        kwargs["root"] = bytes(range(32))
    elif case == "context":
        kwargs["context"] = b"device000002"
    elif case == "decreasing":
        f.image[160:240] = encoded(3, 63, 33)
    else:
        f.image[160:240] = encoded(0, 100, 100)
        f.image[2208:2288] = encoded(0, 100, 100)
    assert attach(api, f, **kwargs)[0] == -3


def test_exhaustion_and_io_failure(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 2**64-1, 2**32-1) == (0, 1, 1)
    assert reserve(api, f, j, 1, 0)[0] == -5
    assert reserve(api, f, j, 0, 1)[0] == -5
    f.read_fail = True
    assert attach(api, f)[0] == -4


def test_serial_exhaustion_and_dispose(api):
    f = Flash()
    f.image[:80] = encoded(2**64-1, 100, 100)
    status, j = attach(api, f)
    assert status == 0
    assert reserve(api, f, j)[0] == -5
    api.key_journal_dispose(C.byref(j))
    assert bytes(j) == bytes(C.sizeof(j))


def test_uncertain_commit_after_full_write_burns_range(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    original = f.program
    def program_then_error(ctx, offset, source, length):
        result = original(ctx, offset, source, length)
        return -1 if length == 2 else result
    f.callbacks = READ(f.read), PROGRAM(program_then_error), ERASE(f.erase)
    f.io = IO(*f.callbacks)
    j.io = C.pointer(f.io)
    assert reserve(api, f, j, 64, 32)[0] == -4
    assert not j.ready
    f = Flash(f.image)  # Remove the injected callback fault before recovery.
    status, recovered = attach(api, f)
    assert status == 0
    assert reserve(api, f, recovered, 64, 32) == (0, 65, 33)


@pytest.mark.parametrize("page", [0, 1])
@pytest.mark.parametrize("damage", ["whole-erased", "whole-zero", "tail", "prefix"])
def test_single_page_loss_preserves_issued_ranges_and_repairs(api, page, damage):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 64, 32) == (0, 1, 1)
    start = page*2048
    if damage == "whole-erased":
        f.image[start:start+2048] = b"\xff" * 2048
    elif damage == "whole-zero":
        f.image[start:start+2048] = bytes(2048)
    elif damage == "tail":
        f.image[start+2000] = 0
    else:
        f.image[start:start+21] = b"\xff" * 21
    status, j = attach(api, f)
    assert status == 0 and j.state.nonce == 64 and j.state.sign_count == 32
    assert reserve(api, f, j, 64, 32) == (0, 65, 33)
    _, j = attach(api, f)
    assert all(j.healthy) and same_state(j.page_state[0], j.page_state[1])


def test_both_pages_damaged_fail_closed(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 64, 32)[0] == 0
    f.image[80] ^= 1
    f.image[2128] ^= 1
    assert attach(api, f)[0] == -3


def test_same_serial_authenticated_conflict_fail_closed(api):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 64, 32)[0] == 0
    f.image[2128:2208] = encoded(2, 128, 64)
    assert attach(api, f)[0] == -3


def test_v1_format_not_silently_reinitialized(api):
    f = Flash()
    for offset in [0, 2048]:
        old_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=CONTEXT,
                       info=b"stm32-fido2/high-water-journal/v1").derive(ROOT_KEY)
        header = b"F2JW\x01\0\0\0" + (1).to_bytes(8, "big") + bytes(16)
        f.image[offset:offset+80] = header + hmac.digest(old_key, header, "sha256") + bytes(14) + b"\xa5\x5a"
    before = bytes(f.image)
    assert attach(api, f)[0] == -3
    assert attach(api, f, provision=True)[0] == -3
    assert bytes(f.image) == before


@pytest.mark.parametrize("seed", range(10))
def test_repeated_random_fault_reboot_repair_chains(api, seed):
    rng = random.Random(seed)
    f = Flash()
    _, j = attach(api, f, provision=True)
    issued_nonce = issued_sign = 0
    for _ in range(150):
        amount, signs = rng.randrange(1, 65), rng.randrange(1, 33)
        f.remaining = None if rng.randrange(4) == 0 else rng.randrange(2200)
        status, nf, sf = reserve(api, f, j, amount, signs)
        if status == 0:
            assert nf > issued_nonce and sf > issued_sign
            issued_nonce, issued_sign = nf+amount-1, sf+signs-1
            assert same_state(j.page_state[0], j.page_state[1])
        f.remaining = None
        recovered, j = attach(api, f)
        assert recovered == 0
        assert j.state.nonce >= issued_nonce and j.state.sign_count >= issued_sign
    assert reserve(api, f, j)[0] == 0


@pytest.mark.parametrize("halfword", range(80))
@pytest.mark.parametrize("bits", [1, 4, 8, 12, 15])
def test_program_bit_torn_halfword_recovery(api, halfword, bits):
    base = Flash()
    assert attach(api, base, provision=True)[0] == 0
    f = Flash(base.image)
    unit = 0
    original = f.program
    def torn_program(ctx, offset, source, length):
        nonlocal unit
        data = C.string_at(source, length)
        for i in range(0, length, 2):
            if unit == halfword:
                intended = int.from_bytes(data[i:i+2], "little")
                # Some required zeros remain ones, never an impossible 0->1.
                partial = intended | (0xffff << bits & 0xffff)
                f.image[offset+i:offset+i+2] = partial.to_bytes(2, "little")
                return -1
            output = C.create_string_buffer(data[i:i+2], 2)
            if original(ctx, offset+i, output, 2):
                return -1
            unit += 1
        return 0
    f.callbacks = READ(f.read), PROGRAM(torn_program), ERASE(f.erase)
    f.io = IO(*f.callbacks)
    _, j = attach(api, f)
    assert reserve(api, f, j, 64, 32)[0] == -4
    f = Flash(f.image)
    status, j = attach(api, f)
    assert status == 0
    if halfword >= 32:
        assert j.state.nonce >= 64
    assert reserve(api, f, j)[0] == 0


def test_erase_driver_false_success_detected_before_allocation(api, rollover_image):
    f = Flash(rollover_image)
    f.callbacks = READ(f.read), PROGRAM(f.program), ERASE(lambda ctx, page: 0)
    f.io = IO(*f.callbacks)
    _, j = attach(api, f)
    before = bytes(f.image)
    assert reserve(api, f, j)[0] == -4 and not j.ready
    assert bytes(f.image) == before
