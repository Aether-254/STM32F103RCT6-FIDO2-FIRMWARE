"""Actual C SPI protocol with a simulated card; no physical card access."""
import binascii
import ctypes as C
from collections import deque
import pytest

TRANSFER = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_uint8, C.POINTER(C.c_uint8))
SELECT = C.CFUNCTYPE(None, C.c_void_p, C.c_bool)
TICK = C.CFUNCTYPE(C.c_uint32, C.c_void_p)
POLL = C.CFUNCTYPE(None, C.c_void_p)


class Bus(C.Structure):
    _fields_ = [('transfer', TRANSFER), ('select', SELECT), ('tick', TICK), ('poll', POLL)]


class SD(C.Structure):
    _fields_ = [('bus', Bus), ('context', C.c_void_p), ('sectors', C.c_uint64),
                ('deadline', C.c_uint32), ('exchanges', C.c_uint32),
                ('csd', C.c_uint8 * 16), ('cid', C.c_uint8 * 16),
                ('ready', C.c_bool), ('block_addressed', C.c_bool)]


def csd(v2=True, size=8191):
    value = ((1 << 126) if v2 else 0) | (9 << 80) | 1
    value |= (size << 48) if v2 else ((size << 62) | (7 << 47))
    return value.to_bytes(16, 'big')


class Card:
    def __init__(self, v2=True, bad_crc=False, stuck=False, io_error=False,
                 bad_echo=False, start=0):
        self.v2, self.bad_crc, self.stuck = v2, bad_crc, stuck
        self.io_error, self.bad_echo = io_error, bad_echo
        self.active, self.packet = False, []
        self.queue, self.commands = deque(), []
        self.polls, self.calls, self.start = 0, 0, start
        self.data = bytes(range(256)) * 2
        self.bus = Bus(TRANSFER(self.transfer), SELECT(self.select),
                       TICK(lambda _: (self.start + self.calls // 4) & 0xffffffff),
                       POLL(self.poll))

    def select(self, _, active):
        self.active = active
        if not active:
            self.packet.clear()
            self.queue.clear()

    def poll(self, _):
        self.polls += 1

    def payload(self, data):
        crc = binascii.crc_hqx(data, 0) ^ (1 if self.bad_crc else 0)
        return [0, 0xff, 0xfe, *data, crc >> 8, crc & 255]

    def transfer(self, _, tx, out):
        self.calls += 1
        out[0] = 255
        if self.io_error:
            return -1
        if not self.active:
            return 0
        if self.queue:
            out[0] = self.queue.popleft()
        elif self.packet or (tx & 0xc0) == 0x40:
            self.packet.append(tx)
            if len(self.packet) == 6:
                cmd = self.packet[0] & 63
                arg = int.from_bytes(bytes(self.packet[1:5]), 'big')
                self.commands.append((cmd, arg, self.packet[5]))
                response = {
                    0: [1], 8: [1, 0, 0, 1, 0xab if self.bad_echo else 0xaa]
                    if self.v2 else [5], 55: [1], 41: [1 if self.stuck else 0],
                    58: [0, 0xc0 if self.v2 else 0x80, 0x30, 0, 0], 16: [0],
                    9: self.payload(csd(self.v2, 8191 if self.v2 else 4095)),
                    10: self.payload(bytes(range(16))), 17: self.payload(self.data),
                }.get(cmd, [4])
                self.queue.extend(response)
                self.packet.clear()
        return 0


@pytest.fixture
def driver(lib):
    lib.key_sd_readonly_init.argtypes = [C.POINTER(SD), C.POINTER(Bus), C.c_void_p]
    lib.key_sd_readonly_read.argtypes = [C.POINTER(SD), C.c_uint64, C.c_void_p]
    lib.key_sd_csd_sectors.argtypes = [C.c_void_p, C.c_bool, C.POINTER(C.c_uint64)]
    return lib


@pytest.mark.parametrize('v2,start', [(True, 0), (False, 0), (True, 0xfffffff0)])
def test_init_read_crc_addressing_and_poll(driver, v2, start):
    card, state = Card(v2=v2, start=start), SD()
    assert driver.key_sd_readonly_init(C.byref(state), C.byref(card.bus), None) == 0
    assert state.ready and state.block_addressed == v2
    assert state.sectors == (8388608 if v2 else 2097152)
    assert bytes(state.cid) == bytes(range(16))
    out = (C.c_uint8 * 512)()
    assert driver.key_sd_readonly_read(C.byref(state), 7, out) == 0
    assert bytes(out) == card.data
    assert card.commands[-1][:2] == (17, 7 if v2 else 3584)
    assert card.commands[0][2] == 0x95
    assert card.commands[1][2] == 0x87
    assert card.polls and not card.active
    assert set(c[0] for c in card.commands) <= {0, 8, 9, 10, 16, 17, 41, 55, 58}


@pytest.mark.parametrize('options,error', [({'bad_crc': True}, -5),
    ({'stuck': True}, -3), ({'io_error': True}, -2), ({'bad_echo': True}, -4)])
def test_init_fail_closed(driver, options, error):
    card, state = Card(**options), SD()
    assert driver.key_sd_readonly_init(C.byref(state), C.byref(card.bus), None) == error
    assert not state.ready and state.sectors == 0 and not card.active
    assert bytes(state.csd) == bytes(16) and bytes(state.cid) == bytes(16)


def test_read_bad_crc_wipes_output_and_invalidates(driver):
    card, state = Card(), SD()
    assert driver.key_sd_readonly_init(C.byref(state), C.byref(card.bus), None) == 0
    card.bad_crc = True
    out = (C.c_uint8 * 512)(*([0xa5] * 512))
    assert driver.key_sd_readonly_read(C.byref(state), 0, out) == -5
    assert bytes(out) == bytes(512) and not state.ready and not card.active


@pytest.mark.parametrize('lba', [8388608, 0xffffffff, 0x100000000, 0xffffffffffffffff])
def test_out_of_range_read_no_card_command(driver, lba):
    card, state = Card(), SD()
    assert driver.key_sd_readonly_init(C.byref(state), C.byref(card.bus), None) == 0
    calls = card.calls
    out = (C.c_uint8 * 512)(*([0xa5] * 512))
    assert driver.key_sd_readonly_read(C.byref(state), lba, out) == -1
    assert bytes(out) == bytes(512) and card.calls == calls


@pytest.mark.parametrize('size', [0, 8191, 0x3fffff])
def test_csd_v2_capacity_64bit(driver, size):
    out = C.c_uint64(0)
    assert driver.key_sd_csd_sectors(csd(True, size), True, C.byref(out)) == 0
    assert out.value == (size + 1) * 1024


@pytest.mark.parametrize('raw,block', [(bytes(16), False), (csd(True), False),
    (csd(False, 4095), True), (((2 << 126) | 1).to_bytes(16, 'big'), True)])
def test_invalid_csd_clears_capacity(driver, raw, block):
    out = C.c_uint64(123)
    assert driver.key_sd_csd_sectors(raw, block, C.byref(out)) == -4
    assert out.value == 0
