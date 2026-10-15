"""Actual C LCD protocol over a simulated bus, not physical display evidence."""
import ctypes as C
import pytest

WRITE = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_bool, C.c_uint16)
READ = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(C.c_uint16))
DELAY = C.CFUNCTYPE(None, C.c_void_p, C.c_uint32)
SERVICE = C.CFUNCTYPE(None, C.c_void_p)


class Bus(C.Structure):
    _fields_ = [('write', WRITE), ('read', READ), ('delay', DELAY), ('service', SERVICE)]


class LCD(C.Structure):
    _fields_ = [('bus', Bus), ('context', C.c_void_p), ('controller', C.c_uint16),
                ('id04', C.c_uint8 * 4), ('idd3', C.c_uint8 * 4), ('ready', C.c_bool)]


class Panel:
    def __init__(self, kind=0x9341, fail_write=0, fail_read=0, upper=0):
        self.kind, self.fail_write, self.fail_read = kind, fail_write, fail_read
        self.writes, self.reads, self.delays, self.services = [], 0, [], 0
        self.command, self.index = None, 0
        self.upper = upper
        self.bus = Bus(WRITE(self.write), READ(self.read), DELAY(self.delay), SERVICE(self.service))

    def write(self, _, data, value):
        self.writes.append((bool(data), value))
        if not data:
            self.command, self.index = value, 0
        return -1 if len(self.writes) == self.fail_write else 0

    def read(self, _, out):
        self.reads += 1
        values = [0, 0, self.kind >> 8, self.kind & 255] if (
            (self.command == 4 and self.kind == 0x8552) or self.command == 0xd3
        ) else [0, 0, 0, 0]
        out[0] = values[self.index] | self.upper
        self.index += 1
        return -1 if self.reads == self.fail_read else 0

    def delay(self, _, ms):
        self.delays.append(ms)

    def service(self, _):
        self.services += 1


def initialize(lib, panel):
    lib.key_lcd_init.argtypes = [C.POINTER(LCD), C.POINTER(Bus), C.c_void_p]
    lib.key_lcd_fill.argtypes = [C.POINTER(LCD), C.c_uint16, C.c_uint16,
                                C.c_uint16, C.c_uint16, C.c_uint16]
    lcd = LCD()
    rc = lib.key_lcd_init(C.byref(lcd), C.byref(panel.bus), None)
    return rc, lcd


def test_probe_before_initialization_and_landscape_rgb565(lib):
    panel = Panel()
    rc, lcd = initialize(lib, panel)
    assert rc == 0 and lcd.ready and lcd.controller == 0x9341
    assert panel.writes == [(False, 4), (False, 0xd3), (False, 1), (False, 0x11),
                            (False, 0x3a), (True, 0x55), (False, 0x36),
                            (True, 0x28), (False, 0x29)]
    assert panel.delays == [150, 120]


@pytest.mark.parametrize('kind', [0, 0xffff, 0x1234, 0x8552])
def test_unknown_or_unimplemented_panel_receives_only_identification(lib, kind):
    panel = Panel(kind)
    rc, lcd = initialize(lib, panel)
    assert rc == -3 and not lcd.ready
    assert panel.writes == ([(False, 4)] if kind == 0x8552 else [(False, 4), (False, 0xd3)])
    assert lcd.controller == (0x8552 if kind == 0x8552 else 0)
    assert not panel.delays


def test_rect_window_exact_coordinates_and_pixel_count(lib):
    panel = Panel()
    _, lcd = initialize(lib, panel)
    panel.writes.clear()
    assert lib.key_lcd_fill(C.byref(lcd), 318, 238, 2, 2, 0xf81f) == 0
    assert panel.writes == [(False, 0x2a), (True, 1), (True, 62), (True, 1), (True, 63),
                            (False, 0x2b), (True, 0), (True, 238), (True, 0), (True, 239),
                            (False, 0x2c)] + [(True, 0xf81f)] * 4


@pytest.mark.parametrize('rect', [(320,0,1,1), (0,240,1,1), (319,0,2,1),
    (0,239,1,2), (0,0,0,1), (0,0,1,0), (0,0,65535,1), (65535,0,1,1)])
def test_invalid_rectangles_do_not_issue_bus_transactions(lib, rect):
    panel = Panel()
    _, lcd = initialize(lib, panel)
    panel.writes.clear()
    assert lib.key_lcd_fill(C.byref(lcd), *rect, 0) == -1
    assert not panel.writes and lcd.ready


def test_full_screen_is_streamed_with_bounded_service_intervals(lib):
    panel = Panel()
    _, lcd = initialize(lib, panel)
    panel.writes.clear()
    assert lib.key_lcd_fill(C.byref(lcd), 0, 0, 320, 240, 0x1234) == 0
    assert len(panel.writes) == 11 + 320 * 240
    assert panel.services == 601


@pytest.mark.parametrize('failure', range(1, 10))
def test_init_write_failure_stops_immediately(lib, failure):
    panel = Panel(fail_write=failure)
    rc, lcd = initialize(lib, panel)
    assert rc == -2 and not lcd.ready and len(panel.writes) == failure


@pytest.mark.parametrize('failure', range(1, 9))
def test_probe_read_failure_never_enables_display(lib, failure):
    panel = Panel(fail_read=failure)
    rc, lcd = initialize(lib, panel)
    assert rc == -2 and not lcd.ready
    assert not panel.delays


@pytest.mark.parametrize('failure', range(1, 16))
def test_rect_io_failure_invalidates_panel_until_reinit(lib, failure):
    panel = Panel()
    _, lcd = initialize(lib, panel)
    panel.writes.clear()
    panel.fail_write = failure
    assert lib.key_lcd_fill(C.byref(lcd), 0, 0, 2, 2, 0) == -2
    assert not lcd.ready and len(panel.writes) == failure
    assert lib.key_lcd_fill(C.byref(lcd), 0, 0, 1, 1, 0) == -1


@pytest.mark.parametrize('upper', [0x0100, 0xff00, 0x5500, 0xaa00])
def test_id_register_unused_upper_bus_bits_are_ignored(lib, upper):
    panel = Panel(upper=upper)
    rc, lcd = initialize(lib, panel)
    assert rc == 0 and lcd.controller == 0x9341


def test_null_or_uninitialized_state_has_no_io(lib):
    panel = Panel()
    initialize(lib, panel)  # configure ctypes signatures
    assert lib.key_lcd_init(None, C.byref(panel.bus), None) == -1
    state = LCD()
    assert lib.key_lcd_init(C.byref(state), None, None) == -1
    assert not state.ready
    assert lib.key_lcd_fill(C.byref(state), 0, 0, 1, 1, 0) == -1
    assert lib.key_lcd_fill(None, 0, 0, 1, 1, 0) == -1


@pytest.mark.parametrize('missing', ['write', 'read', 'delay'])
def test_missing_required_callbacks_rejected_before_io(lib, missing):
    panel = Panel()
    callbacks = {'write': panel.bus.write, 'read': panel.bus.read,
                 'delay': panel.bus.delay, 'service': panel.bus.service}
    callbacks[missing] = {'write': WRITE, 'read': READ, 'delay': DELAY}[missing]()
    bus = Bus(**callbacks)
    state = LCD()
    initialize(lib, Panel())
    assert lib.key_lcd_init(C.byref(state), C.byref(bus), None) == -1
    assert not state.ready and not panel.writes


def test_same_panel_can_be_reinitialized_with_its_owned_bus_copy(lib):
    panel = Panel()
    _, state = initialize(lib, panel)
    assert lib.key_lcd_init(C.byref(state), C.byref(state.bus), None) == 0
    assert state.ready and state.controller == 0x9341


def test_optional_service_callback_can_be_absent(lib):
    panel = Panel()
    panel.bus.service = SERVICE()
    rc, state = initialize(lib, panel)
    assert rc == 0
    assert lib.key_lcd_fill(C.byref(state), 0, 0, 16, 16, 0) == 0
    assert not panel.services
