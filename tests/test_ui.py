"""Real portable C navigation/rendering, not hardware or Figma acceptance."""
import ctypes as C
import random
import pytest


class UI(C.Structure):
    _fields_ = [("changed_at", C.c_uint32), ("pressed_at", C.c_uint32),
                ("candidate", C.c_uint8), ("stable", C.c_uint8),
                ("selected", C.c_uint8), ("page", C.c_uint8),
                ("armed", C.c_bool), ("consumed", C.c_bool)]


RECT = C.CFUNCTYPE(C.c_int, C.c_void_p, *([C.c_uint16] * 5))


@pytest.fixture
def ui_api(lib):
    lib.key_ui_init.argtypes = [C.POINTER(UI), C.c_uint32]
    lib.key_ui_poll.argtypes = [C.POINTER(UI), C.c_uint32, C.c_uint8]
    lib.key_ui_poll.restype = C.c_bool
    lib.key_ui_render.argtypes = [C.POINTER(UI), RECT, C.c_void_p]
    lib.key_ui_render_update.argtypes = [C.POINTER(UI), C.POINTER(UI), RECT, C.c_void_p]
    return lib


class Input:
    def __init__(self, lib, start=0):
        self.lib, self.ui, self.now = lib, UI(), start
        lib.key_ui_init(C.byref(self.ui), start)

    def poll(self, dt, keys):
        self.now = (self.now + dt) & 0xffffffff
        return self.lib.key_ui_poll(C.byref(self.ui), self.now, keys)

    def stable(self, keys):
        self.poll(1, keys)
        return self.poll(35, keys)

    def arm(self):
        self.stable(0)
        assert self.ui.armed

    def tap(self, key):
        self.stable(key)
        return self.stable(0)


def test_navigation_select_enter_back_and_no_repeat(ui_api):
    inp = Input(ui_api)
    inp.arm()
    assert inp.tap(1) and inp.ui.selected == 1
    inp.stable(1)
    assert not inp.poll(699, 1)
    assert inp.poll(1, 1) and inp.ui.page == 2
    assert not inp.poll(4000, 1)
    assert not inp.stable(0)
    assert inp.ui.selected == 1
    assert inp.tap(2) and inp.ui.page == 0


def test_menu_wrap_and_detail_has_no_hidden_mutations(ui_api):
    inp = Input(ui_api)
    inp.arm()
    for _ in range(5):
        assert inp.tap(1)
    assert inp.ui.selected == 0
    inp.stable(1)
    assert inp.poll(700, 1)
    inp.stable(0)
    assert not inp.tap(1) and inp.ui.page == 1
    assert inp.tap(2) and inp.ui.page == 0
    assert not inp.tap(2)


@pytest.mark.parametrize("keys", [1, 2, 3])
def test_boot_held_keys_ignored_until_release(ui_api, keys):
    inp = Input(ui_api)
    inp.stable(keys)
    assert not inp.poll(5000, keys)
    assert inp.ui.page == inp.ui.selected == 0
    assert not inp.stable(0)
    assert inp.ui.armed
    assert inp.tap(1)


@pytest.mark.parametrize("first,second", [(1,3), (2,3), (1,2), (2,1)])
def test_chord_or_key_rollover_consumed_until_all_released(ui_api, first, second):
    inp = Input(ui_api)
    inp.arm()
    inp.stable(first)
    inp.stable(second)
    inp.poll(2000, second)
    inp.stable(first)
    inp.poll(2000, first)
    inp.stable(0)
    assert inp.ui.page == inp.ui.selected == 0
    assert inp.tap(1)


def test_bounce_and_release_pending_never_enter(ui_api):
    inp = Input(ui_api)
    inp.arm()
    for _ in range(20):
        assert not inp.poll(5, 1)
        assert not inp.poll(5, 0)
    inp.stable(0)
    assert inp.ui.selected == 0
    inp.stable(1)
    assert not inp.poll(699, 1)
    assert not inp.poll(1, 0)
    assert inp.poll(35, 0)
    assert inp.ui.selected == 1 and inp.ui.page == 0


def test_unsigned_tick_wrap(ui_api):
    inp = Input(ui_api, 0xffffff80)
    inp.arm()
    inp.stable(1)
    assert inp.poll(700, 1) and inp.ui.page == 1
    inp.stable(0)
    assert inp.tap(2) and inp.ui.page == 0


@pytest.mark.parametrize("selected,page", [(s,p) for s in range(5) for p in range(6)])
def test_every_screen_within_bounds_deterministic_no_state_mutation(ui_api, selected, page):
    ui = UI(selected=selected, page=page)
    before = bytes(ui)
    rects = []

    @RECT
    def draw(_, x, y, w, h, color):
        rects.append((x,y,w,h,color))
        return 0

    assert ui_api.key_ui_render(C.byref(ui), draw, None) == 0
    assert bytes(ui) == before
    assert rects[0][:4] == (0,0,240,320)
    assert all(w and h and x+w<=240 and y+h<=320 for x,y,w,h,c in rects)
    assert len(rects) < 2500
    first = list(rects)
    rects.clear()
    assert ui_api.key_ui_render(C.byref(ui), draw, None) == 0
    assert rects == first


@pytest.mark.parametrize("fail_at", [1,2,30,100,500])
def test_render_error_propagates_without_more_draw_calls(ui_api, fail_at):
    ui = UI()
    calls = 0

    @RECT
    def draw(*_):
        nonlocal calls
        calls += 1
        return -17 if calls == fail_at else 0

    assert ui_api.key_ui_render(C.byref(ui), draw, None) == -17
    assert calls == fail_at


@pytest.mark.parametrize("selected,page", [(5,0), (255,0), (0,6), (0,255)])
def test_invalid_state_no_drawing(ui_api, selected, page):
    calls = []

    @RECT
    def draw(*args):
        calls.append(args)
        return 0

    ui = UI(selected=selected, page=page)
    assert ui_api.key_ui_render(C.byref(ui), draw, None) == -1
    assert not calls


def test_random_input_never_escapes_readonly_navigation(ui_api):
    inp = Input(ui_api)
    rng = random.Random(0x9341)
    for _ in range(10000):
        inp.poll(rng.randrange(1,1000), rng.randrange(4))
        assert inp.ui.page in range(6)
        assert inp.ui.selected in range(5)


@pytest.mark.parametrize("old,new", [(i,j) for i in range(5) for j in range(5)])
def test_incremental_menu_is_pixel_identical_to_full_render(ui_api, old, new):
    pixels = [0] * (240*320)
    count = 0

    @RECT
    def draw(_,x,y,w,h,c):
        nonlocal count
        assert x+w<=240 and y+h<=320
        count += w*h
        for row in range(y,y+h):
            pixels[row*240+x:row*240+x+w] = [c]*w
        return 0

    before,after = UI(selected=old),UI(selected=new)
    assert ui_api.key_ui_render(C.byref(before),draw,None) == 0
    count = 0
    assert ui_api.key_ui_render_update(C.byref(after),C.byref(before),draw,None) == 0
    assert count < 20000
    if old == new:
        assert count == 0
    incremental = list(pixels)
    pixels[:] = [0]*len(pixels)
    assert ui_api.key_ui_render(C.byref(after),draw,None) == 0
    assert pixels == incremental


@pytest.mark.parametrize("old,new", [(0,1), (1,0), (3,5), (5,4)])
def test_page_transition_redraws_whole_frame(ui_api, old, new):
    rects = []

    @RECT
    def draw(_,x,y,w,h,c):
        rects.append((x,y,w,h,c))
        return 0

    before,after = UI(page=old),UI(page=new)
    assert ui_api.key_ui_render_update(C.byref(after),C.byref(before),draw,None) == 0
    incremental = list(rects)
    rects.clear()
    assert ui_api.key_ui_render(C.byref(after),draw,None) == 0
    assert incremental == rects


def test_incremental_first_error_is_propagated(ui_api):
    before,after = UI(),UI(selected=1)
    calls = []

    @RECT
    def draw(*args):
        calls.append(args)
        return -19

    assert ui_api.key_ui_render_update(C.byref(after),C.byref(before),draw,None) == -19
    assert len(calls) == 1
