"""Actual board adapter/MSP on mocked GPIO; physical levels remain unverified."""
import ctypes as C
import pytest
from test_transport import ROOT


@pytest.fixture
def board(lib):
    lib.board_test_levels.argtypes = [C.c_uint32, C.c_uint32]
    lib.board_test_info.argtypes = [C.c_uint]
    lib.board_test_info.restype = C.c_uint32
    lib.board_test_init()
    return lib


def test_real_msp_selects_swd_preserving_remap(board):
    assert board.board_test_info(1) == 2  # Mock trace from actual HAL_MspInit.
    assert board.board_test_info(0) == 1+4+8+16
    assert board.board_test_info(2) == 1
    assert board.board_test_info(3) == 0x2000
    assert board.board_test_info(4) == 0
    assert board.board_test_info(5) == 0x4B455931
    assert not board.board_test_pressed()


@pytest.mark.parametrize('a,c,mask', [(0,0,0),(1,0,1),(0,0x2000,2),(1,0x2000,3),
    (0xfffe,0xdfff,0),(0xffff,0xffff,3)])
def test_active_high_keys_ignore_other_pins(board, a, c, mask):
    board.board_test_levels(a,c)
    board.board_test_poll()
    assert board.board_test_info(8) == mask
    assert bool(board.board_test_pressed()) == bool(mask)
    assert board.board_test_info(6) % 2 == 0


def test_raw_edges_not_cached_authorization(board):
    for _ in range(10):
        board.board_test_levels(1,0x2000)
        board.board_test_poll()
    assert board.board_test_info(9) == board.board_test_info(10) == 1
    board.board_test_levels(0,0)
    board.board_test_poll()
    assert not board.board_test_pressed()  # Counters never authorize later requests.
    board.board_test_levels(1,0)
    board.board_test_poll()
    assert board.board_test_info(9) == 2 and board.board_test_info(10) == 1


def test_ioc_source_guard_matches_serial_wire_configuration():
    ioc = (ROOT/'fido2-key.ioc').read_text()
    assert 'No_Debug' not in ioc and 'SYS.Debug=Serial_Wire' in ioc
    assert 'PA13.Signal=SYS_JTMS-SWDIO' in ioc
    assert 'PA14.Signal=SYS_JTCK-SWCLK' in ioc
    assert 'PA0.GPIO_PuPd=GPIO_PULLDOWN' in ioc and 'PC13.GPIO_PuPd=GPIO_PULLDOWN' in ioc
