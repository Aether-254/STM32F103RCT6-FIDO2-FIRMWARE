"""Real board helper on traced HAL calls; NOT a USB electrical simulation."""
import ctypes as C
from pathlib import Path
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def boot():
    output=ROOT/"build/host/usb-boot.dll"
    output.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([sys.executable,"-m","ziglang","cc","-shared","-std=c11",
        "-O2","-Wall","-Wextra","-Werror","-I",str(ROOT/"tests/mocks/usb_boot"),
        "-I",str(ROOT/"Core/Inc"),str(ROOT/"Core/Src/board_usb_boot.c"),
        str(ROOT/"tests/usb_boot_harness.c"),"-o",str(output)],check=True)
    lib=C.CDLL(str(output))
    lib.usb_boot_info.argtypes=[C.c_uint,C.c_uint]
    lib.usb_boot_info.restype=C.c_uint32
    return lib


def test_boot_disconnect_sequence_only_pa12_and_bounded(boot):
    boot.usb_boot_test()
    assert boot.usb_boot_info(33,0)==0
    assert boot.usb_boot_info(32,0)==7
    assert [(boot.usb_boot_info(n,0),boot.usb_boot_info(n,1)) for n in range(7)]==[
        (1,0), (2,0), (3,1<<12), (4,1<<12), (5,100), (6,1<<12), (7,0)]


def test_real_usb_startup_calls_helper_before_usbd_init():
    source=(ROOT/"USB_DEVICE/App/usb_device.c").read_text(encoding="utf-8")
    assert '#include "board_usb_boot.h"' in source
    assert source.index('board_usb_boot_disconnect();') < source.index('USBD_Init(&hUsbDeviceFS')
    assert source.count('board_usb_boot_disconnect();')==1
