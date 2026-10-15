"""One session-wide build: avoid overwriting a loaded Windows DLL."""
import ctypes as C
import re
import subprocess
import sys
import pytest
from test_transport import ROOT, RNG


@pytest.fixture(scope="session")
def lib():
    output = ROOT / "build" / "host" / "ctaphid.dll"
    output.parent.mkdir(parents=True, exist_ok=True)
    config = (ROOT / "cmake/key_crypto.cmake").read_text()
    modules = re.search(r"set\(KEY_MBEDTLS_MODULES\s+(.*?)\)", config, re.S).group(1).split()
    crypto_sources = [str(ROOT / "third_party/mbedtls-3.6.7/library" / (m + ".c")) for m in modules]
    subprocess.run([
        sys.executable, "-m", "ziglang", "cc", "-shared", "-std=c11",
        "-O2", "-Wall", "-Wextra", "-Werror",
        "-I", str(ROOT / "tests/mocks"), "-I", str(ROOT / "Core/Inc"),
        "-I", str(ROOT / "USB_DEVICE/App"),
        "-I", str(ROOT / "third_party/mbedtls-3.6.7/include"),
        '-DMBEDTLS_CONFIG_FILE="mbedtls_key_config.h"',
        '-DKEY_CRYPTO_HOST_TEST',
        str(ROOT / "tests/transport_harness.c"), str(ROOT / "Core/Src/ctaphid.c"),
        str(ROOT / "tests/usb_harness.c"), str(ROOT / "USB_DEVICE/App/fido_usb.c"),
        str(ROOT / "Core/Src/ctap_dispatch.c"), str(ROOT / "Core/Src/key_crypto.c"),
        str(ROOT / "Core/Src/key_cbor.c"), str(ROOT / "Core/Src/ctap_request.c"),
        str(ROOT / "Core/Src/key_presence.c"), str(ROOT / "tests/presence_harness.c"),
        str(ROOT / "Core/Src/key_authdata.c"),
        str(ROOT / "Core/Src/ctap_credential.c"),
        str(ROOT / "Core/Src/key_vault.c"),
        str(ROOT / "Core/Src/key_journal.c"),
        str(ROOT / "Core/Src/key_root.c"),
        str(ROOT / "Core/Src/key_random.c"),
        str(ROOT / "Core/Src/key_backend.c"),
        str(ROOT / "Core/Src/key_sd_readonly.c"),
        str(ROOT / "Core/Src/key_otp.c"),
        str(ROOT / "Core/Src/key_otp_selftest.c"),
        str(ROOT / "Core/Src/key_lcd.c"),
        str(ROOT / "Core/Src/board_keys.c"), str(ROOT / "tests/board_harness.c"),
        str(ROOT / "Core/Src/stm32f1xx_hal_msp.c"),
        *crypto_sources, "-o", str(output)
    ], check=True, cwd=ROOT)
    dll = C.CDLL(str(output))
    dll.receive.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32]
    dll.peek.argtypes = [C.c_void_p, C.POINTER(C.c_uint32)]
    dll.ack.argtypes = [C.c_uint32]
    dll.tick.argtypes = [C.c_uint32]
    dll.dispatch.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
    dll.dispatch.restype = C.c_size_t
    dll.cbor_valid.argtypes = [C.c_void_p, C.c_size_t]
    dll.request_status.argtypes = [C.c_void_p, C.c_size_t]
    dll.presence_begin.argtypes = [C.c_uint32, C.c_uint32, C.c_int, C.c_uint32]
    dll.presence_sample.argtypes = [C.c_int, C.c_uint32]
    dll.presence_progress.argtypes = [C.c_uint32]
    dll.presence_progress.restype = C.c_uint32
    dll.presence_inputs.argtypes = [C.c_int, C.c_int, C.c_uint32]
    dll.frontend_progress.argtypes = [C.c_uint32]
    dll.frontend_progress.restype = C.c_uint32
    dll.presence_cancel.argtypes = [C.c_uint32, C.c_uint32]
    dll.presence_consume.argtypes = [C.c_uint32, C.c_uint32, C.c_uint32]
    dll.key_authdata_make.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p,
                                    C.c_size_t, C.c_uint32, C.c_void_p, C.c_size_t,
                                    C.POINTER(C.c_size_t), RNG, C.c_void_p]
    dll.key_authdata_assert.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_bool, C.c_void_p, C.c_size_t]
    dll.key_authdata_digest.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p]
    dll.usb_receive.argtypes = [C.c_void_p]
    dll.usb_read.argtypes = [C.c_void_p]
    dll.usb_poll.argtypes = [C.c_uint32]
    dll.usb_reject.argtypes = [C.c_int]
    dll.key_crypto_sha256.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p]
    dll.key_crypto_hkdf.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p]
    dll.key_crypto_seal.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t,
                                  C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p]
    dll.key_crypto_open.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t,
                                  C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
    dll.key_crypto_p256_public.argtypes = [C.c_void_p, C.c_void_p, RNG, C.c_void_p]
    dll.key_crypto_p256_sign.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p, C.c_size_t,
                                       C.POINTER(C.c_size_t), RNG, C.c_void_p]
    dll.key_crypto_job_begin.argtypes = [C.c_uint32, C.c_uint, C.c_void_p, C.c_void_p, RNG, C.c_void_p]
    dll.key_crypto_job_poll.argtypes = [C.c_uint32]
    dll.key_crypto_job_cancel.argtypes = [C.c_uint32]
    dll.key_crypto_job_take.argtypes = [C.c_uint32, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    dll.jobs_crypto_enable.argtypes = [RNG, C.c_void_p]
    dll.frontend_enable.argtypes = [RNG]
    assert dll.key_crypto_init() == 0
    return dll

