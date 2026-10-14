"""Actual C journal + actual C AEAD, persisted host files, independent process.

No SD, target flash, root provisioning, browser or CTAP backend is involved.
"""
import subprocess
import sys
from test_transport import ROOT
from test_journal import api, Flash, attach, reserve
from test_vault import vault, seal, opened, PRIVATE


def test_cold_process_journal_and_credential_reload(api, vault, tmp_path):
    f = Flash()
    assert attach(api, f, provision=True)[0] == 0
    _, j = attach(api, f)
    assert reserve(api, f, j, 64, 32) == (0, 1, 1)
    status, block = seal(vault, sequence=1)
    assert status == 0
    flash_path = tmp_path / "host-flash-model.bin"
    credential_path = tmp_path / "host-credential.bin"
    flash_path.write_bytes(f.image)
    credential_path.write_bytes(block)
    script = '''
import ctypes as C, sys
from pathlib import Path
from test_journal import api, Flash, attach, reserve
from test_vault import configure, opened, seal, PRIVATE
dll = configure(api.__wrapped__(C.CDLL(sys.argv[1])))
assert dll.key_crypto_init() == 0
flash_path, credential_path = Path(sys.argv[2]), Path(sys.argv[3])
f = Flash(flash_path.read_bytes())
status, journal = attach(dll, f)
assert status == 0 and journal.state.nonce == 64 and journal.state.sign_count == 32
status, record = opened(dll, credential_path.read_bytes())
assert status == 0 and bytes(record.private_key) == PRIVATE
status, first, sign = reserve(dll, f, journal, 64, 32)
assert (status, first, sign) == (0, 65, 33)
status, encrypted = seal(dll, record, sequence=first)
assert status == 0 and opened(dll, encrypted)[0] == 0
flash_path.write_bytes(f.image)
credential_path.write_bytes(encrypted)
print('C cold-process high-water and authenticated credential verified')
'''
    result = subprocess.run([sys.executable, "-c", script,
                             str(ROOT / "build/host/ctaphid.dll"),
                             str(flash_path), str(credential_path)],
                            cwd=ROOT / "tests", capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "verified" in result.stdout
    assert credential_path.read_bytes() != block
    f = Flash(flash_path.read_bytes())
    status, j = attach(api, f)
    assert status == 0 and j.state.nonce == 128 and j.state.sign_count == 64
    assert reserve(api, f, j, 64, 32) == (0, 129, 65)
    assert bytes(opened(vault, credential_path.read_bytes())[1].private_key) == PRIVATE


def test_cancelled_or_lost_credential_write_never_reclaims_nonce(api, vault):
    f = Flash()
    _, j = attach(api, f, provision=True)
    assert reserve(api, f, j, 1, 0) == (0, 1, 0)
    status, cancelled_block = seal(vault, sequence=1)
    assert status == 0
    # Simulate dropping the SD transaction after encryption, then reboot.
    # Keep the new callback owner alive (ctypes callback lifetime is explicit).
    restarted = Flash(f.image)
    _, j = attach(api, restarted)
    assert reserve(api, restarted, j, 1, 1) == (0, 2, 1)
    _, new_block = seal(vault, sequence=2)
    assert new_block != cancelled_block
    # Old valid ciphertext remains decryptable: deletion/metadata anti-rollback
    # catalog is a separate missing capability, never claimed by these layers.
    assert opened(vault, cancelled_block)[0] == 0
