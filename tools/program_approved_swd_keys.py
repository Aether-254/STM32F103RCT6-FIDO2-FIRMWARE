"""One-shot, explicitly user-approved diagnostic image; never resets/runs target.

Approval is specific to the frozen hash and first 25 pages. Not a general
programming utility. Connect only to an already approved attach-only server.
"""
from datetime import datetime
import hashlib
import json
import re
from pathlib import Path
import socket

from read_target_tcl import command

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / 'build/candidates/swd-keys-20261012-212252/fido2-key.bin'
EXPECTED = '4C91042198AA037AFEA4CE3B193B44CA64CEE791CBBA3945BC91E9E45CEA4B2A'


def main():
    for previous in (ROOT / 'build/evidence').glob('approved-program-*.json'):
        receipt = json.loads(previous.read_text(encoding='utf-8'))
        if receipt.get('verified') and receipt.get('sha256') == EXPECTED:
            raise RuntimeError('This one-shot approval was already used successfully; no repeat write')
    payload = IMAGE.read_bytes()
    assert len(payload) == 49308
    assert hashlib.sha256(payload).hexdigest().upper() == EXPECTED
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    evidence = ROOT / f'build/evidence/approved-program-{stamp}.json'
    log = {'approval': 'User explicitly approved frozen image, first 25 pages and reset; reset deferred pending BOOT0 low confirmation',
           'image': str(IMAGE), 'sha256': EXPECTED,
           'erase_start': '0x08000000', 'erase_end_exclusive': '0x0800C800',
           'commands': [], 'reset_executed': False, 'verified': False}

    def save():
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(json.dumps(log, indent=2), encoding='utf-8')

    with socket.create_connection(('127.0.0.1', 6666), timeout=5) as conn:
        conn.settimeout(240)

        def run(cmd):
            # Catch Tcl errors, not just transport success or output substrings.
            reply = command(conn, 'set rc [catch {capture {' + cmd + '}} out]; list $rc $out')
            log['commands'].append({'command': cmd, 'response': reply})
            save()
            print(cmd, reply, flush=True)
            if not reply.startswith('0 '):
                raise RuntimeError('OpenOCD command failed; leave halted, do not continue')
            return reply

        def dump(label):
            path = ROOT / f'backup/{label}-{stamp}.bin'
            if path.exists():
                raise RuntimeError('Backup already exists')
            run(f'dump_image "{path.as_posix()}" 0x08000000 0x40000')
            data = path.read_bytes()
            assert len(data) == 262144
            log[label] = {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest().upper()}
            save()
            return data

        run('halt')
        run('wait_halt 3000')
        identity = run('mdw 0xe0042000 1')
        capacity = run('mdh 0x1ffff7e0 1')
        if '10036414' not in identity or '0100' not in capacity:
            raise RuntimeError('Unexpected target identity/capacity')
        info = run('flash info 0 sectors')
        sectors = re.findall(r'#\s*(\d+):\s+0x([0-9a-fA-F]+)\s+\(0x([0-9a-fA-F]+)', info)
        geometry = [(int(i), int(offset, 16), int(size, 16)) for i, offset, size in sectors]
        if ('stm32f1x' not in info or '0x08000000' not in info or
                geometry != [(i, i * 2048, 2048) for i in range(128)]):
            raise RuntimeError('Unexpected Flash bank/page geometry')
        before = dump('prewrite-1')
        before2 = dump('prewrite-2')
        assert before == before2, 'Prewrite full Flash reads differ'
        # Recheck immutable payload immediately before the destructive boundary.
        assert IMAGE.read_bytes() == payload
        run('flash erase_sector 0 0 24')
        run(f'flash write_image "{IMAGE.as_posix()}" 0x08000000 bin')
        run(f'verify_image "{IMAGE.as_posix()}" 0x08000000 bin')
        after = dump('postwrite')
        assert after[:len(payload)] == payload, 'Application readback differs'
        assert after[len(payload):0xC800] == b'\xff' * (0xC800-len(payload)), 'Erased application tail differs'
        assert after[0xC800:] == before[0xC800:], 'Protected Flash remainder differs'
        run('poll')
        log.update(verified=True, protected_remainder_identical=True,
                   application_exact=True, erased_tail_verified=True,
                   final_state='halted; no reset/resume; awaiting BOOT0 low confirmation')
        save()
        print('VERIFIED:', evidence, flush=True)


if __name__ == '__main__':
    main()
