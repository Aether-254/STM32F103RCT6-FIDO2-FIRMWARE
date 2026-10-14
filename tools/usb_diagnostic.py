"""Bounded INIT/PING/getInfo only. No credentials, reset or storage commands.

Windows FIDO HID raw access may require elevation. This script never requests
it automatically. Run only for the known experimental board, not other tokens.
"""
from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def child():
    from fido2.hid import CtapHidDevice, list_descriptors, open_connection
    from fido2.ctap2 import Ctap2

    descriptors = [d for d in list_descriptors()
                   if d.vid == 0x0483 and d.pid == 0x5750
                   and d.serial_number == '48FF574E3243']
    if len(descriptors) != 1:
        raise RuntimeError(f'Expected exactly one known board; accessible matches={len(descriptors)}')
    descriptor = descriptors[0]
    device = CtapHidDevice(descriptor, open_connection(descriptor))
    try:
        results = {'init_nonce_checked_by_fido2': True, 'ping_lengths': [],
                   'serial': descriptor.serial_number,
                   'report_sizes': [descriptor.report_size_in, descriptor.report_size_out]}
        for length in (0, 1, 57, 58, 116, 1024, 4096):
            payload = bytes((i * 37 + 11) % 256 for i in range(length))
            response = device.ping(payload)
            if response != payload:
                raise RuntimeError(f'PING mismatch at length={length}')
            results['ping_lengths'].append(length)
        info = Ctap2(device).get_info()
        if 'FIDO_2_0' not in info.versions:
            raise RuntimeError('getInfo missing FIDO_2_0')
        results['get_info'] = {'versions': info.versions,
                               'options': info.options,
                               'max_msg_size': info.max_msg_size,
                               'algorithms': info.algorithms,
                               'aaguid_hex': bytes(info.aaguid).hex()}
        print(json.dumps(results))
    finally:
        device.close()


def main():
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    path = ROOT / f'build/evidence/usb-diagnostic-{stamp}.json'
    try:
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--child'],
                                 capture_output=True, text=True, timeout=45)
        evidence = {'passed': process.returncode == 0,
                    'exit_code': process.returncode,
                    'stdout': process.stdout, 'stderr': process.stderr,
                    'scope': 'INIT, PING, getInfo only; no credential or reset commands'}
    except subprocess.TimeoutExpired as error:
        evidence = {'passed': False, 'timeout_seconds': 45,
                    'scope': 'INIT, PING, getInfo only', 'error': str(error)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(json.dumps(evidence, indent=2))
    print(path)
    return 0 if evidence['passed'] else 1


if __name__ == '__main__':
    if sys.argv[1:] == ['--child']:
        child()
    elif not sys.argv[1:]:
        sys.exit(main())
    else:
        raise SystemExit('No other arguments supported')
