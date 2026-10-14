"""Approved reads via existing OpenOCD Tcl server, without reset/halt or writes.

Do not start an OpenOCD session here. Flash is only READ into unique host files;
the target's flash, options, RAM and SD are not modified. Host backups may
contain secrets and stay excluded from public release.
"""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import socket

ROOT = Path(__file__).resolve().parents[1]


def command(connection, text):
    connection.sendall(text.encode('utf-8') + b'\x1a')
    response = bytearray()
    while not response.endswith(b'\x1a'):
        part = connection.recv(4096)
        if not part:
            raise RuntimeError('OpenOCD Tcl connection closed')
        response.extend(part)
    return response[:-1].decode('utf-8', errors='replace')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def main():
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    root = ROOT / 'backup'
    root.mkdir(exist_ok=True)
    results = {'timestamp': stamp, 'reads': {}}
    paths = []
    with socket.create_connection(('127.0.0.1', 6666), timeout=5) as connection:
        connection.settimeout(180)
        for address, width, count in [('0xe0042000', 'mdw', 1), ('0x1ffff7e0', 'mdh', 1),
                                      ('0x00000000', 'mdw', 2), ('0x40010004', 'mdw', 1)]:
            value = command(connection, f'capture {{{width} {address} {count}}}')
            print(address, value.strip())
            results['reads'][address] = value.strip()
        if results['reads']['0x1ffff7e0'] != '0x1ffff7e0: 0100':
            raise RuntimeError('Flash size is not the expected 256 KiB; refusing guessed read range')
        for index in [1, 2]:
            path = root / f'readback-{stamp}-{index}.bin'
            if path.exists():
                raise RuntimeError('Refusing to overwrite a backup')
            response = command(connection, f'capture {{dump_image "{path.as_posix()}" 0x08000000 0x40000}}')
            print(response.strip())
            if not path.exists() or path.stat().st_size != 262144:
                raise RuntimeError('Flash readback missing or incomplete')
            paths.append(path)
    hashes = [sha(path) for path in paths]
    original = root / 'original-fw.bin'
    results.update(readbacks=[{'path': str(path), 'sha256': digest} for path, digest in zip(paths, hashes)],
                   repeated_reads_match=hashes[0] == hashes[1],
                   original_backup_sha256=sha(original) if original.exists() else None)
    results['matches_original_backup'] = results['original_backup_sha256'] == hashes[0] == hashes[1]
    evidence = ROOT / 'build/evidence' / f'target-read-{stamp}.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))
    if not results['repeated_reads_match']:
        raise RuntimeError('Repeated flash reads differ: no stable snapshot verified')


if __name__ == '__main__':
    main()
