"""Approved debug-link diagnostic: no target reset/halt, flash or AP writes.

SWJ debug-mode/line reset sequences are NOT an MCU reset. This deliberately
does not instantiate a target/session or run STM32-specific init sequences.
"""
from pyocd.probe.cmsis_dap_probe import CMSISDAPProbe
from pyocd.probe.debug_probe import DebugProbe
from pyocd.probe.swj import SWJSequenceSender
from pyocd.core.session import Session


def main():
    probes = CMSISDAPProbe.get_all_connected_probes()
    matching = [p for p in probes if p.unique_id == 'FS-00000000']
    if len(matching) != 1:
        raise RuntimeError('Expected exactly one Fire FS-00000000 probe')
    probe = matching[0]
    # Options-only session with no probe/board target and no Session.open().
    # CMSISDAPProbe.open needs its transfer options; it does not initialize MCU.
    probe.session = Session(None, auto_open=False, options={'no_config': True})
    probe.open()
    try:
        probe.connect(DebugProbe.Protocol.SWD)
        for frequency in [100000, 10000]:
            probe.set_clock(frequency)
            SWJSequenceSender(probe, use_dormant=False).switch_to_swd()
            for attempt in range(1, 4):
                try:
                    identifier = probe.read_dp(0)
                    print(f'{frequency} Hz attempt {attempt}: DPIDR=0x{identifier:08x}')
                    if identifier not in (0, 0xffffffff):
                        return 0
                except Exception as error:
                    print(f'{frequency} Hz attempt {attempt}: {type(error).__name__}: {error}')
        return 1
    finally:
        try:
            probe.disconnect()
        finally:
            probe.close()


if __name__ == '__main__':
    raise SystemExit(main())
