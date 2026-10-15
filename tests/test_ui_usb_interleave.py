"""Actual C UI -> LCD -> service -> FIDO adapter/CTAPHID interleaving.

Simulated GPIO/USB bus and completion timing. Does NOT measure physical USB,
GPIO timing, interrupts, electrical detach or Windows re-enumeration.
"""
import ctypes as C
import pytest
from test_lcd import Panel, initialize
from test_ui import UI, RECT
from test_transport import initial, usb_allocate, usb_read


@pytest.mark.parametrize("page", range(6))
def test_usb_ping_serviced_during_real_c_ui_lcd_render(lib, page):
    lib.usb_reset_test()
    cid=usb_allocate(lib)
    errors=[]

    class InterleavedPanel(Panel):
        def __init__(self):
            self.active=False
            self.pings=0
            self.previous_write=0
            self.max_service_gap=0
            super().__init__()

        def service(self, _):
            self.services+=1
            if not self.active:
                return
            self.max_service_gap=max(self.max_service_gap,len(self.writes)-self.previous_write)
            self.previous_write=len(self.writes)
            if self.services%37:
                return
            # Capture errors rather than throwing through a ctypes void callback.
            try:
                lib.usb_complete()
                payload=b"LCD"+self.services.to_bytes(4,"big")
                sent=lib.usb_sent()
                lib.usb_receive(initial(cid,0x81,payload))
                lib.usb_poll(2+self.pings)
                response=usb_read(lib)
                assert lib.usb_sent()==sent+1
                assert response[:4]==cid.to_bytes(4,"big")
                assert response[4:7]==bytes([0x81,0,len(payload)])
                assert response[7:7+len(payload)]==payload
                assert lib.usb_masked()==0
                self.pings+=1
            except Exception as exc:
                errors.append(repr(exc))

    panel=InterleavedPanel()
    rc,lcd=initialize(lib,panel)
    assert rc==0
    panel.previous_write=len(panel.writes)
    panel.active=True
    lib.key_ui_render.argtypes=[C.POINTER(UI),RECT,C.c_void_p]

    @RECT
    def draw(_,x,y,w,h,color):
        return lib.key_lcd_fill(C.byref(lcd),x,y,w,h,color)

    assert lib.key_ui_render(C.byref(UI(page=page)),draw,None)==0
    assert lcd.ready
    assert not errors
    assert panel.pings>=20
    # 11 address-window/command writes plus at most 128 pixel writes per service.
    assert panel.max_service_gap<=139
    assert lib.usb_overflows()==0
    lib.usb_complete()
