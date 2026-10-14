"""Tests actual transport with bounded mock jobs; no production credentials."""
import pytest
import ctypes as C
import hashlib
from fido2 import cbor
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from test_transport import secure_random
from test_transport import allocate, feed, initial, send_message, message, peek, usb, usb_allocate, usb_read


@pytest.fixture
def job(lib):
    lib.reset()
    cid = allocate(lib)
    other = allocate(lib)
    assert lib.jobs_enable()
    return lib, cid, other


def start(job, payload=b'\x01pending request', now=0):
    d, cid, _ = job
    send_message(d, cid, 0x90, payload, now)
    assert not d.idle() and d.jobs_borrowed()
    return d, cid


def test_keepalive_cadence_and_status_change(job):
    d, cid = start(job)
    d.tick(99)
    assert peek(d)[1] == 0
    d.tick(100)
    assert message(d) == (cid, 0xbb, b'\x01')
    assert not d.idle()
    d.tick(101)
    assert peek(d)[1] == 0
    d.jobs_status(2)
    d.tick(102)
    assert message(d) == (cid, 0xbb, b'\x02')
    d.tick(201)
    assert peek(d)[1] == 0
    d.tick(202)
    assert message(d) == (cid, 0xbb, b'\x02')


@pytest.mark.parametrize('length', [1, 57, 58, 255, 4096])
def test_async_response_and_borrowed_rx_lifetime(job, length):
    payload = bytes((i*31+7) % 256 for i in range(length))
    d, cid = start(job, payload)
    d.tick(100)
    assert message(d) == (cid, 0xbb, b'\x01')
    d.jobs_mode(1)
    d.tick(101)
    assert message(d) == (cid, 0x90, payload)
    assert not d.jobs_borrowed() and d.idle()
    assert d.jobs_cancelled() == 0


def test_cancel_reply_belongs_to_original_cbor(job):
    d, cid = start(job)
    feed(d, initial(cid, 0x91), 10)
    assert message(d) == (cid, 0x90, b'\x2d')
    assert d.jobs_cancelled() == 1 and not d.jobs_borrowed()
    assert d.idle() and peek(d)[1] == 0


@pytest.mark.parametrize('cid', [0, 2, 999, 0xffffffff])
def test_nonactive_cancel_ignored(job, cid):
    d, active = start(job)
    assert cid != active
    feed(d, initial(cid, 0x91), 1)
    assert peek(d)[1] == 0 and d.jobs_cancelled() == 0
    assert not d.idle()


def test_cancel_inflight_keepalive_invalidates_ticket(job):
    d, cid = start(job)
    d.tick(100)
    old, ticket = peek(d)
    assert old[4] == 0xbb
    feed(d, initial(cid, 0x91), 101)
    d.ack(ticket)
    assert message(d) == (cid, 0x90, b'\x2d')


def test_final_preserves_inflight_keepalive_and_final_bytes(job):
    d, cid = start(job)
    d.tick(100)
    packet, ticket = peek(d)
    d.jobs_mode(1)
    d.tick(101)
    assert peek(d) == (packet, ticket)
    d.ack(ticket)
    assert message(d) == (cid, 0x90, b'\x01pending request')


def test_same_cid_init_cancels_and_wipes_job(job):
    d, cid = start(job)
    d.tick(100)
    _, old = peek(d)
    feed(d, initial(cid, 0x86, b'abcdefgh'), 101)
    d.ack(old)
    result = message(d)
    assert result[:2] == (cid, 0x86) and result[2][:8] == b'abcdefgh'
    assert d.jobs_cancelled() == 1 and not d.jobs_borrowed()


@pytest.mark.parametrize('command', [0x81, 0x86, 0x90])
def test_other_channel_busy_does_not_destroy_job(job, command):
    d, cid = start(job)
    other = job[2]
    feed(d, initial(other, command, b'abcdefgh'), 1)
    assert message(d) == (other, 0xbf, b'\x06')
    assert d.jobs_borrowed() and not d.idle()
    d.jobs_mode(1)
    d.tick(2)
    assert message(d) == (cid, 0x90, b'\x01pending request')


@pytest.mark.parametrize('now', [30000, 30001])
def test_job_timeout_cancels_and_reports_ctap_timeout(job, now):
    d, cid = start(job)
    d.tick(now)
    assert message(d) == (cid, 0x90, b'\x2f')
    assert d.jobs_cancelled() == 1 and not d.jobs_borrowed()


def test_job_timeout_wrap(job):
    d, cid = start(job, now=0xfffffff0)
    d.tick((0xfffffff0+30000) & 0xffffffff)
    assert message(d) == (cid, 0x90, b'\x2f')


def test_dispose_releases_job(job):
    d, _ = start(job)
    d.dispose()
    assert d.jobs_cancelled() == 1 and not d.jobs_borrowed()
    assert d.idle() and peek(d)[1] == 0


def test_immediate_job_does_not_enter_wait(job):
    d, cid, _ = job
    d.jobs_mode(2)
    send_message(d, cid, 0x90, b'\x04')
    assert message(d) == (cid, 0x90, b'\x00')
    assert d.jobs_polled() == 0 and d.idle()


def test_oversized_job_return_fails_closed(job):
    d, cid = start(job)
    d.jobs_mode(3)
    d.tick(1)
    assert message(d) == (cid, 0x90, b'\x7f')
    assert d.jobs_cancelled() == 1


def test_malformed_active_cancel_does_not_cancel(job):
    d, cid = start(job)
    feed(d, initial(cid, 0x91, b'x'), 1)
    assert message(d) == (cid, 0xbf, b'\x03')
    assert d.jobs_cancelled() == 0 and d.jobs_borrowed()


def usb_start(d):
    cid = usb_allocate(d)
    assert d.usb_jobs_enable()
    d.usb_receive(initial(cid, 0x90, b'\x01request'))
    d.usb_poll(2)
    assert d.usb_job_active()
    assert usb_read(d)[4] == 0xbb and usb_read(d)[7] == 2
    return cid


def test_usb_async_keepalive_retained_until_completion(usb):
    cid = usb_start(usb)
    old = usb_read(usb)
    count = usb.usb_sent()
    usb.usb_job_finish()
    usb.usb_poll(3)
    assert usb_read(usb) == old and usb.usb_sent() == count
    usb.usb_complete()
    usb.usb_poll(4)
    final = usb_read(usb)
    assert final[:4] == cid.to_bytes(4, 'big')
    assert final[4] == 0x90 and final[7] == 0x27
    assert usb.usb_callback_masked() == 0


def test_usb_async_cancel_inflight_keepalive(usb):
    cid = usb_start(usb)
    old = usb_read(usb)
    usb.usb_receive(initial(cid, 0x91))
    usb.usb_poll(3)
    assert usb.usb_job_cancelled() == 1 and not usb.usb_job_active()
    assert usb_read(usb) == old
    usb.usb_complete()
    usb.usb_poll(4)
    assert usb_read(usb)[4] == 0x90 and usb_read(usb)[7] == 0x2d
    assert usb.usb_callback_masked() == 0


@pytest.mark.parametrize('event', ['disconnect', 'overflow'])
def test_usb_epoch_cancels_job_in_foreground(usb, event):
    cid = usb_start(usb)
    old = usb_read(usb)
    if event == 'disconnect':
        usb.usb_disconnect()
    else:
        for _ in range(16):
            usb.usb_receive(initial(cid, 0x81, b'flood'))
    assert usb.usb_job_cancelled() == 0  # ISR has not run cleanup.
    usb.usb_poll(3)
    assert usb.usb_job_cancelled() == 1 and not usb.usb_job_active()
    assert usb.usb_callback_masked() == 0
    assert usb_read(usb) == old


def test_usb_cannot_rebind_active_jobs(usb):
    usb_start(usb)
    assert not usb.usb_jobs_disable()
    assert usb.usb_job_active()


def test_real_restartable_signing_keeps_transport_responsive(job):
    d, cid, _ = job
    assert d.jobs_crypto_enable(secure_random, None)
    digest = hashlib.sha256(b'protocol preimage fixture').digest()
    request = b'\x02' + cbor.encode({1: 'example.com', 2: digest})
    send_message(d, cid, 0x90, request)
    keepalives = 0
    for now in range(10, 30000, 10):
        d.tick(now)
        if not peek(d)[1]:
            continue
        channel, command, response = message(d)
        assert channel == cid
        if command == 0xbb:
            assert response == b'\x01'
            keepalives += 1
            continue
        assert command == 0x90 and response[0] == 0
        ec.derive_private_key(17, ec.SECP256R1()).public_key().verify(
            response[1:], digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        assert keepalives > 0 and d.idle()
        break
    else:
        pytest.fail('Actual restartable signing did not finish')


def test_cancel_actual_crypto_job_releases_arena(job):
    d, cid, _ = job
    assert d.jobs_crypto_enable(secure_random, None)
    request = b'\x02' + cbor.encode({1: 'example.com', 2: b'h'*32})
    send_message(d, cid, 0x90, request)
    d.tick(10)
    feed(d, initial(cid, 0x91), 20)
    assert message(d) == (cid, 0x90, b'\x2d')
    assert d.jobs_cancelled() == 1
    # If the actual job is still active/leaked, blocking public-key API is BUSY.
    output = C.create_string_buffer(65)
    assert d.key_crypto_p256_public((17).to_bytes(32,'big'), output, secure_random, None) == 0
