"""Actual C CTAPHID + credential frontend + DRBG/journal/AEAD/backend.

Adapter uses REAL HOST FILES, fake physical buttons and modeled flash. This is
not an SD, browser, target or physical power-loss acceptance test.
"""
import ctypes as C
import os
import subprocess
import sys
from pathlib import Path
import pytest
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject, AuthenticatorData, CollectedClientData,
    RegistrationResponse, AuthenticatorAttestationResponse,
    AuthenticationResponse, AuthenticatorAssertionResponse,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
)
from test_journal import api, Flash, Journal, attach
from test_root_random import provider
from test_vault import ROOT_KEY, CONTEXT
from test_transport import allocate, send_message, message, peek
from test_transport import ROOT

READY = C.CFUNCTYPE(C.c_bool, C.c_void_p)
READ = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
WRITE = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
ABORT = C.CFUNCTYPE(None, C.c_void_p)


class StoreIO(C.Structure):
    _fields_ = [("ready", READY), ("read", READ), ("write_new", WRITE), ("abort", ABORT)]


class HostFiles:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.available = True
        self.pressed = False
        self.delay = 0
        self.pending = None
        self.remaining = 0
        self.errors = []
        self.write_count = 0
        self.abort_count = 0
        self.write_failure = False
        self.readback_corrupt = False
        self.collide = False
        self.callbacks = READY(lambda ctx: self.available), READ(self.read), WRITE(self.write), ABORT(self.abort)
        self.io = StoreIO(*self.callbacks)
        self.input = READY(lambda ctx: self.pressed)

    def path(self, rp, identifier):
        return self.directory / (rp.hex() + '-' + identifier.hex() + '.bin')

    def operation(self, signature):
        if self.pending is None:
            self.pending, self.remaining = signature, self.delay
        if self.pending != signature:
            self.errors.append("pending operation inputs changed")
            return -1
        if self.remaining:
            self.remaining -= 1
            return 256
        self.pending = None
        return 0

    def read(self, ctx, rp_ptr, id_ptr, output):
        rp, identifier = C.string_at(rp_ptr, 32), C.string_at(id_ptr, 32)
        status = self.operation(('read', rp, identifier))
        if status:
            return status
        if self.collide:
            C.memset(output, 0, 512)
            return 0
        path = self.path(rp, identifier)
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return 0x2e
        except OSError:
            return 0x7f
        if len(data) != 512:
            return 0x7f
        if self.readback_corrupt and self.write_count:
            data = data[:-1] + bytes([data[-1] ^ 1])
        C.memmove(output, data, 512)
        return 0

    def write(self, ctx, rp_ptr, id_ptr, data_ptr):
        rp, identifier = C.string_at(rp_ptr, 32), C.string_at(id_ptr, 32)
        data = C.string_at(data_ptr, 512)
        status = self.operation(('write', rp, identifier, data))
        if status:
            return status
        if self.write_failure:
            return 0x7f
        path = self.path(rp, identifier)
        try:
            # Serial host fixture: no overwrite; fsync before completion. This
            # does NOT claim SD atomic publication or directory power-loss safety.
            with path.open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            self.write_count += 1
            return 0
        except OSError:
            return 0x7f

    def abort(self, ctx):
        self.pending = None
        self.remaining = 0
        self.abort_count += 1
        # Already durable files are deliberately retained.


class PersistentFrontend:
    def __init__(self, dll, directory, image=None):
        self.d = dll
        self.store = HostFiles(directory)
        self.flash = Flash(image)
        if image is None:
            assert attach(dll, self.flash, provision=True)[0] == 0
        status, self.journal = attach(dll, self.flash)
        assert status == 0
        self.now = 0
        self.keepalives = []
        dll.reset()
        self.cid = allocate(dll)
        assert dll.key_random_boot(C.byref(self.journal), ROOT_KEY, CONTEXT) == 0
        assert dll.persistent_enable(C.byref(self.journal), ROOT_KEY, CONTEXT,
                                     C.byref(self.store.io), None, self.store.input, None)

    def step(self, press=True):
        self.now += 10
        if self.d.frontend_phase() == 2 and press:
            if not hasattr(self, 'waiting_since'):
                self.waiting_since = self.now
            if self.now-self.waiting_since >= 50:
                self.store.pressed = True
        else:
            if hasattr(self, 'waiting_since'):
                del self.waiting_since
        self.d.tick(self.now)
        if not peek(self.d)[1]:
            return None
        cid, command, response = message(self.d)
        assert cid == self.cid
        if command == 0xbb:
            self.keepalives.append(response[0])
            return None
        assert command == 0x90
        self.store.pressed = False
        assert self.d.frontend_clean() and self.d.persistent_transient_clean()
        assert not self.store.errors
        return response

    def exchange(self, command, request, press=True):
        send_message(self.d, self.cid, 0x90, bytes([command])+cbor.encode(request), self.now)
        for _ in range(3200):
            response = self.step(press)
            if response is not None:
                return response
        pytest.fail('persistent frontend did not terminate')

    def make(self, client_hash=b'h'*32, rp='example.com', user=b'user'):
        response = self.exchange(1, {1: client_hash, 2: {'id': rp}, 3: {'id': user},
                                     4: [{'type': 'public-key', 'alg': -7}]})
        assert response[0] == 0, response
        decoded = cbor.decode(response[1:])
        return decoded, AuthenticatorData(decoded[2]).credential_data

    def get(self, identifier, client_hash=b'h'*32, rp='example.com'):
        return self.exchange(2, {1: rp, 2: client_hash,
            3: [{'type': 'public-key', 'id': identifier}]})

    def close(self):
        self.d.persistent_close()

    def reboot(self):
        image = bytes(self.flash.image)
        directory, dll = self.store.directory, self.d
        self.close()
        return PersistentFrontend(dll, directory, image)


@pytest.fixture
def persistent(provider, tmp_path):
    provider.persistent_enable.argtypes = [C.POINTER(Journal), C.c_void_p, C.c_void_p,
        C.POINTER(StoreIO), C.c_void_p, READY, C.c_void_p]
    front = PersistentFrontend(provider, tmp_path / 'credentials')
    yield front
    front.close()


def test_full_registration_and_reboot_authentication_server_acceptance(persistent):
    front = persistent
    server = Fido2Server(PublicKeyCredentialRpEntity(id='example.com', name='Persistent host test'))
    options, state = server.register_begin(PublicKeyCredentialUserEntity(id=b'user', name='user'),
                                           challenge=b'persistent registration')
    client = CollectedClientData.create('webauthn.create', options.public_key.challenge, 'https://example.com')
    result, credential = front.make(client.hash)
    registration = RegistrationResponse(raw_id=credential.credential_id,
        response=AuthenticatorAttestationResponse(client_data=client,
            attestation_object=AttestationObject(cbor.encode({'fmt': result[1], 'authData': result[2], 'attStmt': result[3]}))))
    assert server.register_complete(state, registration).credential_data == credential
    files = list(front.store.directory.glob('*.bin'))
    assert len(files) == 1 and files[0].stat().st_size == 512
    assert files[0].read_bytes()[:4] == b'F2CR'
    assert b'user' not in files[0].read_bytes()[32:496]
    for expected_counter in [1, 2, 33]:
        if expected_counter == 33:
            front = front.reboot()  # cached unconsumed 3..32 burned
        options, state = server.authenticate_begin([credential], challenge=bytes([expected_counter])*32)
        client = CollectedClientData.create('webauthn.get', options.public_key.challenge, 'https://example.com')
        response = front.get(credential.credential_id, client.hash)
        assert response[0] == 0
        decoded = cbor.decode(response[1:])
        data = AuthenticatorData(decoded[2])
        assert data.counter == expected_counter and data.is_user_present()
        authentication = AuthenticationResponse(raw_id=credential.credential_id,
            response=AuthenticatorAssertionResponse(client_data=client, authenticator_data=data, signature=decoded[3]))
        assert server.authenticate_complete(state, [credential], authentication) == credential
    front.close()


def test_pending_store_retries_are_stable_and_keepalive(persistent):
    persistent.store.delay = 20
    _, credential = persistent.make()
    assert persistent.store.write_count == 1
    assert persistent.get(credential.credential_id)[0] == 0
    assert 1 in persistent.keepalives and 2 in persistent.keepalives
    assert not persistent.store.errors


@pytest.mark.parametrize('damage', ['cipher', 'tag', 'truncate', 'wrong-rp', 'wrong-id'])
def test_lookup_rejects_tampered_or_swapped_objects(persistent, damage):
    _, credential = persistent.make()
    path = next(persistent.store.directory.glob('*.bin'))
    data = bytearray(path.read_bytes())
    rp, identifier = path.stem.split('-')
    if damage in ('cipher', 'tag'):
        data[32 if damage == 'cipher' else 511] ^= 1
        path.write_bytes(data)
    elif damage == 'truncate':
        path.write_bytes(data[:-1])
    elif damage == 'wrong-rp':
        import hashlib
        other = persistent.store.path(hashlib.sha256(b'other.example').digest(), bytes.fromhex(identifier))
        other.write_bytes(data)
        assert persistent.get(credential.credential_id, rp='other.example') == b'\x7f'
        return
    else:
        other_id = bytes([credential.credential_id[0] ^ 1]) + credential.credential_id[1:]
        persistent.store.path(bytes.fromhex(rp), other_id).write_bytes(data)
        assert persistent.get(other_id) == b'\x7f'
        return
    assert persistent.get(credential.credential_id) == b'\x7f'


def test_commit_readback_corruption_never_reports_registration_success(persistent):
    persistent.store.readback_corrupt = True
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}]}
    assert persistent.exchange(1, request) == b'\x7f'
    assert persistent.store.write_count == 1  # durable orphan retained safely
    assert persistent.journal.state.nonce >= 65


def test_cancel_pending_commit_burns_nonce_and_clears_transient(persistent):
    front = persistent
    front.store.delay = 30
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}]}
    send_message(front.d, front.cid, 0x90, b'\1'+cbor.encode(request), front.now)
    for _ in range(1000):
        front.step()
        if front.d.persistent_phase() == 4:  # ciphertext prepared, write pending
            break
    assert front.d.persistent_phase() == 4
    left = front.d.persistent_nonce_left()
    assert left == 63
    send_message(front.d, front.cid, 0x91, b'', front.now)
    for _ in range(50):
        response = front.step()
        if response is not None:
            break
    assert response == b'\x2d'
    assert front.d.persistent_nonce_left() == left
    assert front.store.write_count == 0
    front.store.delay = 0
    front.make()
    block = next(front.store.directory.glob('*.bin')).read_bytes()
    assert int.from_bytes(block[8:16], 'big') == 3  # boot1, cancelled2, committed3


def test_store_failure_or_unready_never_succeeds(persistent):
    persistent.store.write_failure = True
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}]}
    assert persistent.exchange(1, request) == b'\x7f'
    assert persistent.store.write_count == 0
    persistent.store.available = False
    assert persistent.exchange(1, request) == b'\x27'


def test_collision_bound_and_no_overwrite(persistent):
    persistent.store.collide = True
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}]}
    assert persistent.exchange(1, request) == b'\x28'
    assert persistent.store.write_count == 0


def test_missing_wrong_rp_and_non32_id_do_not_advance_counter(persistent):
    _, credential = persistent.make()
    assert persistent.get(credential.credential_id, rp='other.example') == b'\x2e'
    assert persistent.get(b'x') == b'\x2e'
    assert persistent.get(bytes(32)) == b'\x2e'
    assert persistent.journal.state.sign_count == 0


def test_exclude_lookup_uses_encrypted_persisted_record(persistent):
    _, credential = persistent.make()
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}],
               5: [{'type': 'public-key', 'id': credential.credential_id}]}
    assert persistent.exchange(1, request) == b'\x19'
    assert persistent.store.write_count == 1


def test_new_process_full_authentication_from_saved_files(persistent, tmp_path):
    front = persistent
    _, credential = front.make()
    server = Fido2Server(PublicKeyCredentialRpEntity(id='example.com', name='Cold host process'))
    options, state = server.authenticate_begin([credential], challenge=b'cold full authentication')
    client = CollectedClientData.create('webauthn.get', options.public_key.challenge, 'https://example.com')
    flash_path, response_path = tmp_path / 'flash-model.bin', tmp_path / 'response.cbor'
    flash_path.write_bytes(front.flash.image)
    directory = front.store.directory
    front.close()  # Destroy frontend/backend/RNG before independent process.
    script = '''
import ctypes as C, sys
from pathlib import Path
from test_journal import api, Journal
from test_root_random import provider
from test_persistent_backend import PersistentFrontend, StoreIO, READY
dll = api.__wrapped__(C.CDLL(sys.argv[1]))
assert dll.key_crypto_init() == 0
configuration = provider.__wrapped__(dll)
next(configuration)
dll.persistent_enable.argtypes = [C.POINTER(Journal), C.c_void_p, C.c_void_p,
                                 C.POINTER(StoreIO), C.c_void_p, READY, C.c_void_p]
front = PersistentFrontend(dll, sys.argv[2], Path(sys.argv[3]).read_bytes())
response = front.get(bytes.fromhex(sys.argv[4]), bytes.fromhex(sys.argv[5]))
assert response[0] == 0
Path(sys.argv[6]).write_bytes(response)
Path(sys.argv[3]).write_bytes(front.flash.image)
front.close()
try:
    next(configuration)
except StopIteration:
    pass
'''
    result = subprocess.run([sys.executable, '-c', script,
        str(ROOT / 'build/host/ctaphid.dll'), str(directory), str(flash_path),
        credential.credential_id.hex(), client.hash.hex(), str(response_path)],
        cwd=ROOT / 'tests', capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    response = response_path.read_bytes()
    decoded = cbor.decode(response[1:])
    data = AuthenticatorData(decoded[2])
    assert data.counter == 1 and data.is_user_present()
    authentication = AuthenticationResponse(raw_id=credential.credential_id,
        response=AuthenticatorAssertionResponse(client_data=client, authenticator_data=data, signature=decoded[3]))
    assert server.authenticate_complete(state, [credential], authentication) == credential


def test_cancel_after_durable_write_does_not_delete_object(persistent):
    front = persistent
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}]}
    send_message(front.d, front.cid, 0x90, b'\1'+cbor.encode(request), front.now)
    for _ in range(1000):
        front.step()
        if front.d.persistent_phase() == 5:  # durable write finished, verification pending
            break
    assert front.d.persistent_phase() == 5 and front.store.write_count == 1
    identifier = bytes.fromhex(next(front.store.directory.glob('*.bin')).stem.split('-')[1])
    front.store.delay = 20  # Keep readback pending while CANCEL is received.
    send_message(front.d, front.cid, 0x91, b'', front.now)
    for _ in range(50):
        response = front.step()
        if response is not None:
            break
    assert response == b'\x2d'
    assert len(list(front.store.directory.glob('*.bin'))) == 1
    assert front.get(identifier)[0] == 0


def test_counter_journal_io_failure_never_signs(persistent):
    _, credential = persistent.make()
    persistent.flash.read_fail = True
    assert persistent.get(credential.credential_id) == b'\x7f'
    assert not persistent.journal.ready


def test_provider_teardown_disables_backend(persistent):
    persistent.d.key_random_stop()
    request = {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
               4: [{'type': 'public-key', 'alg': -7}]}
    assert persistent.exchange(1, request) == b'\x27'
