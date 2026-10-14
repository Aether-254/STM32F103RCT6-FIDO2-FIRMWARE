"""Full C CTAPHID/CTAP credential frontend; RAM backend and fake buttons only."""
import pytest
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject, AuthenticatorData, CollectedClientData,
    RegistrationResponse, AuthenticatorAttestationResponse,
    AuthenticationResponse, AuthenticatorAssertionResponse,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
)
from test_transport import secure_random, allocate, send_message, peek, message, feed, initial


class Frontend:
    def __init__(self, d):
        self.d = d
        d.reset()
        self.cid = allocate(d)
        assert d.frontend_enable(secure_random)
        self.now = 0
        self.keepalives = []

    def exchange(self, command, request, press=True):
        send_message(self.d, self.cid, 0x90, bytes([command])+cbor.encode(request), self.now)
        waiting_since = None
        deadline = self.now + 31000
        while self.now < deadline:
            self.now += 10
            if self.d.frontend_phase() == 2:
                if waiting_since is None:
                    waiting_since = self.now
                if press and self.now-waiting_since >= 50:
                    self.d.frontend_press(1)
            self.d.tick(self.now)
            if not peek(self.d)[1]:
                continue
            cid, response_command, response = message(self.d)
            assert cid == self.cid
            if response_command == 0xbb:
                self.keepalives.append(response[0])
                continue
            assert response_command == 0x90
            self.d.frontend_press(0)
            assert self.d.frontend_clean()
            return response
        pytest.fail('credential transaction did not terminate')

    def make(self, hash_value=b'h'*32, **overrides):
        request = {1: hash_value, 2: {'id': 'example.com'},
                   3: {'id': b'user'}, 4: [{'type': 'public-key', 'alg': -7}]}
        request.update(overrides)
        response = self.exchange(1, request)
        assert response[0] == 0
        decoded = cbor.decode(response[1:])
        assert cbor.encode(decoded) == response[1:]
        return decoded, AuthenticatorData(decoded[2]).credential_data


@pytest.fixture
def front(lib):
    frontend = Frontend(lib)
    yield frontend
    lib.dispose()


def make_request():
    return {1: b'h'*32, 2: {'id': 'example.com'}, 3: {'id': b'user'},
            4: [{'type': 'public-key', 'alg': -7}]}


def test_full_c_transport_registration_and_authentication_server_acceptance(front):
    server = Fido2Server(PublicKeyCredentialRpEntity(id='example.com', name='Local test'))
    options, state = server.register_begin(PublicKeyCredentialUserEntity(id=b'user', name='user'),
                                           challenge=b'register integration fixture')
    client = CollectedClientData.create('webauthn.create', options.public_key.challenge, 'https://example.com')
    result, credential = front.make(client.hash)
    assert result[1] == 'none' and result[3] == {}
    registration = RegistrationResponse(raw_id=credential.credential_id,
        response=AuthenticatorAttestationResponse(client_data=client,
            attestation_object=AttestationObject(cbor.encode({'fmt': result[1], 'authData': result[2], 'attStmt': result[3]}))))
    accepted = server.register_complete(state, registration)
    assert accepted.credential_data == credential
    assert front.d.frontend_stored() == 1 and front.d.frontend_count() == 0
    for counter in [1, 2, 3]:
        options, state = server.authenticate_begin([credential], challenge=bytes([counter])*32)
        client = CollectedClientData.create('webauthn.get', options.public_key.challenge, 'https://example.com')
        response = front.exchange(2, {1: 'example.com', 2: client.hash,
            3: [{'type': 'public-key', 'id': credential.credential_id}]})
        assert response[0] == 0
        decoded = cbor.decode(response[1:])
        assert cbor.encode(decoded) == response[1:]
        data = AuthenticatorData(decoded[2])
        assert data.counter == counter and data.is_user_present() and not data.is_user_verified()
        authentication = AuthenticationResponse(raw_id=decoded[1]['id'], response=AuthenticatorAssertionResponse(
            client_data=client, authenticator_data=data, signature=decoded[3]))
        assert server.authenticate_complete(state, [credential], authentication) == credential
    assert 2 in front.keepalives and 1 in front.keepalives


def test_exclude_list_waits_for_presence_and_never_creates(front):
    _, credential = front.make()
    request = make_request()
    request[5] = [{'type': 'public-key', 'id': credential.credential_id}]
    assert front.exchange(1, request) == b'\x19'
    assert front.d.frontend_stored() == 1


def test_excluded_timeout_returns_excluded_not_action_timeout(front):
    _, credential = front.make()
    request = make_request()
    request[5] = [{'type': 'public-key', 'id': credential.credential_id}]
    assert front.exchange(1, request, press=False) == b'\x19'
    assert front.d.frontend_stored() == 1


def test_wrong_rp_or_unknown_id_never_signs(front):
    _, credential = front.make()
    for rp, identifier in [('other.example', credential.credential_id), ('example.com', b'unknown')]:
        assert front.exchange(2, {1: rp, 2: b'h'*32, 3: [{'type': 'public-key', 'id': identifier}]}) == b'\x2e'
    assert front.d.frontend_count() == 0


def test_held_button_cannot_create_credential(front):
    front.d.frontend_press(1)
    assert front.exchange(1, make_request(), press=False) == b'\x2f'
    assert front.d.frontend_stored() == 0


@pytest.mark.parametrize('duration', [100, 500, 999])
def test_real_job_reports_hold_progress_and_cancel_clears_it(front, duration):
    d = front.d
    send_message(d, front.cid, 0x90, b'\x01' + cbor.encode(make_request()), front.now)
    for _ in range(6):
        front.now += 10
        d.tick(front.now)
    assert d.frontend_phase() == 2 and d.frontend_progress(front.now) == 0
    d.frontend_press(1)
    start = front.now + 10
    for offset in list(range(0, duration, 10)) + [duration]:
        front.now = start + offset
        d.tick(front.now)
        if peek(d)[1]:
            cid, command, body = message(d)
            assert cid == front.cid and command == 0xbb and body == b'\x02'
        assert d.frontend_phase() == 2
        assert d.frontend_progress(front.now) == offset
        assert d.frontend_stored() == 0
    send_message(d, front.cid, 0x91, b'', front.now)
    assert d.frontend_progress(front.now) == 0
    assert d.frontend_clean() and d.frontend_stored() == 0


@pytest.mark.parametrize('command,key,value,status', [
    (1, 7, {'rk': True}, 0x2b), (1, 7, {'uv': True}, 0x2c),
    (1, 7, {'up': True}, 0x2c), (1, 7, {'up': False}, 0x2c),
    (1, 8, b'pin', 0x2b), (1, 9, 1, 0x2b),
    (2, 5, {'rk': False}, 0x2b), (2, 5, {'uv': True}, 0x2c),
])
def test_unsupported_options_fail_closed(front, command, key, value, status):
    request = make_request() if command == 1 else {1: 'example.com', 2: b'h'*32}
    request[key] = value
    assert front.exchange(command, request) == bytes([status])


def test_backend_not_ready_never_starts_presence(front):
    front.d.frontend_set_ready(0)
    assert front.exchange(1, make_request()) == b'\x27'
    assert front.d.frontend_stored() == 0 and not front.keepalives


@pytest.mark.parametrize('op', [2, 4, 6])
def test_create_or_commit_failure_never_returns_success(front, op):
    front.d.frontend_fail(op)
    assert front.exchange(1, make_request()) == b'\x7f'
    assert front.d.frontend_stored() == 0


@pytest.mark.parametrize('op', [1, 3, 5, 7])
def test_lookup_counter_or_mismatched_record_failure(front, op):
    _, credential = front.make()
    front.d.frontend_fail(op)
    request = {1: 'example.com', 2: b'h'*32, 3: [{'type': 'public-key', 'id': credential.credential_id}]}
    assert front.exchange(2, request) == b'\x7f'


def test_bounded_pending_backend_operations(front):
    front.d.frontend_delay(20)
    _, credential = front.make()
    response = front.exchange(2, {1: 'example.com', 2: b'h'*32,
        3: [{'type': 'public-key', 'id': credential.credential_id}]})
    assert response[0] == 0 and front.d.frontend_stored() == 1 and front.d.frontend_count() == 1


def test_preflight_up_false_does_not_claim_presence(front):
    _, credential = front.make()
    response = front.exchange(2, {1: 'example.com', 2: b'h'*32,
        3: [{'type': 'public-key', 'id': credential.credential_id}], 5: {'up': False}}, press=False)
    assert response[0] == 0
    assert not AuthenticatorData(cbor.decode(response[1:])[2]).is_user_present()


def test_no_allow_list_no_discoverable_backend(front):
    assert front.exchange(2, {1: 'example.com', 2: b'h'*32}) == b'\x2e'


def test_counter_overflow_does_not_wrap_to_zero(front):
    _, credential = front.make()
    front.d.frontend_count_set(0xffffffff)
    assert front.exchange(2, {1: 'example.com', 2: b'h'*32,
        3: [{'type': 'public-key', 'id': credential.credential_id}]}) == b'\x28'


def test_cancel_before_presence_no_candidate_or_commit(front):
    d = front.d
    send_message(d, front.cid, 0x90, b'\x01'+cbor.encode(make_request()), front.now)
    d.tick(10)
    feed(d, initial(front.cid, 0x91), 11)
    while peek(d)[1]:
        _, cmd, response = message(d)
        if cmd == 0x90:
            assert response == b'\x2d'
    assert d.frontend_stored() == 0 and d.frontend_clean()


def test_allow_list_ignores_unknown_types_and_selects_valid_candidate(front):
    _, credential = front.make()
    response = front.exchange(2, {1: 'example.com', 2: b'h'*32, 3: [
        {'type': 'unknown-type', 'id': credential.credential_id},
        {'type': 'public-key', 'id': b'not-stored'},
        {'type': 'public-key', 'id': credential.credential_id}]})
    assert response[0] == 0
    assert cbor.decode(response[1:])[1]['id'] == credential.credential_id


def test_counter_reservation_is_not_rolled_back_on_cancel(front):
    _, credential = front.make()
    d = front.d
    request = {1: 'example.com', 2: b'h'*32,
        3: [{'type': 'public-key', 'id': credential.credential_id}]}
    send_message(d, front.cid, 0x90, b'\x02'+cbor.encode(request), front.now)
    wait = None
    for _ in range(1000):
        front.now += 10
        if d.frontend_phase() == 2:
            if wait is None:
                wait = front.now
            if front.now-wait >= 50:
                d.frontend_press(1)
        d.tick(front.now)
        while peek(d)[1]:
            assert message(d)[1] == 0xbb
        if d.frontend_phase() == 7:
            break
    else:
        pytest.fail('never reached sign phase')
    assert d.frontend_count() == 1
    feed(d, initial(front.cid, 0x91), front.now+1)
    assert message(d) == (front.cid, 0x90, b'\x2d')
    assert d.frontend_clean() and d.frontend_count() == 1
    d.frontend_press(0)
    response = front.exchange(2, request)
    assert response[0] == 0
    assert AuthenticatorData(cbor.decode(response[1:])[2]).counter == 2


def test_backend_readiness_lost_mid_request_revokes_authorization(front):
    d = front.d
    send_message(d, front.cid, 0x90, b'\x01'+cbor.encode(make_request()), front.now)
    d.tick(10)
    d.frontend_set_ready(0)
    d.tick(20)
    while peek(d)[1]:
        _, command, response = message(d)
        if command == 0x90:
            assert response == b'\x27'
    assert d.frontend_clean() and d.frontend_stored() == 0


def test_unknown_extensions_and_parameters_do_not_break_basic_registration(front):
    request = make_request()
    request[6] = {'unknownExtension': True}
    request[99] = {'futureParameter': b'ignored'}
    response = front.exchange(1, request)
    assert response[0] == 0 and front.d.frontend_stored() == 1


def test_engine_without_backend_denies_valid_make(lib):
    # Production main binds this exact engine with NULL backend, never host RAM.
    lib.reset()
    cid = allocate(lib)
    assert lib.frontend_no_backend()
    send_message(lib, cid, 0x90, b'\x01'+cbor.encode(make_request()))
    assert message(lib) == (cid, 0x90, b'\x27')
    assert lib.frontend_clean()
