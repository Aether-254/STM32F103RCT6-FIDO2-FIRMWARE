"""Server-accepted protocol artifacts; NOT a USB/browser/hardware ceremony."""
import ctypes as C
import hashlib
import pytest
from cryptography.exceptions import InvalidSignature
from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject, AuthenticatorData, CollectedClientData,
    RegistrationResponse, AuthenticatorAttestationResponse,
    AuthenticationResponse, AuthenticatorAssertionResponse,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
)
from test_transport import secure_random

RP = b'example.com'
PRIVATE = (17).to_bytes(32, 'big')


def make(lib, identifier=b'test-credential', counter=0):
    output = C.create_string_buffer(388)
    size = C.c_size_t()
    assert lib.key_authdata_make(RP, len(RP), PRIVATE, identifier, len(identifier),
                                counter, output, len(output), C.byref(size), secure_random, None) == 0
    return bytes(output)[:size.value]


def assertion(lib, client_data, rp=RP, up=True, counter=1):
    output = C.create_string_buffer(37)
    assert lib.key_authdata_assert(rp, len(rp), counter, up, output, 37) == 0
    authdata = bytes(output)
    digest = C.create_string_buffer(32)
    assert lib.key_authdata_digest(authdata, len(authdata), client_data.hash, digest) == 0
    assert bytes(digest) == hashlib.sha256(authdata+client_data.hash).digest()
    signature = C.create_string_buffer(72)
    size = C.c_size_t()
    assert lib.key_crypto_p256_sign(PRIVATE, digest, signature, 72, C.byref(size), secure_random, None) == 0
    return authdata, bytes(signature)[:size.value]


@pytest.mark.parametrize('length', [1, 23, 24, 255, 256])
@pytest.mark.parametrize('counter', [0, 1, 0xffffffff])
def test_authdata_cose_roundtrip(lib, length, counter):
    identifier = bytes(range(256))[:length]
    data = make(lib, identifier, counter)
    parsed = AuthenticatorData(data)
    assert parsed.rp_id_hash == hashlib.sha256(RP).digest()
    assert parsed.is_user_present() and parsed.is_attested()
    assert not parsed.is_user_verified()
    assert parsed.counter == counter
    assert parsed.credential_data.credential_id == identifier
    assert parsed.credential_data.aaguid == bytes(16)
    assert parsed.credential_data.public_key[1] == 2
    assert parsed.credential_data.public_key[3] == -7
    # Independent decoder and canonical encoding reproduce the exact C COSE.
    cose = data[55+length:]
    assert cbor.encode(cbor.decode(cose)) == cose


@pytest.mark.parametrize('identifier', [b'', b'x'*257])
def test_authdata_credential_bounds(lib, identifier):
    output = C.create_string_buffer(b'Z'*388)
    size = C.c_size_t(999)
    assert lib.key_authdata_make(RP, len(RP), PRIVATE, identifier, len(identifier), 0,
                                output, 388, C.byref(size), secure_random, None) != 0
    assert size.value == 0


def test_authdata_capacity_no_overwrite(lib):
    output = C.create_string_buffer(b'Z'*388)
    size = C.c_size_t(999)
    assert lib.key_authdata_make(RP, len(RP), PRIVATE, b'id', 2, 0,
                                output, 133, C.byref(size), secure_random, None) != 0
    assert size.value == 0 and bytes(output)[:388] == b'Z'*388


def registration(lib):
    server = Fido2Server(PublicKeyCredentialRpEntity(id='example.com', name='Local test'))
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(id=b'user', name='user', display_name='User'),
        challenge=b'registration challenge fixture')
    client = CollectedClientData.create('webauthn.create', options.public_key.challenge,
                                       'https://example.com')
    data = make(lib)
    response = RegistrationResponse(raw_id=b'test-credential', response=AuthenticatorAttestationResponse(
        client_data=client, attestation_object=AttestationObject(cbor.encode(
            {'fmt': 'none', 'attStmt': {}, 'authData': data}))))
    accepted = server.register_complete(state, response)
    return server, accepted.credential_data


def test_c_artifacts_accepted_by_real_fido2_server(lib):
    server, credential = registration(lib)
    options, state = server.authenticate_begin([credential], challenge=b'assertion challenge fixture')
    client = CollectedClientData.create('webauthn.get', options.public_key.challenge, 'https://example.com')
    data, signature = assertion(lib, client)
    response = AuthenticationResponse(raw_id=credential.credential_id,
        response=AuthenticatorAssertionResponse(client_data=client,
            authenticator_data=AuthenticatorData(data), signature=signature, user_handle=b'user'))
    assert server.authenticate_complete(state, [credential], response) == credential


@pytest.mark.parametrize('tamper', ['origin', 'challenge', 'rp', 'presence', 'signature', 'credential', 'client_hash'])
def test_server_rejects_wrong_ceremony_binding(lib, tamper):
    server, credential = registration(lib)
    options, state = server.authenticate_begin([credential], challenge=b'assertion challenge fixture')
    client = CollectedClientData.create('webauthn.get',
        b'wrong challenge' if tamper == 'challenge' else options.public_key.challenge,
        'https://evil.example' if tamper == 'origin' else 'https://example.com')
    data, signature = assertion(lib, client, rp=b'other.example' if tamper == 'rp' else RP,
                                up=tamper != 'presence')
    if tamper == 'signature':
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    if tamper == 'client_hash':
        client = CollectedClientData.create('webauthn.get', options.public_key.challenge,
                                           'https://example.com', unrelated='changed JSON after signing')
    response = AuthenticationResponse(
        raw_id=b'unknown-id' if tamper == 'credential' else credential.credential_id,
        response=AuthenticatorAssertionResponse(client_data=client,
            authenticator_data=AuthenticatorData(data), signature=signature, user_handle=b'user'))
    with pytest.raises((ValueError, InvalidSignature)):
        server.authenticate_complete(state, [credential], response)
