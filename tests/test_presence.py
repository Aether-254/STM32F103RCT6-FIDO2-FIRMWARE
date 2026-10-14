"""Physical input is simulated; never claims real board user presence."""
import pytest


@pytest.fixture
def presence(lib):
    lib.presence_reset()
    return lib


def approved(p, start=0):
    assert p.presence_begin(1, 1, 0, start)
    assert p.presence_sample(0, (start+25) & 0xffffffff) == 2
    assert p.presence_sample(1, (start+26) & 0xffffffff) == 2
    for offset in range(51, 1026, 25):
        assert p.presence_sample(1, (start+offset) & 0xffffffff) == 2
    assert p.presence_sample(1, (start+1026) & 0xffffffff) == 3


def test_fresh_debounced_press_one_shot(presence):
    p = presence
    approved(p)
    assert p.presence_consume(1, 1, 1026)
    assert not p.presence_consume(1, 1, 1026)


def test_held_button_never_authorizes(presence):
    p = presence
    assert p.presence_begin(1, 1, 1, 0)
    for t in [25, 100, 1000, 29999]:
        assert p.presence_sample(1, t) == 1
        assert not p.presence_consume(1, 1, t)
    assert p.presence_sample(1, 30000) == 5


def test_release_required_after_begin(presence):
    p = presence
    assert p.presence_begin(1, 1, 1, 0)
    assert p.presence_sample(0, 10) == 1
    assert p.presence_sample(0, 34) == 1
    assert p.presence_sample(0, 35) == 2
    assert p.presence_sample(1, 36) == 2
    assert p.presence_sample(1, 60) == 2
    for t in range(61, 1036, 25):
        assert p.presence_sample(1, t) == 2
    assert p.presence_sample(1, 1036) == 3


def test_press_and_release_bounce(presence):
    p = presence
    assert p.presence_begin(1, 1, 0, 0)
    for t in range(1, 51):
        assert p.presence_sample(t % 2, t) == 1
    assert p.presence_sample(0, 75) == 2
    for t in range(76, 126):
        assert p.presence_sample(t % 2, t) == 2
    for t in range(150, 1125, 25):
        assert p.presence_sample(1, t) == 2
    assert p.presence_sample(1, 1125) == 3


@pytest.mark.parametrize('cid,epoch', [(2, 1), (1, 2), (0, 0), (0xffffffff, 1)])
def test_identity_bound_no_cross_request(presence, cid, epoch):
    p = presence
    approved(p)
    assert not p.presence_consume(cid, epoch, 1026)
    assert not p.presence_cancel(cid, epoch)
    assert p.presence_consume(1, 1, 1026)


@pytest.mark.parametrize('cid,epoch', [(0, 1), (0xffffffff, 1), (1, 0)])
def test_invalid_identity(presence, cid, epoch):
    assert not presence.presence_begin(cid, epoch, 0, 0)


def test_busy_does_not_replace_request(presence):
    p = presence
    approved(p)
    assert not p.presence_begin(2, 2, 0, 1100)
    assert p.presence_consume(1, 1, 1100)


@pytest.mark.parametrize('time', [30000, 30001, 0x7fffffff])
def test_expiration_even_after_approval(presence, time):
    p = presence
    approved(p)
    assert not p.presence_consume(1, 1, time)
    assert p.presence_sample(1, time) == 5


def test_cancel_clears_approval(presence):
    p = presence
    approved(p)
    assert p.presence_cancel(1, 1)
    assert p.presence_sample(1, 1100) == 4
    assert not p.presence_consume(1, 1, 1100)
    assert p.presence_begin(1, 2, 1, 1101)
    assert p.presence_sample(1, 1200) == 1


def test_disconnect_reset_clears_approval(presence):
    p = presence
    approved(p)
    p.presence_reset()
    assert not p.presence_consume(1, 1, 100)
    assert p.presence_sample(1, 100) == 0


def test_tick_wrap(presence):
    p = presence
    start = 0xfffffff0
    approved(p, start)
    assert p.presence_consume(1, 1, (start+1026) & 0xffffffff)
    approved(p, start)
    assert not p.presence_consume(1, 1, (start+30000) & 0xffffffff)


def test_previous_press_cannot_authorize_next(presence):
    p = presence
    approved(p)
    assert p.presence_consume(1, 1, 1026)
    assert p.presence_begin(1, 2, 1, 1027)
    assert p.presence_sample(1, 1200) == 1
    assert not p.presence_consume(1, 2, 1200)
