"""Actual C presence seam with normalized, simulated physical samples."""
import pytest


def waiting(lib):
    lib.presence_reset()
    assert lib.presence_begin(1, 1, 0, 0)
    assert lib.presence_sample(0, 25) == 2
    assert lib.presence_sample(1, 26) == 2


def test_short_press_cannot_authorize(lib):
    waiting(lib)
    for now in range(51, 1026, 25):
        assert lib.presence_sample(1, now) == 2
        assert not lib.presence_consume(1, 1, now)
    assert lib.presence_sample(1, 1026) == 3
    assert lib.presence_consume(1, 1, 1026)


@pytest.mark.parametrize('duration', range(1000))
def test_every_subsecond_hold_is_insufficient(lib, duration):
    waiting(lib)
    for now in range(51, 26 + duration, 25):
        assert lib.presence_sample(1, now) == 2
    assert lib.presence_sample(1, 26 + duration) == 2
    assert not lib.presence_consume(1, 1, 26 + duration)
    assert lib.presence_sample(0, 27 + duration) == 2
    assert lib.presence_progress(27 + duration) == 0


def test_progress_is_read_only_and_does_not_finish_hold(lib):
    waiting(lib)
    for now in range(51, 527, 25):
        lib.presence_sample(1, now)
    assert lib.presence_progress(526) == 500
    for now in range(551, 1002, 25):
        lib.presence_sample(1, now)
    assert lib.presence_progress(1025) == 999
    assert lib.presence_progress(1026) == 999  # No sample, no approval.
    assert not lib.presence_consume(1, 1, 1026)
    assert lib.presence_sample(1, 1026) == 3
    assert lib.presence_progress(1026) == 1000
    assert lib.presence_consume(1, 1, 1026)
    assert lib.presence_progress(1026) == 0


@pytest.mark.parametrize('gap', [101, 500, 999, 1000, 5000])
def test_missing_samples_restart_hold(lib, gap):
    waiting(lib)
    assert lib.presence_sample(1, 126) == 2
    assert lib.presence_progress(126 + gap) == 0
    restart = 126 + gap
    assert lib.presence_sample(1, restart) == 2
    assert lib.presence_progress(restart) == 0
    for now in range(restart + 25, restart + 1000, 25):
        assert lib.presence_sample(1, now) == 2
    assert lib.presence_sample(1, restart + 1000) == 3


def test_release_midway_never_accumulates_previous_hold(lib):
    waiting(lib)
    for now in range(51, 927, 25):
        lib.presence_sample(1, now)
    assert lib.presence_progress(926) == 900
    assert lib.presence_sample(0, 927) == 2
    assert lib.presence_progress(927) == 0
    lib.presence_sample(1, 928)
    for now in range(953, 1928, 25):
        assert lib.presence_sample(1, now) == 2
    assert lib.presence_sample(1, 1928) == 3


def test_timeout_wins_over_hold_completion(lib):
    lib.presence_reset()
    assert lib.presence_begin(1, 1, 0, 0)
    for now in range(25, 29001, 25):
        lib.presence_sample(0, now)
    lib.presence_sample(1, 29000)
    for now in range(29025, 30000, 25):
        assert lib.presence_sample(1, now) == 2
    assert lib.presence_sample(1, 30000) == 5
    assert lib.presence_progress(30000) == 0


def test_long_hold_not_reused_for_next_generation(lib):
    waiting(lib)
    for now in range(51, 1026, 25):
        lib.presence_sample(1, now)
    lib.presence_sample(1, 1026)
    assert lib.presence_consume(1, 1, 1026)
    assert lib.presence_begin(1, 2, 1, 1027)
    for now in range(1052, 3027, 25):
        assert lib.presence_sample(1, now) == 1
    assert not lib.presence_consume(1, 2, 3027)


def test_dual_key_requires_both_released_then_both_held(lib):
    lib.presence_reset()
    assert lib.presence_begin(1, 1, 1, 0)  # One key already down.
    for now in range(25, 1501, 25):
        assert lib.presence_inputs(0, 0, now) == 1
    assert lib.presence_inputs(1, 0, 1502) == 1
    assert lib.presence_inputs(1, 0, 1527) == 2
    for now in range(1552, 1803, 25):  # Only one key: no hold progress.
        assert lib.presence_inputs(0, 0, now) == 2
        assert lib.presence_progress(now) == 0
    lib.presence_inputs(0, 1, 1803)
    for now in range(1828, 2803, 25):
        assert lib.presence_inputs(0, 1, now) == 2
    assert lib.presence_inputs(0, 1, 2803) == 3
    assert lib.presence_consume(1, 1, 2803)


def test_dual_key_one_released_resets_progress(lib):
    waiting(lib)
    for now in range(51, 927, 25):
        lib.presence_inputs(0, 1, now)
    assert lib.presence_progress(926) == 900
    assert lib.presence_inputs(0, 0, 927) == 2  # One remains down.
    assert lib.presence_progress(927) == 0
    lib.presence_inputs(0, 1, 928)
    for now in range(953, 1928, 25):
        assert lib.presence_inputs(0, 1, now) == 2
    assert lib.presence_inputs(0, 1, 1928) == 3


def test_inconsistent_physical_input_fails_closed(lib):
    waiting(lib)
    assert lib.presence_inputs(1, 1, 51) == 4
    assert lib.presence_progress(51) == 0
    assert not lib.presence_consume(1, 1, 51)
