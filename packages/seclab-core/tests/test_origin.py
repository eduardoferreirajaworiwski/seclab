"""Locks in the backward-compat contract of the DataOrigin shared refactor:
seclab_phantom.models.DataOrigin must be the *same object* as
seclab.core.origin.DataOrigin (a re-export, not a redefinition), so every
existing `from seclab_phantom.models import DataOrigin` import elsewhere in
the codebase keeps working unchanged after the move."""

from seclab.core.origin import DataOrigin as CoreDataOrigin


def test_phantom_data_origin_is_the_same_object_as_core_data_origin():
    from seclab_phantom.models import DataOrigin as PhantomDataOrigin

    assert PhantomDataOrigin is CoreDataOrigin


def test_data_origin_has_expected_members():
    assert CoreDataOrigin.LIVE == "live"
    assert CoreDataOrigin.MOCK == "mock"
    assert CoreDataOrigin.FALLBACK == "fallback"
