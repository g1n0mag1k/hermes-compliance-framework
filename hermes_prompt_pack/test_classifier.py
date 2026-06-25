"""Sanity tests for the hermes.classifier module.

These verify the test infrastructure is wired and import paths are
correct before any real classifier rules land. Per project mandate,
every regex rule shipped in classifier.py ships with positive,
negative, and adversarial-edge tests in this file as part of the
same commit.
"""


def test_classifier_module_imports() -> None:
    """The hermes.classifier module imports cleanly."""
    from hermes import classifier  # noqa: F401


def test_classifier_module_is_a_module() -> None:
    """Sanity: classifier is a real module, not unexpectedly mocked."""
    import types

    from hermes import classifier

    assert isinstance(classifier, types.ModuleType)
