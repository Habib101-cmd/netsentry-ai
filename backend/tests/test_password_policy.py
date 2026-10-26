import pytest

from app.security import COMMON_PASSWORDS, validate_password


@pytest.mark.parametrize(
    "password",
    [
        "Password1234",
        "P@ssword!!!!!",
        "Passw0rd-2026!",
        "Qwerty-123456",
        "aaaaaaaaaaaa",
        "123456789012",
        "motdepasse2026",
        "administrator",
        "Football-2026-!!",
        "short",
    ],
)
def test_weak_passwords_are_rejected(password):
    with pytest.raises(ValueError):
        validate_password(password)


@pytest.mark.parametrize("password", ["Correct-Horse-42", "Another-Strong-Pass-9", "vélo-Océan-grille-47"])
def test_reasonable_passwords_are_accepted(password):
    validate_password(password)


def test_username_is_refused_inside_the_password():
    with pytest.raises(ValueError):
        validate_password("Mon-habib-Secret-91", "habib")


def test_common_password_list_is_loaded():
    assert len(COMMON_PASSWORDS) > 5000
