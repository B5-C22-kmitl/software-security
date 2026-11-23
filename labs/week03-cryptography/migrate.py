"""Login-time migration from the Week 3 vulnerable password format.

Legacy format (vulnerable_crypto.py): MD5 hex digest.
New format (solution_skeleton.py): Argon2id encoded hash.

Call login_with_migration() from the application's login handler. It verifies
legacy passwords first and upgrades the stored hash only after a successful
password check. It never creates a new MD5 hash.

Requires:
    pip install argon2-cffi
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError


_password_hasher = PasswordHasher()
_LEGACY_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def verify_and_migrate_password(
    stored_hash: str,
    supplied_password: str,
) -> tuple[bool, str, bool]:
    """Verify a password and return (valid, replacement_hash, was_migrated).

    Argon2 hashes are verified normally. A legacy 32-character MD5 digest is
    checked for compatibility; when it matches, a fresh Argon2 hash is made.
    Unknown or malformed hash formats fail closed.
    """
    if not isinstance(stored_hash, str) or not isinstance(supplied_password, str):
        return False, stored_hash, False

    # Already migrated: verify with Argon2. Rehash if parameters have changed.
    if stored_hash.startswith("$argon2"):
        try:
            valid = _password_hasher.verify(stored_hash, supplied_password)
        except (VerificationError, InvalidHashError, TypeError):
            return False, stored_hash, False

        if not valid:
            return False, stored_hash, False

        if _password_hasher.check_needs_rehash(stored_hash):
            return True, _password_hasher.hash(supplied_password), True

        return True, stored_hash, False

    # Legacy compatibility path. This is verification only, not new storage.
    if _LEGACY_MD5_RE.fullmatch(stored_hash):
        legacy_candidate = hashlib.md5(supplied_password.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(legacy_candidate, stored_hash.lower()):
            return False, stored_hash, False

        return True, _password_hasher.hash(supplied_password), True

    # Never guess an unknown hash format.
    return False, stored_hash, False


def login_with_migration(
    user_id: str,
    supplied_password: str,
    load_password_hash: Callable[[str], str | None],
    save_password_hash: Callable[[str, str], None],
) -> bool:
    """Authenticate and upgrade a legacy hash during login.

    `load_password_hash(user_id)` reads the user's stored hash.
    `save_password_hash(user_id, new_hash)` updates that user's stored hash.

    The save callback is invoked only after the password is verified. Connect
    these callbacks to the database functions used by your application.
    """
    stored_hash = load_password_hash(user_id)
    if stored_hash is None:
        return False

    valid, replacement_hash, was_migrated = verify_and_migrate_password(
        stored_hash,
        supplied_password,
    )
    if not valid:
        return False

    if was_migrated:
        save_password_hash(user_id, replacement_hash)

    return True
