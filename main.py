"""Password reminder: store Argon2id hashes and quiz yourself.

Originally written by Claude Sonnet 4.6 on 2026/03/28
"""

import json
import os
import random
import tempfile
import time
import uuid
from pathlib import Path

import argon2
import argon2.exceptions
import click
import keyring
import keyring.errors

CONFIG_PATH = Path.home() / ".password-reminder" / "config.json"
KEYRING_SERVICE = "password-reminder"
_CALIBRATION_PASSWORD = "calibration-sentinel-do-not-use"


# ---------------------------------------------------------------------------
# Config I/O
# ---------------------------------------------------------------------------


def load_config(path: Path = CONFIG_PATH) -> dict[str, object]:
    """Read config from *path*; return empty config if the file is absent."""
    if not path.exists():
        return {"services": {}, "argon2_params": None}
    with path.open() as f:
        data: dict[str, object] = json.load(f)
    data.setdefault("services", {})
    data.setdefault("argon2_params", None)
    return data


def save_config(config: dict[str, object], path: Path = CONFIG_PATH) -> None:
    """Atomically write *config* to *path*, creating parent dirs as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        os.unlink(tmp)
        raise


# ---------------------------------------------------------------------------
# Argon2 calibration and hashing
# ---------------------------------------------------------------------------


def _time_one_hash(params: dict[str, int]) -> float:
    """Hash the calibration sentinel with *params* and return elapsed seconds."""
    ph = argon2.PasswordHasher(
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params["hash_len"],
        salt_len=params["salt_len"],
    )
    start = time.perf_counter()
    ph.hash(_CALIBRATION_PASSWORD)
    return time.perf_counter() - start


def calibrate_argon2(target_seconds: float = 1.0) -> dict[str, int]:
    """Return Argon2id params that make one hash take at least *target_seconds*.

    Doubles memory_cost starting at 64 MiB until the target is reached.
    Uses all available CPU cores for parallelism.

    @param target_seconds: Minimum seconds a single hash should take (default 1s).
    @return: Parameter dict suitable for make_hasher().
    @raises RuntimeError: If memory_cost would exceed 32 GiB (safety guard).
    """
    parallelism = os.cpu_count() or 1
    params: dict[str, int] = {
        "time_cost": 1,
        "memory_cost": 65536,  # 64 MiB in KiB
        "parallelism": parallelism,
        "hash_len": 32,
        "salt_len": 16,
    }
    max_memory_kib = 32 * 1024 * 1024  # 32 GiB guard
    while True:
        elapsed = _time_one_hash(params)
        if elapsed >= target_seconds:
            return params
        if params["memory_cost"] >= max_memory_kib:
            raise RuntimeError(
                f"Could not reach {target_seconds}s target even at 32 GiB memory. "
                "Something is very wrong with the environment."
            )
        params = {**params, "memory_cost": params["memory_cost"] * 2}


def make_hasher(params: dict[str, int]) -> argon2.PasswordHasher:
    """Construct an Argon2id PasswordHasher from a params dict."""
    return argon2.PasswordHasher(
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params["hash_len"],
        salt_len=params["salt_len"],
    )


def hash_password(password: str, params: dict[str, int]) -> str:
    """Hash *password* with Argon2id and return the self-describing PHC string."""
    return make_hasher(params).hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify *password* against *stored_hash* (PHC format).

    @return: True on match, False on mismatch.
    @raises argon2.exceptions.InvalidHashError: If *stored_hash* is malformed.
    """
    ph = argon2.PasswordHasher()
    try:
        ph.verify(stored_hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


# ---------------------------------------------------------------------------
# Keyring helpers
# ---------------------------------------------------------------------------


def store_hash(uuid_key: str, hash_str: str) -> None:
    """Store *hash_str* in the system keyring under *uuid_key*."""
    keyring.set_password(KEYRING_SERVICE, uuid_key, hash_str)


def retrieve_hash(uuid_key: str) -> str:
    """Retrieve the hash stored under *uuid_key*.

    @raises ValueError: If no entry is found (should not happen in normal flow).
    """
    value = keyring.get_password(KEYRING_SERVICE, uuid_key)
    if value is None:
        raise ValueError(
            f"No hash found in keyring for key {uuid_key!r}. "
            "The keyring entry may have been deleted manually."
        )
    return value


def delete_hash(uuid_key: str) -> None:
    """Delete the keyring entry for *uuid_key*, ignoring missing-key errors."""
    try:
        keyring.delete_password(KEYRING_SERVICE, uuid_key)
    except keyring.errors.PasswordDeleteError:
        pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.group()
def cli() -> None:
    """Password reminder: store hashes and quiz yourself."""


@cli.command()
@click.argument("name")
def add(name: str) -> None:
    """Add or update the password for service NAME."""
    config = load_config()
    services: dict[str, str] = config["services"]  # type: ignore[assignment]

    # Calibrate on first use
    if config["argon2_params"] is None:
        click.echo("Calibrating Argon2 parameters (this runs only once)…")
        config["argon2_params"] = calibrate_argon2()
        save_config(config)
        params: dict[str, int] = config["argon2_params"]  # type: ignore[assignment]
        click.echo(
            f"Calibrated: memory={params['memory_cost'] // 1024} MiB, "
            f"parallelism={params['parallelism']}"
        )

    params = config["argon2_params"]  # type: ignore[assignment]

    # Handle existing entry
    if name in services:
        if not click.confirm(f"'{name}' already exists. Overwrite?", default=False):
            click.echo("Aborted.")
            return
        delete_hash(services[name])

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    click.echo("Hashing… (this takes about a second)")
    hash_str = hash_password(password, params)

    uuid_key = str(uuid.uuid4())
    store_hash(uuid_key, hash_str)
    services[name] = uuid_key
    config["services"] = services
    save_config(config)
    click.echo(f"Stored '{name}'.")


@cli.command("ask")
def ask_cmd() -> None:
    """Test all stored passwords in random order."""
    config = load_config()
    services: dict[str, str] = config["services"]  # type: ignore[assignment]

    if not services:
        click.echo("No services stored. Use 'add' to add one.")
        return

    order = list(services.items())
    random.shuffle(order)
    total = len(order)
    correct = 0

    for i, (name, uuid_key) in enumerate(order, 1):
        click.echo(f"[{i}/{total}] Testing: {name}")
        password = click.prompt("Password", hide_input=True)
        stored_hash = retrieve_hash(uuid_key)
        if verify_password(password, stored_hash):
            click.echo("  correct\n")
            correct += 1
        else:
            click.echo("  WRONG\n")

    click.echo(f"Result: {correct}/{total} correct")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
