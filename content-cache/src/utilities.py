# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of helper functions or classes."""

import logging
import subprocess  # nosec B404
from typing import Any, Sequence

logger = logging.getLogger(__name__)


def execute_command(command: Sequence[str], **kwargs: Any) -> tuple[int, str, str]:
    """Execute a command.

    NOTE: if a python interface exist for a command use that instead.

    The command is executed with `subprocess.run`, additional arguments can be passed to it as
    keyword arguments. The following arguments to `subprocess.run` should not be set:
    `capture_output`, `shell`, `check`. As those arguments are set by this function.

    Args:
        command: The command to execute.
        kwargs: Additional keyword arguments for the `subprocess.run` call.

    Returns:
        The return code, stdout, and stderr.
    """
    logger.info("Executing: %s", command)
    result = subprocess.run(
        command,
        **kwargs,
        capture_output=True,
        # Disable running in shell for security reasons.
        # When shell is false, bandit (B603) will recommends to use python interface when possible.
        shell=False,  # nosec B603
        check=False,
    )
    stdout = result.stdout.decode("utf-8")
    stderr = result.stderr.decode("utf-8")
    logger.info("Return code of %s: %s", command, result.returncode)
    logger.debug("stdout of %s: %s", command, stdout)
    logger.debug("stderr of %s: %s", command, stderr)
    return (result.returncode, stdout, stderr)
