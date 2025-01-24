# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utilities for testing."""

from utilities import execute_command


def test_execute_command():
    """
    arrange: None
    act: Execute echo hello.
    assert: Returned values are correct.
    """
    return_code, stdout, stderr = execute_command(["echo", "hello"])
    assert return_code == 0
    assert stdout == "hello\n"
    assert stderr == ""
