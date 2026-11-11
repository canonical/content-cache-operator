#!/bin/bash
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
set -euo pipefail

echo "CHARMCRAFT_EXPERIMENTAL_MONOREPO=1" >> "${GITHUB_ENV}"
