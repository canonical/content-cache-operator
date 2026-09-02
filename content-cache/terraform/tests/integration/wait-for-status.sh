#!/bin/bash
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

MODEL_UUID=$1

juju wait-for application content-cache --query='status=="active" || status=="blocked" || status=="maintenance"' --timeout=10m &> /dev/null
STATUS=$(juju status content-cache --model "$MODEL_UUID" --format=json | jq -r '.applications["content-cache"]["application-status"].current')

echo '{"status": "'"$STATUS"'"}'
