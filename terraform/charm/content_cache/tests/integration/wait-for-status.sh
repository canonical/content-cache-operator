#!/bin/bash
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

MODEL_UUID=$1

juju wait-for application content-cache --model "$MODEL_UUID" --query='status=="active" || status=="blocked" || status=="maintenance"' --timeout=10m &> /dev/null
STATUS=$(juju status content-cache --model "$MODEL_UUID" --format=json | jq -r '.applications["content-cache"]["application-status"].current')

echo '{"status": "'"$STATUS"'"}'
