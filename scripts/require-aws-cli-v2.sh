#!/usr/bin/env bash

set -euo pipefail

if ! aws_version=$(aws --version 2>&1); then
  echo "::error::enrollment recovery requires AWS CLI v2, but aws is unavailable"
  exit 1
fi
if [[ ! "$aws_version" =~ ^aws-cli/2\. ]]; then
  echo "::error::enrollment recovery requires AWS CLI v2"
  exit 1
fi
