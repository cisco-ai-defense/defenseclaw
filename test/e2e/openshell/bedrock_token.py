#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Print a short-term Amazon Bedrock API key for the real-model E2E lanes.

The key is minted from the ambient AWS identity (on the E2E host, the EC2
instance role) and is valid for at most 12 hours. Shared credential and config
files are ignored so a stale developer profile cannot shadow the role.

Requires the ``aws-bedrock-token-generator`` package; the E2E driver installs
it into a throwaway virtualenv.
"""

import argparse
import os


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    args = parser.parse_args()
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    os.environ["AWS_CONFIG_FILE"] = os.devnull
    from aws_bedrock_token_generator import provide_token

    print(provide_token(region=args.region))


if __name__ == "__main__":
    main()
