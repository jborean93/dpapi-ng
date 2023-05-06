# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import pathlib


def get_test_data(name: str) -> bytes:
    test_path = pathlib.Path(__file__).parent / "data" / name
    return test_path.read_bytes()
