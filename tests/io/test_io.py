import re
import pytest
from os import path
from src.io import io

def test_read_config():
    try:
        config = io.read_config()
    except Exception as e:
        pytest.fail(str(e))

    assert isinstance(config, dict)
    assert len(config.keys()) != 0
    assert all(isinstance(key, str) for key in config.values())


def test_read_fuzzer_stats_nonexistent_file():
    with pytest.raises(FileNotFoundError, match="Config file does not exist."):
        io.read_fuzzer_stats(f_path="nonexistent_file")


def test_read_fuzzer_stats_unreadable_file():
    with pytest.raises(RuntimeError):
        io.read_fuzzer_stats(f_path="/dev/urandom")


def test_read_fuzzer_stats_valid():
    try:
        contents = io.read_fuzzer_stats(f_path="tests/io/artifacts/test_fuzzer_stats.txt")
    except Exception as e:
        pytest.fail(str(e))

    assert isinstance(contents, dict)
    assert len(contents.keys()) != 0
    assert len(contents.values()) != 0


def test_get_frontier_seed_nonexistent_file():
    with pytest.raises(FileNotFoundError, match=f"Cannot determine frontier seed. `nonexistent_file` not found."):
        io.get_frontier_seed(f_path="nonexistent_file")


def test_get_frontier_seed_wrong_folder():
    with pytest.raises(FileNotFoundError, match=re.escape(f"[!] `/dev` does not contain valid seeds.")):
        io.get_frontier_seed(f_path="/dev")


def test_get_frontier_seed_empty_folder():
    try:
        f_path = io.get_frontier_seed(f_path="tests/io/artifacts/seeds/queue2")
    except Exception as e:
        pytest.fail(str(e))

    assert isinstance(f_path, str)
    assert len(f_path) == 0


def test_get_frontier_seed_valid():
    try:
        f_path = io.get_frontier_seed(f_path="tests/io/artifacts/seeds/queue1")
    except Exception as e:
        pytest.fail(str(e))

    assert isinstance(f_path, str)
    assert len(f_path) != 0
    assert path.exists(f_path)


def test_read_frontier_seed_nonexistent_file():
    with pytest.raises(FileNotFoundError, match=f"Cannot read frontier seed. `nonexistent_file` not found."):
        io.read_frontier_seed(f_path="nonexistent_file")

def test_read_frontier_seed_invalid_file():
    with pytest.raises(RuntimeError):
        io.read_frontier_seed(f_path="tests/io/artifacts/seeds")

def read_frontier_seed_valid():
    try:
        contents = io.read_frontier_seed(f_path='tests/io/artifacts/seeds/queue1/id:test_seed')
    except Exception as e:
        pytest.fail(str(e))

    assert isinstance(contents, bytes)
    assert len(contents) != 0