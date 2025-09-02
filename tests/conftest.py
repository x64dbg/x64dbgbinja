import json
import pathlib
import tempfile
from unittest.mock import Mock, MagicMock

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield pathlib.Path(tmpdir)


@pytest.fixture
def sample_json_db():
    """Sample x64dbg JSON database for testing."""
    return {
        "labels": [
            {
                "text": "main",
                "manual": False,
                "module": "test.exe",
                "address": "0x1000"
            },
            {
                "text": "sub_function",
                "manual": True,
                "module": "test.exe", 
                "address": "0x2000"
            }
        ],
        "comments": [
            {
                "text": "Entry point",
                "manual": True,
                "module": "test.exe",
                "address": "0x1000"
            }
        ]
    }


@pytest.fixture
def json_db_file(temp_dir, sample_json_db):
    """Create a temporary JSON database file."""
    db_file = temp_dir / "test.dd64"
    db_file.write_text(json.dumps(sample_json_db))
    return db_file


@pytest.fixture
def mock_binary_view():
    """Mock Binary Ninja BinaryView object."""
    mock_bv = Mock()
    mock_bv.start = 0x400000
    mock_bv.arch.address_size = 8
    mock_bv.arch.default_int_size = 8
    mock_bv.arch.name = "x86_64"
    mock_bv.file.original_filename = "/path/to/test.exe"
    mock_bv.file.filename = "/path/to/test.exe"
    mock_bv.file.database.globals = {}
    
    # Mock functions and symbols
    mock_symbol = Mock()
    mock_symbol.name = "test_symbol"
    mock_symbol.address = 0x401000
    mock_symbol.auto = False
    
    mock_bv.get_symbols.return_value = [mock_symbol]
    mock_bv.functions = []
    
    return mock_bv


@pytest.fixture
def mock_function():
    """Mock Binary Ninja Function object."""
    mock_func = Mock()
    mock_func.name = "test_function"
    mock_func.comments = {0x401000: "Test comment"}
    mock_func.symbol.type.name = "FunctionSymbol"
    return mock_func


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    mock_log = Mock()
    mock_log.log_info = Mock()
    mock_log.log_debug = Mock()
    mock_log.log_error = Mock()
    return mock_log


@pytest.fixture
def mock_settings():
    """Mock Binary Ninja Settings object."""
    mock_settings = Mock()
    mock_settings.get_bool.return_value = True
    mock_settings.register_group = Mock()
    mock_settings.register_setting = Mock()
    return mock_settings


@pytest.fixture
def mock_pathlib_path(temp_dir):
    """Mock pathlib.Path for file operations."""
    def _mock_path(filename):
        return temp_dir / filename
    return _mock_path


@pytest.fixture(autouse=True)
def reset_mocks():
    """Reset all mocks after each test."""
    yield
    # Any cleanup code can go here if needed


@pytest.fixture
def sample_plugin_config():
    """Sample plugin configuration for testing."""
    return {
        "pluginmetadataversion": 2,
        "name": "x64dbgbinja",
        "author": "x64dbg",
        "type": ["sync"],
        "api": ["python3"],
        "description": "Official x64dbg plugin for Binary Ninja.",
        "platforms": ["Darwin", "Windows", "Linux"],
        "version": "2.0.7",
        "minimumBinaryNinjaVersion": 6455
    }


@pytest.fixture
def mock_file_dialogs():
    """Mock file dialog functions."""
    dialogs = Mock()
    dialogs.get_save_filename_input = Mock(return_value="/tmp/test.dd64")
    dialogs.get_open_filename_input = Mock(return_value="/tmp/test.dd64")
    return dialogs