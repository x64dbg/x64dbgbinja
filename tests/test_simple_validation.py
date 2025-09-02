import json
import pathlib
import tempfile


def test_pytest_works():
    """Test that pytest is working."""
    assert True


def test_basic_python_functionality():
    """Test basic Python functionality."""
    assert 1 + 1 == 2


def test_json_works():
    """Test JSON functionality."""
    data = {"test": "value"}
    json_str = json.dumps(data)
    assert json.loads(json_str) == data


def test_pathlib_works():
    """Test pathlib functionality."""
    path = pathlib.Path("test.txt")
    assert path.name == "test.txt"
    assert path.suffix == ".txt"


def test_tempfile_works():
    """Test temporary file creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        assert tmp_path.exists()
        
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        assert test_file.read_text() == "test content"


def test_mock_import():
    """Test that unittest.mock is available."""
    from unittest.mock import Mock
    mock_obj = Mock()
    mock_obj.test_method.return_value = "test"
    assert mock_obj.test_method() == "test"