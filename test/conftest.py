import os
import sys
import tempfile
import shutil
import atexit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "python_wrapper"))

# Sandbox temporal aislado para evitar contaminar el entorno de desarrollo
_TEST_SANDBOX = tempfile.mkdtemp(prefix="terminus_pytest_")
_TEST_STORAGE = os.path.join(_TEST_SANDBOX, "storage")
_TEST_DB = os.path.join(_TEST_SANDBOX, "test_terminus.db")

os.environ["TERMINUS_STORAGE_DIR"] = _TEST_STORAGE
os.environ["TERMINUS_DB_PATH"] = _TEST_DB


def _cleanup_sandbox():
    shutil.rmtree(_TEST_SANDBOX, ignore_errors=True)


atexit.register(_cleanup_sandbox)
