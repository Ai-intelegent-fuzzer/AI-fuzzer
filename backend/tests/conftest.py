import os
import tempfile
from pathlib import Path


os.environ["AI_FUZZER_ALLOW_PRIVATE_TARGETS"] = "true"
os.environ["AI_FUZZER_ALLOW_LOCAL_OLLAMA"] = "true"
test_database_path = Path(tempfile.gettempdir()) / f"ai_fuzzer_tests_{os.getpid()}.sqlite3"
os.environ["AI_FUZZER_DATABASE_URL"] = f"sqlite:///{test_database_path.as_posix()}"
