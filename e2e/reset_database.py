from pathlib import Path


DATABASE_PATH = Path("/tmp/sentinelsoc-e2e.db")

for suffix in ("", "-wal", "-shm"):
    (DATABASE_PATH.parent / f"{DATABASE_PATH.name}{suffix}").unlink(missing_ok=True)
