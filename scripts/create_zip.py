import os
import zipfile
from pathlib import Path

def create_codebase_zip():
    root = Path(__file__).resolve().parent.parent
    zip_name = "CG.zip"
    out_path = root / zip_name

    exclude_dirs = {"venv", ".git", "__pycache__", ".pytest_cache", ".idea", ".vscode", "screenshots", "logs"}
    exclude_exts = {".pyc", ".pyo", ".pyd", ".zip", ".db", ".db-wal", ".db-shm", ".sqlite", ".log", ".lnk"}
    exclude_files = {".env", "audit_anchor.jsonl", "testbed_runner.log", "contextguard.db", "platform.db"}

    count = 0
    total_size = 0

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for f in filenames:
                ext = Path(f).suffix.lower()
                if ext in exclude_exts or f in exclude_files or f == zip_name or f.startswith(".env.") and f != ".env.example":
                    continue
                full_path = Path(dirpath) / f
                rel_path = full_path.relative_to(root)
                arcname = Path("CG") / rel_path
                zf.write(full_path, arcname=str(arcname).replace("\\", "/"))
                count += 1
                total_size += full_path.stat().st_size

    print(f"SUCCESS: Zipped {count} files ({total_size / (1024*1024):.2f} MB uncompressed) into {zip_name} ({out_path.stat().st_size / (1024*1024):.2f} MB compressed)")
    print(f"Location: {out_path}")

if __name__ == "__main__":
    create_codebase_zip()
