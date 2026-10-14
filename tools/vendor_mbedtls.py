"""Fetch pinned official crypto sources. Never runs upstream scripts or touches hardware."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import json
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSION = "3.6.7"
URL = f"https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-{VERSION}/mbedtls-{VERSION}.tar.bz2"
SHA256 = "a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
DEST = ROOT / "third_party" / f"mbedtls-{VERSION}"


def main():
    manifest = DEST / "SOURCE.json"
    if manifest.exists():
        recorded = json.loads(manifest.read_text())
        for name, expected in recorded["files"].items():
            actual = hashlib.sha256((DEST / name).read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError(f"Vendored source modified: {name}")
        print(f"Verified existing Mbed TLS {VERSION}: {len(recorded['files'])} files")
        return
    data = urllib.request.urlopen(URL, timeout=90).read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError("Official source archive SHA256 mismatch")
    archive = ROOT / "build" / "downloads" / f"mbedtls-{VERSION}.tar.bz2"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(data)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if ".." in path.parts or path.is_absolute():
                raise RuntimeError("Unsafe archive path")
            parts = path.parts[1:]
            if not parts or not member.isfile():
                continue
            if parts[0] not in {"include", "library", "LICENSE", "LICENSES", "SECURITY.md", "README.md"}:
                continue
            relative = Path(*parts)
            output = DEST / relative
            if output.exists():
                raise RuntimeError(f"Refusing to overwrite existing unmanifested file: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            stream = tar.extractfile(member)
            assert stream is not None
            content = stream.read()
            output.write_bytes(content)
            files[relative.as_posix()] = hashlib.sha256(content).hexdigest()
    manifest.write_text(json.dumps({"version": VERSION, "url": URL,
        "archive_sha256": SHA256, "files": files}, indent=2), encoding="utf-8")
    print(f"Fetched and verified Mbed TLS {VERSION}: {len(files)} files")


if __name__ == "__main__":
    main()
