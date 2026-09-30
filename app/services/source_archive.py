"""Uploaded ZIP archives: validation, encrypted storage in GridFS, safe extraction.

Archives are treated as hostile (PRD §17, §80). They are inspected before being
stored, and extraction re-checks every entry and counts the bytes actually
written, because ZIP headers can lie about sizes.
"""
import hashlib
import io
import os
import posixpath
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from typing import BinaryIO

from bson import ObjectId
from flask import current_app
from gridfs import GridFSBucket, NoFile

from ..db import get_db
from ..db.utils import utcnow
from ..errors import ApiError
from .crypto import decrypt_stream, encrypt_stream

BUCKET = "source_archives"
_COPY_CHUNK = 1024 * 1024


class UnsafeArchive(Exception):
    def __init__(self, message: str, entry: str | None = None):
        super().__init__(message)
        self.message = message
        self.entry = entry


@dataclass
class ArchiveStats:
    file_count: int
    uncompressed_size: int
    root_prefix: str  # e.g. "project-main/" when everything sits in one top folder, else ""


def _bucket() -> GridFSBucket:
    return GridFSBucket(get_db(), bucket_name=BUCKET)


def _clean_name(name: str) -> str:
    """Normalise an entry name, rejecting absolute paths and traversal."""
    if "\x00" in name:
        raise UnsafeArchive("Entry name contains a NUL byte", name)
    unified = name.replace("\\", "/")
    if unified.startswith("/") or (len(unified) > 1 and unified[1] == ":"):
        raise UnsafeArchive("Absolute paths are not allowed", name)
    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchive("Path traversal ('..') is not allowed", name)
    return "/".join(parts)


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16)


def inspect_zip(zf: zipfile.ZipFile) -> ArchiveStats:
    cfg = current_app.config
    max_files, max_bytes = cfg["MAX_SOURCE_FILES"], cfg["MAX_SOURCE_BYTES"]
    max_ratio = cfg["ZIP_MAX_COMPRESSION_RATIO"]

    files, total, tops = 0, 0, set()
    seen = set()
    for info in zf.infolist():
        name = _clean_name(info.filename)
        if not name:
            continue
        if info.flag_bits & 0x1:
            raise UnsafeArchive("Encrypted entries are not supported", info.filename)
        if _is_symlink(info):
            raise UnsafeArchive("Symbolic links are not allowed", info.filename)
        tops.add(name.split("/")[0] + ("/" if "/" in name or info.is_dir() else ""))
        if info.is_dir():
            continue
        key = name.lower()
        if key in seen:
            raise UnsafeArchive("Duplicate file names are not allowed", info.filename)
        seen.add(key)
        files += 1
        total += info.file_size
        if files > max_files:
            raise UnsafeArchive(f"Archive has more than {max_files} files")
        if total > max_bytes:
            raise UnsafeArchive(f"Archive expands to more than {max_bytes // (1024 * 1024)} MB")
        if info.file_size > 1024 * 1024 and info.file_size > max_ratio * max(info.compress_size, 1):
            raise UnsafeArchive("Suspicious compression ratio (possible zip bomb)", info.filename)
    if files == 0:
        raise UnsafeArchive("Archive contains no files")
    root = next(iter(tops)) if len(tops) == 1 and next(iter(tops)).endswith("/") else ""
    return ArchiveStats(file_count=files, uncompressed_size=total, root_prefix=root)


def validate_upload(fileobj: BinaryIO) -> ArchiveStats:
    """Raise ApiError(422) if the upload is not a safe ZIP archive."""
    fileobj.seek(0)
    if not zipfile.is_zipfile(fileobj):
        raise ApiError(422, "invalid_archive", "File is not a valid ZIP archive")
    fileobj.seek(0)
    try:
        with zipfile.ZipFile(fileobj) as zf:
            return inspect_zip(zf)
    except UnsafeArchive as err:
        raise ApiError(422, "unsafe_archive", err.message, {"entry": err.entry} if err.entry else None)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError):
        raise ApiError(422, "invalid_archive", "File is not a valid ZIP archive")
    finally:
        fileobj.seek(0)


def store_archive(fileobj: BinaryIO, *, org_id: ObjectId, repo_id: ObjectId, filename: str,
                  stats: ArchiveStats) -> dict:
    """Encrypt and store an archive in GridFS. Returns the repository `source` sub-document."""
    fileobj.seek(0)
    digest = hashlib.sha256()
    size = 0

    class _Hashing:
        def read(self, n: int) -> bytes:
            nonlocal size
            chunk = fileobj.read(n)
            digest.update(chunk)
            size += len(chunk)
            return chunk

    now = utcnow()
    with _bucket().open_upload_stream(
        filename,
        metadata={"organization_id": org_id, "repository_id": repo_id, "encrypted": True, "created_at": now},
    ) as stream:
        encrypt_stream(_Hashing(), stream.write)
        archive_id = stream._id
    _bucket_files().update_one({"_id": archive_id}, {"$set": {"metadata.sha256": digest.hexdigest(),
                                                               "metadata.size": size}})
    return {
        "type": "zip",
        "archive_id": archive_id,
        "filename": filename,
        "size": size,
        "sha256": digest.hexdigest(),
        "file_count": stats.file_count,
        "uncompressed_size": stats.uncompressed_size,
        "uploaded_at": now,
    }


def _bucket_files():
    return get_db()[f"{BUCKET}.files"]


def reencrypt_archive(source: dict, org_id: ObjectId) -> dict:
    """Rewrite a stored archive under the primary encryption key (key rotation). Returns the new
    `source` sub-document; the caller swaps it in and deletes the old archive."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "a.zip")
        load_archive(source, org_id, path)  # verifies the SHA-256 on the way out
        with open(path, "rb") as fh:
            data = io.BytesIO(fh.read())
    doc = _bucket_files().find_one({"_id": source["archive_id"]}, {"metadata": 1})
    stats = ArchiveStats(file_count=source["file_count"], uncompressed_size=source["uncompressed_size"], root_prefix="")
    new = store_archive(data, org_id=org_id, repo_id=doc["metadata"]["repository_id"], filename=source["filename"],
                        stats=stats)
    if new["sha256"] != source["sha256"]:
        delete_archive(new["archive_id"])
        raise UnsafeArchive("Re-encrypted archive didn't match the original")
    new["uploaded_at"] = source["uploaded_at"]
    return new


def delete_archive(archive_id: ObjectId, session=None) -> None:
    try:
        _bucket().delete(archive_id, session=session)
    except NoFile:
        pass


def delete_repository_archives(org_id: ObjectId, repo_id: ObjectId, session=None) -> None:
    ids = [f["_id"] for f in _bucket_files().find(
        {"metadata.organization_id": org_id, "metadata.repository_id": repo_id}, {"_id": 1}, session=session)]
    for archive_id in ids:
        delete_archive(archive_id, session=session)


def load_archive(source: dict, org_id: ObjectId, dest_path: str) -> None:
    """Decrypt a stored archive to dest_path (mode 0600) and verify its SHA-256."""
    doc = _bucket_files().find_one({"_id": source["archive_id"], "metadata.organization_id": org_id})
    if doc is None:
        raise UnsafeArchive("Stored archive not found")
    digest = hashlib.sha256()
    fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out, _bucket().open_download_stream(doc["_id"]) as stream:
        for chunk in decrypt_stream(stream.readline):
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != source["sha256"]:
        raise UnsafeArchive("Stored archive failed its integrity check")


def safe_extract(zip_path: str, dest: str, *, root_prefix: str = "", max_bytes: int | None = None,
                 max_files: int | None = None) -> int:
    """Extract into dest, re-validating every entry. Returns the number of files written.

    - Names are normalised and must stay inside dest (checked on the real path).
    - Symlinks, encrypted entries and device files are rejected.
    - Files are created with O_EXCL | O_NOFOLLOW and mode 0600; archive
      permissions (e.g. executable bits) are ignored.
    - The real number of bytes written is capped, whatever the headers claim.
    """
    cfg = current_app.config
    max_bytes = max_bytes if max_bytes is not None else cfg["MAX_SOURCE_BYTES"]
    max_files = max_files if max_files is not None else cfg["MAX_SOURCE_FILES"]
    dest_real = os.path.realpath(dest)
    written, files = 0, 0

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = _clean_name(info.filename)
            if root_prefix and name.startswith(root_prefix):
                name = name[len(root_prefix):]
            if not name or info.is_dir():
                continue
            if info.flag_bits & 0x1 or _is_symlink(info):
                raise UnsafeArchive("Unsafe entry", info.filename)
            target = os.path.realpath(os.path.join(dest_real, *posixpath.normpath(name).split("/")))
            if not target.startswith(dest_real + os.sep):
                raise UnsafeArchive("Entry escapes the extraction directory", info.filename)
            files += 1
            if files > max_files:
                raise UnsafeArchive(f"Archive has more than {max_files} files")
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as out, zf.open(info) as src:
                while chunk := src.read(_COPY_CHUNK):
                    written += len(chunk)
                    if written > max_bytes:
                        raise UnsafeArchive("Archive expands beyond the size limit")
                    out.write(chunk)
    return files


def extract_stored_archive(source: dict, org_id: ObjectId, dest: str) -> int:
    """Load, verify and safely extract a stored archive into dest."""
    fd, tmp_zip = tempfile.mkstemp(suffix=".zip", dir=os.path.dirname(dest))
    os.close(fd)
    os.unlink(tmp_zip)  # load_archive creates it with O_EXCL
    try:
        load_archive(source, org_id, tmp_zip)
        with zipfile.ZipFile(tmp_zip) as zf:
            stats = inspect_zip(zf)
        os.makedirs(dest, mode=0o700, exist_ok=True)
        return safe_extract(tmp_zip, dest, root_prefix=stats.root_prefix)
    finally:
        if os.path.exists(tmp_zip):
            os.unlink(tmp_zip)
