"""
Reusable JSON cache manager for threat-intelligence lookups.

This module handles:
- VirusTotal cache
- AbuseIPDB cache
- TTL expiration
- Atomic JSON writes
- Corrupted cache recovery
- Cache metadata
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class ThreatIntelCache:
    """Manage persistent JSON caches for threat-intelligence providers."""

    SUPPORTED_SOURCES = {
        "virustotal": "vt_cache.json",
        "abuseipdb": "abuseipdb_cache.json",
    }

    def __init__(
        self,
        cache_directory: str | Path | None = None,
        default_ttl_hours: int = 24,
    ) -> None:
        """
        Initialize the cache manager.

        Args:
            cache_directory:
                Directory containing the cache JSON files.
                Defaults to the root-level `cache` directory.

            default_ttl_hours:
                Number of hours before cached data expires.
        """
        if default_ttl_hours <= 0:
            raise ValueError("default_ttl_hours must be greater than zero.")

        project_root = Path(__file__).resolve().parent.parent

        self.cache_directory = (
            Path(cache_directory).resolve()
            if cache_directory is not None
            else project_root / "cache"
        )

        self.default_ttl_hours = default_ttl_hours
        self.metadata_file = self.cache_directory / "cache_metadata.json"
        self._lock = threading.RLock()

        self.cache_directory.mkdir(parents=True, exist_ok=True)
        self._initialize_cache_files()

    @staticmethod
    def _utc_now() -> datetime:
        """Return the current timezone-aware UTC datetime."""
        return datetime.now(timezone.utc)

    @staticmethod
    def _normalize_ioc(ioc: str) -> str:
        """
        Normalize an IOC before using it as a cache key.

        Domains, URLs, hashes, and IP addresses are stripped and converted
        to lowercase for consistent cache lookups.
        """
        if not isinstance(ioc, str):
            raise TypeError("IOC must be a string.")

        normalized = ioc.strip().lower()

        if not normalized:
            raise ValueError("IOC cannot be empty.")

        return normalized

    def _validate_source(self, source: str) -> str:
        """Validate and normalize a threat-intelligence source name."""
        if not isinstance(source, str):
            raise TypeError("Source must be a string.")

        normalized_source = source.strip().lower()

        if normalized_source not in self.SUPPORTED_SOURCES:
            supported = ", ".join(sorted(self.SUPPORTED_SOURCES))
            raise ValueError(
                f"Unsupported cache source: {source!r}. "
                f"Supported sources: {supported}"
            )

        return normalized_source

    def _cache_path(self, source: str) -> Path:
        """Return the JSON file path for a cache source."""
        validated_source = self._validate_source(source)
        return self.cache_directory / self.SUPPORTED_SOURCES[validated_source]

    def _initialize_cache_files(self) -> None:
        """Create missing cache files and ensure they contain JSON objects."""
        files = [
            self.cache_directory / filename
            for filename in self.SUPPORTED_SOURCES.values()
        ]
        files.append(self.metadata_file)

        for file_path in files:
            if not file_path.exists():
                self._atomic_write(file_path, {})

    def _load_json(self, file_path: Path) -> dict[str, Any]:
        """
        Load a JSON object from disk.

        If the file is empty, malformed, or does not contain an object,
        it is backed up and reset to an empty object.
        """
        with self._lock:
            try:
                if not file_path.exists():
                    self._atomic_write(file_path, {})
                    return {}

                content = file_path.read_text(encoding="utf-8").strip()

                if not content:
                    self._atomic_write(file_path, {})
                    return {}

                data = json.loads(content)

                if not isinstance(data, dict):
                    raise ValueError(
                        f"Cache file must contain a JSON object: {file_path}"
                    )

                return data

            except (json.JSONDecodeError, OSError, ValueError):
                self._backup_corrupted_file(file_path)
                self._atomic_write(file_path, {})
                return {}

    def _atomic_write(
        self,
        file_path: Path,
        data: dict[str, Any],
    ) -> None:
        """
        Write JSON data atomically.

        Data is first written to a temporary file and then moved into place,
        reducing the chance of cache corruption.
        """
        with self._lock:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = file_path.with_suffix(file_path.suffix + ".tmp")

            try:
                with temporary_path.open("w", encoding="utf-8") as file:
                    json.dump(
                        data,
                        file,
                        indent=4,
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    file.flush()
                    os.fsync(file.fileno())

                os.replace(temporary_path, file_path)

            finally:
                if temporary_path.exists():
                    try:
                        temporary_path.unlink()
                    except OSError:
                        pass

    def _backup_corrupted_file(self, file_path: Path) -> None:
        """Create a timestamped backup of a corrupted cache file."""
        if not file_path.exists():
            return

        timestamp = self._utc_now().strftime("%Y%m%dT%H%M%SZ")
        backup_path = file_path.with_name(
            f"{file_path.stem}.corrupted-{timestamp}{file_path.suffix}"
        )

        try:
            file_path.replace(backup_path)
        except OSError:
            pass

    def _update_metadata(
        self,
        source: str,
        operation: str,
        entry_count: int,
    ) -> None:
        """Update cache operation metadata."""
        metadata = self._load_json(self.metadata_file)

        metadata[source] = {
            "last_operation": operation,
            "last_updated": self._utc_now().isoformat(),
            "entry_count": entry_count,
        }

        self._atomic_write(self.metadata_file, metadata)

    def get(
        self,
        source: str,
        ioc: str,
    ) -> dict[str, Any] | None:
        """
        Retrieve a valid cached IOC result.

        Returns:
            Cached threat-intelligence data when present and unexpired.
            Otherwise, returns None.
        """
        validated_source = self._validate_source(source)
        normalized_ioc = self._normalize_ioc(ioc)
        cache_path = self._cache_path(validated_source)

        with self._lock:
            cache_data = self._load_json(cache_path)
            entry = cache_data.get(normalized_ioc)

            if not isinstance(entry, dict):
                return None

            expires_at_raw = entry.get("expires_at")

            if not isinstance(expires_at_raw, str):
                cache_data.pop(normalized_ioc, None)
                self._atomic_write(cache_path, cache_data)
                return None

            try:
                expires_at = datetime.fromisoformat(expires_at_raw)
            except ValueError:
                cache_data.pop(normalized_ioc, None)
                self._atomic_write(cache_path, cache_data)
                return None

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if self._utc_now() >= expires_at:
                cache_data.pop(normalized_ioc, None)
                self._atomic_write(cache_path, cache_data)

                self._update_metadata(
                    source=validated_source,
                    operation="expired_entry_removed",
                    entry_count=len(cache_data),
                )
                return None

            result = entry.get("data")

            return result if isinstance(result, dict) else None

    def set(
        self,
        source: str,
        ioc: str,
        data: dict[str, Any],
        ttl_hours: int | None = None,
    ) -> None:
        """
        Save or update an IOC result.

        Args:
            source:
                Threat-intelligence provider name.

            ioc:
                IP address, domain, URL, or hash.

            data:
                Provider response after normalization.

            ttl_hours:
                Optional entry-specific TTL. Uses the default TTL when omitted.
        """
        validated_source = self._validate_source(source)
        normalized_ioc = self._normalize_ioc(ioc)

        if not isinstance(data, dict):
            raise TypeError("Cached data must be a dictionary.")

        effective_ttl = (
            ttl_hours if ttl_hours is not None else self.default_ttl_hours
        )

        if effective_ttl <= 0:
            raise ValueError("ttl_hours must be greater than zero.")

        cached_at = self._utc_now()
        expires_at = cached_at + timedelta(hours=effective_ttl)
        cache_path = self._cache_path(validated_source)

        with self._lock:
            cache_data = self._load_json(cache_path)

            cache_data[normalized_ioc] = {
                "cached_at": cached_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "ttl_hours": effective_ttl,
                "data": data,
            }

            self._atomic_write(cache_path, cache_data)

            self._update_metadata(
                source=validated_source,
                operation="entry_saved",
                entry_count=len(cache_data),
            )

    def delete(self, source: str, ioc: str) -> bool:
        """
        Delete one IOC from a provider cache.

        Returns:
            True if the IOC existed and was deleted.
            False if it was not present.
        """
        validated_source = self._validate_source(source)
        normalized_ioc = self._normalize_ioc(ioc)
        cache_path = self._cache_path(validated_source)

        with self._lock:
            cache_data = self._load_json(cache_path)

            if normalized_ioc not in cache_data:
                return False

            del cache_data[normalized_ioc]
            self._atomic_write(cache_path, cache_data)

            self._update_metadata(
                source=validated_source,
                operation="entry_deleted",
                entry_count=len(cache_data),
            )

            return True

    def remove_expired(self, source: str) -> int:
        """
        Remove all expired or malformed entries from one provider cache.

        Returns:
            Number of entries removed.
        """
        validated_source = self._validate_source(source)
        cache_path = self._cache_path(validated_source)
        now = self._utc_now()

        with self._lock:
            cache_data = self._load_json(cache_path)
            valid_entries: dict[str, Any] = {}
            removed_count = 0

            for ioc, entry in cache_data.items():
                if not isinstance(entry, dict):
                    removed_count += 1
                    continue

                expires_at_raw = entry.get("expires_at")

                if not isinstance(expires_at_raw, str):
                    removed_count += 1
                    continue

                try:
                    expires_at = datetime.fromisoformat(expires_at_raw)

                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)

                except ValueError:
                    removed_count += 1
                    continue

                if now >= expires_at:
                    removed_count += 1
                    continue

                valid_entries[ioc] = entry

            if removed_count:
                self._atomic_write(cache_path, valid_entries)

            self._update_metadata(
                source=validated_source,
                operation="expired_entries_removed",
                entry_count=len(valid_entries),
            )

            return removed_count

    def clear(self, source: str) -> None:
        """Delete every entry from one provider cache."""
        validated_source = self._validate_source(source)
        cache_path = self._cache_path(validated_source)

        with self._lock:
            self._atomic_write(cache_path, {})

            self._update_metadata(
                source=validated_source,
                operation="cache_cleared",
                entry_count=0,
            )

    def contains(self, source: str, ioc: str) -> bool:
        """Return True when a valid, unexpired cache entry exists."""
        return self.get(source, ioc) is not None

    def get_stats(self) -> dict[str, Any]:
        """Return basic statistics for every provider cache."""
        stats: dict[str, Any] = {
            "cache_directory": str(self.cache_directory),
            "default_ttl_hours": self.default_ttl_hours,
            "sources": {},
        }

        for source in self.SUPPORTED_SOURCES:
            cache_data = self._load_json(self._cache_path(source))

            stats["sources"][source] = {
                "entry_count": len(cache_data),
                "file": str(self._cache_path(source)),
            }

        return stats
    
