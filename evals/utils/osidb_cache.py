import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from aegis_ai.toolsets.tools.osidb import CVE, CVEID, cve_retrieve

logger = logging.getLogger(__name__)

# directory where we cache CVE data retrieved from OSIDB
OSIDB_CACHE_DIR = os.getenv("OSIDB_CACHE_DIR", "evals/osidb_cache")

# global mutex for access to OSIDB_CACHE_DIR
# Note that cache hits (which is the most common case) are handle very quickly.
# So there is no need to implement any per-file locking for the OSIDB cache.
cache_lock = asyncio.Lock()

cache_misses: list[str] = []

# per-CVE in-flight tasks so concurrent misses for the same CVE fetch only once
_inflight: dict[str, asyncio.Task[CVE]] = {}


def write_cache_entry(
    cve_id: str, cve_data: CVE, *, include_affects: bool = False
) -> Path:
    """Serialize a CVE to the OSIDB cache.

    When *include_affects* is False (default), the ``affects`` field is
    excluded from the JSON to keep committed cache files small.  The input
    model is never mutated.
    """
    cache_file = Path(OSIDB_CACHE_DIR) / f"{cve_id}.json"
    exclude: set[str] = {"affects"} if not include_affects else set()
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        cve_data.model_dump_json(indent=4, exclude=exclude) + "\n", encoding="utf-8"
    )
    return cache_file


def read_cache_json(cve_id: str) -> dict[str, Any] | None:
    """Read a CVE's cached JSON as a raw dict, or None on miss/error."""
    cache_file = Path(OSIDB_CACHE_DIR) / f"{cve_id}.json"
    try:
        return json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


async def _do_fetch(cve_id: CVEID) -> CVE:
    """Fetch a single CVE from OSIDB and write the result to cache."""
    cve_data = await cve_retrieve(cve_id)

    async with cache_lock:
        path = write_cache_entry(str(cve_id), cve_data)
        logger.info('writing CVE data cache to "%s"', path)
        cache_misses.append(str(cve_id))

    return cve_data


async def osidb_cache_retrieve(cve_id: CVEID) -> CVE:
    """Return cached CVE data if available.  If not, retrieve CVE data
    from OSIDB and store them to cache for subsequent runs."""
    cache_file = Path(OSIDB_CACHE_DIR, f"{cve_id}.json")
    key = str(cve_id)

    async with cache_lock:
        try:
            # check whether the CVE data is cached already
            with open(cache_file, "r") as f:  # noqa: ASYNC230
                json_data = f.read()

            # try to load data from the existing JSON file
            cve_data = CVE.model_validate_json(json_data)
            logger.debug(f'read CVE data from "{cache_file}"')
            return cve_data
        except OSError:
            pass

        # coalesce concurrent misses for the same CVE into a single fetch
        task = _inflight.get(key)
        if task is None:
            task = asyncio.create_task(_do_fetch(cve_id))
            _inflight[key] = task

    try:
        return await task
    finally:
        _inflight.pop(key, None)


def write_misses_report() -> Path | None:
    """Write cache-miss CVE IDs to a file so the user knows what was fetched live."""
    if not cache_misses:
        return None
    report = Path(OSIDB_CACHE_DIR) / "MISSES.txt"
    report.write_text("\n".join(sorted(cache_misses)) + "\n", encoding="utf-8")
    return report


def get_miss_files() -> list[Path]:
    """Return paths to cache files written during this session (misses)."""
    return [Path(OSIDB_CACHE_DIR) / f"{cve_id}.json" for cve_id in cache_misses]
