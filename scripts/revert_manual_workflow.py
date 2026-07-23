#!/usr/bin/env python3
"""Revert flaws switched to the MANUAL workflow by mistake (AEGIS-475).

Removes the ``manual-triage`` alias label from eligible flaws so that the
OSIDB workflow reverts from MANUAL back to DEFAULT, allowing the Aegis bot
to pick them up again.
"""

import logging
import textwrap

from datetime import datetime
from typing import Any, Optional, Sequence, cast

import click
import osidb_bindings
import requests

from aegis_ai import get_settings
from aegis_ai.osidb_bot.bot import ELIGIBLE_FLAWS, FLAW_FIELDS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

LABEL_NAME = "manual-triage"


ALLOWED_STATES = tuple(
    dict.fromkeys(
        cast(dict[str, str], c)["state"] for c in ELIGIBLE_FLAWS["classification"]
    )
)


def validate_flaw(flaw_data: dict[str, Any]) -> None:
    """Check ELIGIBLE_FLAWS criteria except ``classification.workflow``."""
    for field, allowed in ELIGIBLE_FLAWS.items():
        if field == "classification":
            state = flaw_data[field].get("state", "")
            if state not in ALLOWED_STATES:
                raise RuntimeError(
                    f'skipped because classification.state="{state}",'
                    f" allowed={ALLOWED_STATES}"
                )
            continue

        value = flaw_data[field]
        if value in allowed:
            continue

        short_value = textwrap.shorten(str(value), width=64, placeholder=" [...]")
        raise RuntimeError(
            f'skipped because {field}="{short_value}", allowed={allowed}'
        )


def search_manual_flaws(
    session: Any,
    created_after: Optional[datetime],
    created_before: Optional[datetime],
) -> Sequence[str]:
    """Search OSIDB for MANUAL-workflow flaws in the given date range."""
    kwargs: dict[str, Any] = {
        "include_fields": ["cve_id", "classification"],
        "cve_id__isempty": False,
        "order": ["created_dt"],
        "source_in": list(ELIGIBLE_FLAWS["source"]),
        "workflow_state_in": list(ALLOWED_STATES),
        "limit": 1000,
    }

    # emptiness predicates for indexed fields (same logic as FlawFinder.search)
    for field, allowed in ELIGIBLE_FLAWS.items():
        if field in ("affects",):
            continue
        if len(allowed) == 1 and not allowed[0]:
            kwargs[f"{field}_isempty"] = True

    if created_after is not None:
        kwargs["created_dt_gte"] = created_after
    if created_before is not None:
        kwargs["created_dt_lte"] = created_before

    logger.info("searching for MANUAL-workflow flaws...")
    flaw_iterator = session.flaws.retrieve_list_iterator(**kwargs)
    cve_ids = [
        flaw.cve_id
        for flaw in flaw_iterator
        if flaw.classification.to_dict().get("workflow") == "MANUAL"
    ]

    logger.info("found %d MANUAL-workflow flaws", len(cve_ids))
    return cve_ids


def remove_manual_triage_label(
    session: Any,
    flaw_uuid: str,
    cve_id: str,
    dry_run: bool,
) -> bool:
    """Remove the manual-triage label from a flaw. Return True on success."""
    labels_api = session.flaws.labels
    label_list = labels_api.retrieve_list(flaw_id=flaw_uuid)

    target = None
    for label_obj in label_list.results:
        label_dict = label_obj.to_dict()
        if label_dict.get("label") == LABEL_NAME:
            target = label_dict
            break

    if target is None:
        logger.info("%s: no '%s' label found, skipping", cve_id, LABEL_NAME)
        return False

    label_id = target["uuid"]
    if dry_run:
        logger.info(
            "[DRY RUN] %s: would remove '%s' label (id=%s)",
            cve_id,
            LABEL_NAME,
            label_id,
        )
        return True

    try:
        labels_api.delete(flaw_uuid, label_id)
    except requests.exceptions.JSONDecodeError:
        pass  # 204 No Content — the delete succeeded but the bindings choke on the empty body
    logger.info("%s: removed '%s' label (id=%s)", cve_id, LABEL_NAME, label_id)
    return True


def process_cve(
    session: Any,
    cve_id: str,
    dry_run: bool,
) -> str:
    """Process a single CVE. Return 'reverted', 'skipped', or 'failed'."""
    try:
        flaw = session.flaws.retrieve(
            id=cve_id,
            include_fields=",".join(FLAW_FIELDS),
        )
        flaw_data = flaw.to_dict()
    except Exception as e:
        logger.warning("%s: failed to retrieve flaw (%s)", cve_id, e)
        return "failed"

    workflow = flaw_data.get("classification", {}).get("workflow", "")
    if workflow != "MANUAL":
        logger.warning("%s: skipped because workflow=%r, expected MANUAL", cve_id, workflow)
        return "skipped"

    try:
        validate_flaw(flaw_data)
    except RuntimeError as e:
        logger.warning("%s: %s", cve_id, e)
        return "skipped"

    try:
        if remove_manual_triage_label(session, flaw_data["uuid"], cve_id, dry_run):
            return "reverted"
        return "skipped"
    except Exception as e:
        logger.warning("%s: failed to remove label (%s)", cve_id, e)
        return "failed"


@click.command()
@click.option("--dry-run", is_flag=True, help="Log actions without making changes.")
@click.option(
    "--cve-ids",
    multiple=True,
    help="Explicit CVE IDs to revert (repeatable).",
)
@click.option(
    "--created-after",
    type=click.DateTime(),
    default=None,
    help="Lower bound on created_dt (ISO 8601).",
)
@click.option(
    "--created-before",
    type=click.DateTime(),
    default=None,
    help="Upper bound on created_dt (ISO 8601).",
)
def main(
    dry_run: bool,
    cve_ids: tuple[str, ...],
    created_after: Optional[datetime],
    created_before: Optional[datetime],
) -> None:
    """Revert flaws from MANUAL to DEFAULT workflow by removing the manual-triage label."""
    if not cve_ids and created_after is None:
        raise click.UsageError(
            "Provide at least --cve-ids or --created-after to select flaws."
        )

    osidb_server = get_settings().osidb_server_url
    logger.info("connecting to OSIDB at %s", osidb_server)
    try:
        session = osidb_bindings.new_session(osidb_server_uri=osidb_server)
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        raise click.ClickException(f"failed to establish OSIDB session: {e}")

    if cve_ids:
        targets = list(cve_ids)
    else:
        targets = list(search_manual_flaws(session, created_after, created_before))

    if not targets:
        logger.info("no flaws to process")
        return

    if dry_run:
        logger.info("DRY RUN MODE — no changes will be made")

    reverted = 0
    skipped = 0
    failed = 0

    for i, cve_id in enumerate(targets, 1):
        logger.info("[%d/%d] processing %s", i, len(targets), cve_id)
        result = process_cve(session, cve_id, dry_run)
        if result == "reverted":
            reverted += 1
        elif result == "skipped":
            skipped += 1
        else:
            failed += 1

    logger.info(
        "summary: %d reverted, %d skipped, %d failed out of %d total",
        reverted,
        skipped,
        failed,
        len(targets),
    )


if __name__ == "__main__":
    main()
