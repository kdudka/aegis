import fcntl
import json
import os
from datetime import datetime
from typing import Any, Never, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis_ai.data_models import CVEID
from aegis_ai.osidb_bot.util import logger


class BotPosition(BaseModel):
    """Position in the CVE stream — hashable, used as dict key in Bot.pending."""

    # make the position hashable so that it can be used as key for a dict
    model_config = ConfigDict(frozen=True)

    # the last processed CVE
    last_cve: CVEID | None = None

    # update timestamp of the last processed CVE
    updated_dt: datetime | None = None


class BotState(BotPosition):
    """Full bot state for persistence — extends BotPosition with mutable fields."""

    model_config = ConfigDict(frozen=False)

    # CVE IDs that failed processing, mapped to remaining retry attempts
    retry_list: dict[str, int] = Field(default_factory=dict)


class StateFileHandler:
    # state file name (path)
    state_file: str | None

    # state file descriptor (OS level)
    state_fd: int

    def __init__(self, state_file: str | None):
        self.state_file = state_file
        self.state_fd = -1

    def _fail(self, e: Exception, msg: str) -> Never:
        logger.debug(f"{msg}: {e!s}")
        raise RuntimeError(f"{msg}: {self.state_file} ({e.__class__.__name__})")

    def _sf_prefix(self) -> str:
        """state file prefix for logging of state read/writes"""
        assert 0 <= self.state_fd
        fd_link = f"/proc/{os.getpid()}/fd/{self.state_fd}"
        try:
            target = os.readlink(fd_link)
            return f"{fd_link} -> {target}"
        except OSError:
            return fd_link

    def __enter__(self) -> Self:
        if not self.state_file:
            # do nothing
            return self

        # open the state file for reading and writing
        try:
            self.state_fd = os.open(self.state_file, os.O_RDWR | os.O_CREAT)
        except OSError as e:
            self._fail(e, "failed to open or create state file")

        # lock the state file
        try:
            fcntl.flock(self.state_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            self._fail(e, "failed to lock state file")

        logger.debug(f"successfully locked state file: {self.state_file}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self.state_file:
            # do nothing
            return

        # unlock and close the state file
        fcntl.flock(self.state_fd, fcntl.LOCK_UN)
        os.close(self.state_fd)
        self.state_fd = -1

    def read_state(self) -> BotState | None:
        """Read JSON-encoded BotState from state_fd. Returns None if file is empty."""
        if not self.state_file:
            # do nothing
            return None

        # read file contents
        assert 0 <= self.state_fd
        with os.fdopen(self.state_fd, "r", closefd=False) as f:
            f.seek(0)
            data = f.read()
        if not data:
            return None

        # parse JSON
        try:
            state = BotState.model_validate_json(data)
            logger.debug(f"{self._sf_prefix()}: read {state.model_dump_json()}")
            return state
        except (ValidationError, json.JSONDecodeError):
            logger.warning(
                "Failed to load bot state from %r; treating as no state",
                self.state_file,
            )
            return None

    def write_state(self, state: BotState) -> None:
        """Write JSON-encoded BotState to state_fd."""
        if not self.state_file:
            # do nothing
            return

        assert 0 <= self.state_fd

        # serialize JSON (exclude_defaults omits empty retry_list)
        payload = state.model_dump_json(exclude_defaults=True) + "\n"
        raw = payload.encode("utf-8")

        # write the data at the beginning of the state file
        os.lseek(self.state_fd, 0, os.SEEK_SET)
        size: int = os.write(self.state_fd, raw)
        os.ftruncate(self.state_fd, size)

        # log a successfully written state file
        logger.debug(f"{self._sf_prefix()}: written {state.model_dump_json()}")


class _ObservableDict(dict):
    """Dict subclass that calls a callback when its contents change."""

    _on_change: Any

    def __init__(self, *args: Any, _on_change: Any = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._on_change = _on_change

    def __setitem__(self, key: object, value: object) -> None:
        old = self.get(key)
        super().__setitem__(key, value)
        if old is None:
            logger.info("retry_list: added %s (%s attempts)", key, value)
        elif old != value:
            logger.info("retry_list: updated %s (%s → %s attempts)", key, old, value)
        if self._on_change:
            self._on_change()

    def __delitem__(self, key: object) -> None:
        super().__delitem__(key)
        logger.info("retry_list: removed %s (%d entries remain)", key, len(self))
        if self._on_change:
            self._on_change()

    def pop(self, key: object, *args: Any) -> Any:
        if key not in self:
            return super().pop(key, *args)
        result = super().pop(key, *args)
        logger.info("retry_list: removed %s (%d entries remain)", key, len(self))
        if self._on_change:
            self._on_change()
        return result


class StateProxy:
    """In-memory cache for BotState that auto-writes to disk on update."""

    _sfh: "StateFileHandler"
    _state: BotState
    _retry_list: _ObservableDict
    read_only: bool

    def __init__(self, sfh: "StateFileHandler", read_only: bool = False):
        self._sfh = sfh
        self._state = sfh.read_state() or BotState()
        self._retry_list = _ObservableDict(
            self._state.retry_list, _on_change=self._flush
        )
        self.read_only = read_only
        self._log_position("read")

    @property
    def state(self) -> BotState:
        return self._state

    @property
    def retry_list(self) -> dict[str, int]:
        return self._retry_list

    def _log_position(self, action: str) -> None:
        logger.info(
            "state %s: last_cve=%s, updated_dt=%s, len(retry_list)=%d",
            action,
            self._state.last_cve,
            self._state.updated_dt,
            len(self._retry_list),
        )

    def decrement_retry(self, cve: str) -> None:
        """Decrement the retry count for a CVE, removing it when it reaches zero."""
        if cve not in self._retry_list:
            return

        remains = self._retry_list[cve] - 1
        if remains <= 0:
            self._retry_list.pop(cve)
        else:
            self._retry_list[cve] = remains

    def _flush(self) -> None:
        """Rebuild BotState from current retry_list and write to disk."""
        self._state = BotState(
            last_cve=self._state.last_cve,
            updated_dt=self._state.updated_dt,
            retry_list=self._retry_list,
        )
        if not self.read_only:
            self._sfh.write_state(self._state)

    @state.setter
    def state(self, value: BotPosition) -> None:
        self._state = BotState(
            last_cve=value.last_cve,
            updated_dt=value.updated_dt,
            retry_list=self._retry_list,
        )
        if not self.read_only:
            self._sfh.write_state(self._state)
        self._log_position("written")
