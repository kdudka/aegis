import logging
from datetime import date

from pydantic import BaseModel
from pydantic_ai import RunContext, Tool

logger = logging.getLogger(__name__)


class BaseToolInput(BaseModel):
    pass


class BaseToolOutput(BaseModel):
    status: str = "success"
    error_message: str | None = None


@Tool
async def date_tool(ctx: RunContext) -> str:
    """Returns the current date."""
    logger.info("calling date_lookup")
    today = date.today()  # noqa: DTZ011
    return str(today)


default_tool_http_headers = {
    "User-Agent": "aegis - https://github.com/RedHatProductSecurity/aegis-ai",
    # Signal to the server that the client supports gzip, deflate, and brotli compression.
    "Accept-Encoding": "gzip, deflate, br",
}
