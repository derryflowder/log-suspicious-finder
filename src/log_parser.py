import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AccessLogEntry:
    """Structured representation of a Common or Combined Log Format entry."""

    client_ip: str
    timestamp: str
    method: str
    target: str
    http_version: str
    status_code: int
    response_size: int | None
    referer: str | None = None
    user_agent: str | None = None


LOG_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>(?:\\.|[^"\\])*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>(?:\\.|[^"\\])*)"'
    r'\s+"(?P<user_agent>(?:\\.|[^"\\])*)")?\s*$'
)


def parse_access_log(line: str) -> AccessLogEntry | None:
    """Parse a Common or Combined Log Format line.

    Return None when the line does not match the supported format.
    """
    match = LOG_PATTERN.fullmatch(line.rstrip("\r\n"))

    if match is None:
        return None

    fields = match.groupdict()
    request_parts = fields["request"].split()

    if len(request_parts) != 3:
        return None

    method, target, protocol = request_parts

    if not protocol.startswith("HTTP/"):
        return None

    http_version = protocol.removeprefix("HTTP/")

    if not http_version:
        return None

    size_text = fields["size"]

    return AccessLogEntry(
        client_ip=fields["client_ip"],
        timestamp=fields["timestamp"],
        method=method,
        target=target,
        http_version=http_version,
        status_code=int(fields["status"]),
        response_size=int(size_text) if size_text != "-" else None,
        referer=fields["referer"],
        user_agent=fields["user_agent"],
    )
