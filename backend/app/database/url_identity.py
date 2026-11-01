"""Bounded URL index keys without shortening the stored URL or requiring pgcrypto."""

from sqlalchemy import LargeBinary
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement


class url_digest(FunctionElement):
    type = LargeBinary()
    inherit_cache = True
    name = "url_digest"


@compiles(url_digest, "postgresql")
def postgres_url_digest(element, compiler, **kwargs):
    value = compiler.process(list(element.clauses)[0], **kwargs)
    # convert_to/textsend are STABLE, so cannot appear in an index. Escape
    # backslashes before the immutable text -> bytea cast to preserve them
    # literally, including sequences such as \xAB and \123. All functions
    # here are PostgreSQL core IMMUTABLE functions; no extension is needed.
    return f"sha256(replace({value}, chr(92), chr(92) || chr(92))::bytea)"


@compiles(url_digest, "sqlite")
def sqlite_url_digest(element, compiler, **kwargs):
    # SQLite unit tests register the deterministic SHA-256 function locally.
    value = compiler.process(list(element.clauses)[0], **kwargs)
    return f"sha256(CAST({value} AS BLOB))"
