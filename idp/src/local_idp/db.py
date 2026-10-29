"""The identity provider's own Postgres connection pool. One pool per process; a request borrows one connection and gives
it back, and its work is committed when the request ends normally and rolled back if it raises."""
from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

PgConnection = psycopg.Connection[dict[str, Any]]


def open_pool(dsn: str, *, min_size: int = 2, max_size: int = 10) -> ConnectionPool:
    pool = ConnectionPool(
        dsn,
        min_size=min_size,
        max_size=max_size,
        kwargs={"row_factory": dict_row},
        check=ConnectionPool.check_connection,
        open=False,
    )
    pool.open(wait=True, timeout=10)
    return pool
