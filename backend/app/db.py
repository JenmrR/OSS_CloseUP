import os

import psycopg


def connect(timeout: int = 3) -> psycopg.Connection:
    """URL 문자열 대신 항목별로 넘겨서, 비밀번호에 특수문자가 있어도 깨지지 않게 함."""
    return psycopg.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", "5432")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        dbname=os.environ["DB_NAME"],
        connect_timeout=timeout,
    )
