from __future__ import annotations

import os
import sys
import time

from sqlalchemy import create_engine, text

url = os.environ["DATABASE_URL"]
engine = create_engine(url, pool_pre_ping=True)
for attempt in range(30):
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        print("database is ready")
        break
    except Exception as exc:
        if attempt == 29:
            print(f"database did not become ready: {type(exc).__name__}", file=sys.stderr)
            raise SystemExit(1) from None
        time.sleep(1)
