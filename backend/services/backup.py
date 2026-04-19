import glob
import logging
import os
import re
import subprocess
from datetime import datetime

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from services.db import get_database_config

load_dotenv()

logger = logging.getLogger(__name__)

BACKUP_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "backups"))
MAX_BACKUPS = 7


def _safe_filename(filename: str) -> str:
    """Validate and sanitize a backup filename to prevent path traversal."""
    name = os.path.basename(filename)
    if not re.fullmatch(r"[A-Za-z0-9_\-\.]+", name):
        raise ValueError(f"Invalid backup filename: {filename!r}")
    if not name.endswith(".sql"):
        raise ValueError(f"Backup filename must end with .sql: {filename!r}")
    return name


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def _format_date(ts: float) -> str:
    dt = datetime.fromtimestamp(ts)
    day = str(dt.day)
    hour = dt.hour % 12 or 12
    minute = dt.strftime("%M")
    ampm = "AM" if dt.hour < 12 else "PM"
    return f"{dt.strftime('%b')} {day}, {dt.strftime('%Y')} at {hour}:{minute} {ampm}"


def cleanup_old_backups():
    files = glob.glob(os.path.join(BACKUP_DIR, "*.sql"))
    files.sort(key=os.path.getctime, reverse=True)
    for old_file in files[MAX_BACKUPS:]:
        try:
            os.remove(old_file)
            logger.info(f"Deleted old backup: {old_file}")
        except OSError as e:
            logger.error(f"Failed to delete old backup {old_file}: {e}")


def list_backups() -> list:
    files = glob.glob(os.path.join(BACKUP_DIR, "*.sql"))
    files.sort(key=os.path.getctime, reverse=True)
    result = []
    for f in files:
        stat = os.stat(f)
        result.append({
            "filename": os.path.basename(f),
            "size_human": _format_size(stat.st_size),
            "created_at_formatted": _format_date(stat.st_ctime),
        })
    return result


def _topological_sort(tables: list, fk_deps: dict) -> list:
    visited = set()
    order = []

    def visit(t):
        if t in visited:
            return
        visited.add(t)
        for dep in fk_deps.get(t, []):
            if dep in tables:
                visit(dep)
        order.append(t)

    for t in tables:
        visit(t)
    return order


def _python_dump(filepath: str):
    """Generate a SQL dump using psycopg2 when pg_dump CLI is unavailable."""
    db_config = get_database_config()
    meta_conn = psycopg2.connect(cursor_factory=psycopg2.extras.RealDictCursor, **db_config)
    data_conn = psycopg2.connect(**db_config)
    meta_cur = meta_conn.cursor()
    data_cur = data_conn.cursor()

    try:
        meta_cur.execute("""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name
        """)
        tables = [row["table_name"] for row in meta_cur.fetchall()]

        meta_cur.execute("""
            SELECT
                tc.table_name AS source_table,
                ccu.table_name AS ref_table
            FROM information_schema.table_constraints tc
            JOIN information_schema.referential_constraints rc
                ON tc.constraint_name = rc.constraint_name
                AND tc.constraint_schema = rc.constraint_schema
            JOIN information_schema.constraint_column_usage ccu
                ON rc.unique_constraint_name = ccu.constraint_name
                AND rc.unique_constraint_schema = ccu.constraint_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
              AND tc.table_schema = 'public'
        """)
        fk_deps = {}
        for row in meta_cur.fetchall():
            src, ref = row["source_table"], row["ref_table"]
            if src != ref:
                fk_deps.setdefault(src, []).append(ref)

        ordered_tables = _topological_sort(tables, fk_deps)

        lines = [
            "-- Lab Inventory Backup (Python fallback)",
            f"-- Created: {datetime.now().isoformat()}",
            "",
            "SET session_replication_role = replica;",
            "",
        ]

        for table in reversed(ordered_tables):
            lines.append(f"DROP TABLE IF EXISTS {table} CASCADE;")
        lines.append("")

        for table in ordered_tables:
            meta_cur.execute("""
                SELECT
                    column_name, data_type, character_maximum_length,
                    numeric_precision, numeric_scale, is_nullable, column_default, udt_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                ORDER BY ordinal_position
            """, (table,))
            columns = meta_cur.fetchall()

            col_defs = []
            for col in columns:
                col_name = col["column_name"]
                data_type = col["data_type"]
                default = col["column_default"]
                nullable = col["is_nullable"] == "YES"

                if data_type == "character varying":
                    ml = col["character_maximum_length"]
                    type_str = f"VARCHAR({ml})" if ml else "TEXT"
                elif data_type == "character":
                    ml = col["character_maximum_length"]
                    type_str = f"CHAR({ml})" if ml else "CHAR"
                elif data_type in ("integer", "bigint", "smallint", "boolean", "text",
                                   "real", "double precision", "date", "uuid"):
                    type_str = data_type.upper()
                elif data_type == "numeric":
                    p, s = col["numeric_precision"], col["numeric_scale"]
                    type_str = f"NUMERIC({p},{s})" if p else "NUMERIC"
                elif "timestamp" in data_type:
                    type_str = "TIMESTAMP"
                elif data_type == "USER-DEFINED":
                    type_str = col["udt_name"]
                else:
                    type_str = data_type.upper()

                if default and default.startswith("nextval("):
                    type_str = "BIGSERIAL" if data_type == "bigint" else "SERIAL"
                    default = None

                col_def = f"    {col_name} {type_str}"
                if default:
                    col_def += f" DEFAULT {default}"
                if not nullable:
                    col_def += " NOT NULL"
                col_defs.append(col_def)

            meta_cur.execute("""
                SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  AND tc.table_schema = 'public' AND tc.table_name = %s
                ORDER BY kcu.ordinal_position
            """, (table,))
            pk_cols = [r["column_name"] for r in meta_cur.fetchall()]
            if pk_cols:
                col_defs.append(f"    PRIMARY KEY ({', '.join(pk_cols)})")

            meta_cur.execute("""
                SELECT tc.constraint_name, kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'UNIQUE'
                  AND tc.table_schema = 'public' AND tc.table_name = %s
                ORDER BY tc.constraint_name, kcu.ordinal_position
            """, (table,))
            unique_map = {}
            for row in meta_cur.fetchall():
                unique_map.setdefault(row["constraint_name"], []).append(row["column_name"])
            for cols in unique_map.values():
                col_defs.append(f"    UNIQUE ({', '.join(cols)})")

            meta_cur.execute("""
                SELECT
                    kcu.column_name,
                    ccu.table_name AS foreign_table,
                    ccu.column_name AS foreign_column,
                    tc.constraint_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                JOIN information_schema.referential_constraints rc
                    ON tc.constraint_name = rc.constraint_name
                    AND tc.constraint_schema = rc.constraint_schema
                JOIN information_schema.constraint_column_usage ccu
                    ON rc.unique_constraint_name = ccu.constraint_name
                    AND rc.unique_constraint_schema = ccu.constraint_schema
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  AND tc.table_schema = 'public' AND tc.table_name = %s
                ORDER BY tc.constraint_name, kcu.ordinal_position
            """, (table,))
            fk_map = {}
            for row in meta_cur.fetchall():
                key = (row["constraint_name"], row["foreign_table"])
                fk_map.setdefault(key, {"src": [], "ref": []})
                fk_map[key]["src"].append(row["column_name"])
                fk_map[key]["ref"].append(row["foreign_column"])
            for (_, foreign_table), fk_data in fk_map.items():
                src_cols = ", ".join(fk_data["src"])
                ref_cols = ", ".join(fk_data["ref"])
                col_defs.append(f"    FOREIGN KEY ({src_cols}) REFERENCES {foreign_table} ({ref_cols})")

            lines.append(f"CREATE TABLE IF NOT EXISTS {table} (")
            lines.append(",\n".join(col_defs))
            lines.append(");")
            lines.append("")

            data_cur.execute(f"SELECT * FROM {table}")
            rows = data_cur.fetchall()
            if rows:
                col_names = [desc[0] for desc in data_cur.description]
                col_list = ", ".join(col_names)
                placeholders = ", ".join(["%s"] * len(col_names))
                for row in rows:
                    values = data_cur.mogrify(f"({placeholders})", row).decode("utf-8")
                    lines.append(f"INSERT INTO {table} ({col_list}) VALUES {values};")
            lines.append("")

        lines.append("SET session_replication_role = DEFAULT;")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    finally:
        meta_conn.close()
        data_conn.close()


def create_backup() -> dict:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"backup_{timestamp}.sql"
    filepath = os.path.join(BACKUP_DIR, filename)

    params = get_database_config()
    host = params.get("host", "localhost")
    port = params.get("port", "5432")
    dbname = params.get("dbname", "")
    user = params.get("user", "")
    password = params.get("password", "")

    used_pgdump = False
    try:
        env = os.environ.copy()
        env["PGPASSWORD"] = password
        result = subprocess.run(
            [
                "pg_dump",
                "--inserts",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-acl",
                "-h", host,
                "-p", port,
                "-U", user,
                "-d", dbname,
                "-f", filepath,
            ],
            capture_output=True,
            env=env,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode().strip())
        used_pgdump = True
        logger.info(f"Backup created via pg_dump: {filepath}")
    except FileNotFoundError:
        logger.warning("pg_dump not found, falling back to Python-based backup")
        _python_dump(filepath)
        logger.info(f"Backup created via Python fallback: {filepath}")
    except Exception as e:
        logger.warning(f"pg_dump failed ({e}), falling back to Python-based backup")
        if os.path.exists(filepath):
            os.remove(filepath)
        _python_dump(filepath)
        logger.info(f"Backup created via Python fallback: {filepath}")

    size = os.path.getsize(filepath)
    cleanup_old_backups()

    return {
        "filepath": filepath,
        "filename": filename,
        "size_human": _format_size(size),
        "created_at": datetime.now().isoformat(),
        "method": "pg_dump" if used_pgdump else "python",
    }


def restore_backup(filename: str) -> None:
    safe_name = _safe_filename(filename)
    filepath = os.path.join(BACKUP_DIR, safe_name)
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Backup not found: {safe_name}")

    with open(filepath, "r", encoding="utf-8") as f:
        sql_content = f.read()

    conn = psycopg2.connect(**get_database_config())
    conn.autocommit = True
    cur = conn.cursor()
    try:
        for raw_stmt in sql_content.split(";"):
            stmt = raw_stmt.strip()
            if not stmt:
                continue
            non_comment = [
                line for line in stmt.splitlines()
                if line.strip() and not line.strip().startswith("--")
            ]
            if not non_comment:
                continue
            cur.execute(stmt)
        logger.info(f"Restored backup: {filepath}")
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        raise
    finally:
        conn.close()


def delete_backup(filename: str) -> None:
    safe_name = _safe_filename(filename)
    filepath = os.path.join(BACKUP_DIR, safe_name)
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Backup not found: {safe_name}")
    os.remove(filepath)
    logger.info(f"Deleted backup: {filepath}")
