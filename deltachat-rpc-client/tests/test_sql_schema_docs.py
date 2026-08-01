"""Test that docs/schema.sql matches the actual database schema."""

import re
import sqlite3
from pathlib import Path

DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "schema.sql"


def strip_comments(sql):
    return re.sub(r"--[^\n]*", "", sql)


def normalize(stmt):
    stmt = re.sub(r"\s+", " ", stmt).strip()
    stmt = stmt.replace("CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ")
    return re.sub(r'"(\w+)"', r"\1", stmt)


def split_table(body):
    items = []
    depth = 0
    current = ""
    for char in body:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            items.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        items.append(current.strip())
    return items


def parse_schema(sql):
    objects = {}
    for raw_stmt in strip_comments(sql).split(";"):
        stmt = normalize(raw_stmt)
        if not stmt:
            continue
        match = re.match(r"CREATE TABLE (\w+) ?\((.*)\)( STRICT)?$", stmt)
        if match:
            name, body, strict = match.groups()
            objects[f"table {name}"] = {
                "items": sorted(split_table(body)),
                "strict": bool(strict),
            }
            continue
        match = re.match(r"CREATE (?:UNIQUE )?INDEX (\w+)", stmt)
        if match:
            objects[f"index {match.group(1)}"] = {"sql": stmt}
            continue
        objects[stmt[:60]] = {"sql": stmt}
    return objects


def format_diff(documented, real):
    if "items" in documented and "items" in real:
        lines = []
        # disregards order
        for item in sorted(set(documented["items"]) - set(real["items"])):
            lines.append(f"    documented but not in the database: {item}")
        for item in sorted(set(real["items"]) - set(documented["items"])):
            lines.append(f"    in the database but not documented: {item}")
        if documented["strict"] != real["strict"]:
            lines.append(f"    STRICT: documented={documented['strict']} actual={real['strict']}")
        return "\n".join(lines)
    return f"    documented: {documented}\n    actual:     {real}"


def read_database_schema(dbfile):
    with sqlite3.connect(f"file:{dbfile}?mode=ro", uri=True) as conn:
        rows = conn.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'",
        ).fetchall()
    return ";\n".join(row[0] for row in rows)


def test_documented_schema_matches_database(acfactory):
    account = acfactory.get_unconfigured_account()
    real = parse_schema(read_database_schema(account.get_info()["database_dir"]))
    documented = parse_schema(DOC_PATH.read_text())

    problems = []
    for name in sorted(real.keys() - documented.keys()):
        problems.append(f"{name} exists in the database but is not documented")
    for name in sorted(documented.keys() - real.keys()):
        problems.append(f"{name} is documented but does not exist in the database")
    for name in sorted(documented.keys() & real.keys()):
        if documented[name] != real[name]:
            problems.append(f"{name} differs:\n{format_diff(documented[name], real[name])}")
    assert not problems, "documented schema deviates from the database:\n" + "\n".join(problems)
