"""Small capture-first protocol clients used by fingerprinting and checks."""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(slots=True)
class HTTPExchange:
    url: str
    method: str
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def capture(self) -> str:
        headers = "\n".join(f"{k}: {v}" for k, v in sorted(self.headers.items()))
        return f"HTTP {self.status}\n{headers}\n\n{self.text[:2048]}"[:4096]


def _http_sync(url: str, timeout: float, headers: dict[str, str] | None = None, method: str = "GET") -> HTTPExchange:
    request = Request(url, headers={"User-Agent": "CYGNUS/3.0 passive-verifier", **(headers or {})}, method=method)
    try:
        response = urlopen(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        return HTTPExchange(
            response.geturl(), method, response.status,
            {key.lower(): value for key, value in response.headers.items()},
            response.read(65536),
        )


async def http_request(url: str, timeout: float = 3.0, headers: dict[str, str] | None = None, method: str = "GET") -> HTTPExchange:
    return await asyncio.to_thread(_http_sync, url, timeout, headers, method)


def _tcp_sync(host: str, port: int, timeout: float, send: bytes | None = None) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        if send:
            connection.sendall(send)
        try:
            return connection.recv(4096)
        except socket.timeout:
            return b""


async def tcp_capture(host: str, port: int, timeout: float = 3.0, send: bytes | None = None) -> bytes:
    return await asyncio.to_thread(_tcp_sync, host, port, timeout, send)
