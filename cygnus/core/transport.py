"""Small capture-first protocol clients used by fingerprinting and checks."""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler,Request,build_opener

SENSITIVE_HEADERS={"authorization","proxy-authorization","cookie","set-cookie","x-api-key"}

class _NoRedirect(HTTPRedirectHandler):
    """Do not silently leave the operator-authorized origin."""
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

@dataclass(slots=True)
class HTTPExchange:
    url: str; method: str; status: int; headers: dict[str,str]; body: bytes
    @property
    def text(self)->str:return self.body.decode("utf-8","replace")
    def capture(self)->str:
        headers="\n".join(f"{k}: {'[REDACTED]' if k.lower() in SENSITIVE_HEADERS else v}" for k,v in sorted(self.headers.items()))
        return f"HTTP {self.status}\n{headers}\n\n{self.text[:2048]}"[:4096]

def _http_sync(url:str,timeout:float,headers:dict[str,str]|None=None,method:str="GET",body:bytes|None=None)->HTTPExchange:
    request=Request(url,data=body,headers={"User-Agent":"CYGNUS/3.3 passive-verifier",**(headers or {})},method=method)
    try:response=build_opener(_NoRedirect).open(request,timeout=timeout)
    except HTTPError as error:response=error
    with response:
        return HTTPExchange(response.geturl(),method,response.status,{k.lower():v for k,v in response.headers.items()},response.read(65536))

async def http_request(url:str,timeout:float=3.0,headers:dict[str,str]|None=None,method:str="GET",body:bytes|None=None)->HTTPExchange:
    return await asyncio.to_thread(_http_sync,url,timeout,headers,method,body)

def _tcp_sync(host:str,port:int,timeout:float,send:bytes|None=None)->bytes:
    with socket.create_connection((host,port),timeout=timeout) as connection:
        connection.settimeout(timeout)
        if send:connection.sendall(send)
        try:return connection.recv(4096)
        except socket.timeout:return b""

async def tcp_capture(host:str,port:int,timeout:float=3.0,send:bytes|None=None)->bytes:
    return await asyncio.to_thread(_tcp_sync,host,port,timeout,send)
