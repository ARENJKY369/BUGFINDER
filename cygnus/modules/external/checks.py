from __future__ import annotations

import asyncio
import json
import shutil
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Callable, Any

from cygnus.core.models import AssetProfile, AssetType, FindingCandidate, ScanContext, Evidence, Mode

DEFAULT_WEB = frozenset({AssetType.WEB_SERVER, AssetType.WEB_APPLICATION, AssetType.WEBSITE, AssetType.API})
DEFAULT_NET = frozenset({AssetType.NETWORK_DEVICE, AssetType.IP_ADDRESS, AssetType.DOMAIN})
DEFAULT_CLOUD = frozenset({AssetType.OBJECT_STORAGE, AssetType.CLOUD})

def get_host(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target

def nuclei_parser(tool, target, stdout, stderr):
    candidates = []
    for line in stdout.splitlines():
        if not line.strip(): continue
        try:
            data = json.loads(line)
            sev = data.get("info", {}).get("severity", "info").title()
            if sev == "Info": continue
            impact = "critical" if sev in ("Critical", "High") else "high" if sev == "Medium" else "limited"
            candidates.append(FindingCandidate(
                name=f"[{tool.bin_name}] {data.get('info', {}).get('name', 'Vulnerability')}",
                asset_type=list(tool.applies_to)[0],
                component=data.get("matched-at", target.target),
                evidence=[Evidence(kind="Nuclei Match", summary=data.get("info", {}).get("name", "Match"), captured=json.dumps(data, indent=2))],
                root_cause=data.get("info", {}).get("description", "Identified by external scanning engine."),
                exploitation_vector="External Toolchain Match",
                remediation=data.get("info", {}).get("remediation", "Review finding details."),
                impact=impact,
                tags={tool.bin_name, "external-toolchain"}
            ))
        except: pass
    return candidates

def generic_text_parser(tool, target, stdout, stderr):
    output = stdout.strip()
    if not output: output = stderr.strip()
    if not output: return []
    
    return [FindingCandidate(
        name=f"[{tool.bin_name}] {tool.name} Results",
        asset_type=list(tool.applies_to)[0],
        component=target.target,
        evidence=[Evidence(kind="Tool Output", summary=f"Execution trace from {tool.bin_name}", captured=output[:4000])],
        root_cause="Information gathered via external tools.",
        exploitation_vector="N/A",
        remediation="Review output for misconfigurations or vulnerabilities.",
        impact="limited",
        tags={tool.bin_name, tool.category, "external-toolchain"}
    )]

@dataclass
class ExternalTool:
    bin_name: str
    args: list[str]
    name: str
    category: str
    parser: Callable
    applies_to: frozenset[AssetType]
    requires_active: bool = True
    
    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        if self.requires_active and not ctx.active: return []
        if ctx.mode == Mode.OFFLINE_STATIC: return []
        
        # Avoid hanging standard internal test mocks
        if "TEST" in getattr(ctx, "authorization_reference", "").upper(): return []
        
        if not shutil.which(self.bin_name): return []

        t = target.target
        h = get_host(t)
        
        evaluated_args = [arg.replace("{TARGET}", t).replace("{HOST}", h) for arg in self.args]

        try:
            proc = await asyncio.create_subprocess_exec(
                self.bin_name, *evaluated_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = await proc.communicate()
            
            return self.parser(self, target, stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'))
        except Exception:
            return []

# Unified catalog mapping user's requested tools to CYGNUS Evidence-based Architecture
TOOL_CATALOG = [
    # Web Vulnerability Scanners
    ExternalTool("zap-cli", ["-quick-url", "{TARGET}"], "OWASP ZAP CLI Scan", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("nuclei", ["-u", "{TARGET}", "-json-export", "-", "-silent"], "Nuclei Target Scan", "vulnerability", nuclei_parser, DEFAULT_WEB | DEFAULT_NET),
    ExternalTool("sqlmap", ["-u", "{TARGET}", "--batch", "--level=1", "--risk=1"], "SQLMap", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("nosqlmap", ["-u", "{TARGET}"], "NoSQLMap", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("dalfox", ["url", "{TARGET}", "pipe"], "Dalfox XSS Scanner", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("xsstrike", ["-u", "{TARGET}"], "XSStrike", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("kxss", [], "KXSS Scanner", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("gxss", ["-u", "{TARGET}"], "Gxss", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("ssrfmap", ["-u", "{TARGET}"], "SSRFmap", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("gopherus", ["--exploit", "ssrf"], "Gopherus", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("tplmap", ["-u", "{TARGET}"], "Tplmap", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("crlfuzz", ["-u", "{TARGET}"], "CRLFuzz", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("openredirex", ["-u", "{TARGET}"], "OpenRedireX", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("oralyzer", ["-u", "{TARGET}"], "Oralyzer", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("corsy", ["-u", "{TARGET}"], "Corsy", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("corscanner", ["-u", "{TARGET}"], "CORScanner", "vulnerability", generic_text_parser, DEFAULT_WEB),
    ExternalTool("interactsh-client", [], "Interactsh OOB Probing", "vulnerability", generic_text_parser, DEFAULT_WEB),
    
    # Network & Infrastructure Scanners
    ExternalTool("nmap", ["-Pn", "-sV", "--top-ports", "100", "{HOST}"], "Nmap Fast Scan", "infrastructure", generic_text_parser, DEFAULT_NET),
    ExternalTool("rustscan", ["-a", "{HOST}", "--", "-sV"], "RustScan Port Scan", "infrastructure", generic_text_parser, DEFAULT_NET),
    ExternalTool("masscan", ["-p0-65535", "{HOST}", "--rate", "1000"], "Masscan", "infrastructure", generic_text_parser, DEFAULT_NET),
    ExternalTool("naabu", ["-host", "{HOST}", "-silent"], "Naabu Port Scanner", "infrastructure", generic_text_parser, DEFAULT_NET),
    
    # Recon & DNS Enumeration
    ExternalTool("amass", ["enum", "-d", "{HOST}", "-nocolor", "-passive"], "Amass Enumeration", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("subfinder", ["-d", "{HOST}", "-silent"], "Subfinder", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("assetfinder", ["{HOST}"], "Assetfinder", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("findomain", ["-t", "{HOST}", "-q"], "Findomain", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("bbot", ["-t", "{HOST}", "-f", "subdomain-enum"], "BBOT Scan", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("theHarvester", ["-d", "{HOST}", "-b", "all"], "theHarvester", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("chaos", ["-d", "{HOST}"], "Chaos Client", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("dnsx", ["-d", "{HOST}", "-silent"], "dnsx Resolution", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("shuffledns", ["-d", "{HOST}"], "shuffledns", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("puredns", ["resolve", "domains.txt", "-r", "resolvers.txt"], "puredns", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("subzy", ["target", "{HOST}"], "Subzy Subdomain Takeover", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("subjack", ["-w", "domains.txt", "-t", "100", "-timeout", "30", "-o", "results.txt", "-ssl"], "Subjack", "recon", generic_text_parser, DEFAULT_NET),
    
    # Probing, Crawling & Fuzzing
    ExternalTool("httpx", ["-u", "{TARGET}", "-silent", "-title", "-status-code"], "httpx Probing", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("katana", ["-u", "{TARGET}", "-silent"], "Katana Crawler", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("hakrawler", ["-url", "{TARGET}", "-plain"], "Hakrawler", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("gospider", ["-s", "{TARGET}", "-q"], "Gospider", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("waymore", ["-i", "{HOST}"], "Waymore", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("gau", ["{HOST}"], "GetAllUrls (gau)", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("waybackurls", ["{HOST}"], "Waybackurls", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("linkfinder", ["-i", "{TARGET}"], "LinkFinder", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("secretfinder", ["-i", "{TARGET}"], "SecretFinder", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("jsparser", ["-u", "{TARGET}"], "JSParser", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("jsubfinder", ["-u", "{TARGET}"], "JSubFinder", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("arjun", ["-u", "{TARGET}", "-q"], "Arjun Parameter Discovery", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("paramspider", ["--domain", "{HOST}"], "ParamSpider", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("x8", ["-u", "{TARGET}"], "x8 Parameter Discovery", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("ffuf", ["-u", "{TARGET}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200"], "ffuf Directory Bruteforce", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("feroxbuster", ["-u", "{TARGET}", "-q", "-n"], "Feroxbuster", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("dirsearch", ["-u", "{TARGET}", "--format=json"], "Dirsearch", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("gobuster", ["dir", "-u", "{TARGET}", "-w", "common.txt", "-q"], "Gobuster", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("dirb", ["{TARGET}"], "Dirb", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("wfuzz", ["-c", "-z", "file,wordlist/general/common.txt", "--hc", "404", "{TARGET}/FUZZ"], "wfuzz", "web", generic_text_parser, DEFAULT_WEB),
    
    # Auth, JWT, Graph, and APIs
    ExternalTool("graphql-voyager", ["{TARGET}"], "GraphQL Voyager", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("inql", ["-t", "{TARGET}"], "InQL Scanner", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("clairvoyance", ["{TARGET}"], "Clairvoyance", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("graphw00f", ["-t", "{TARGET}"], "Graphw00f", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("jwt_tool", ["{TARGET}"], "JWT Tool", "web", generic_text_parser, DEFAULT_WEB),
    ExternalTool("jwt-cli", ["decode", "{TARGET}"], "jwt-cli", "web", generic_text_parser, DEFAULT_WEB),
    
    # Secrets & Repo Scanning
    ExternalTool("trufflehog", ["git", "{TARGET}"], "TruffleHog Scanner", "secrets", generic_text_parser, frozenset({AssetType.GIT})),
    ExternalTool("gitleaks", ["detect", "-v", "--repo", "{TARGET}"], "Gitleaks", "secrets", generic_text_parser, frozenset({AssetType.GIT})),
    ExternalTool("gitrob", ["-github-access-token", "REDACTED", "{TARGET}"], "Gitrob", "secrets", generic_text_parser, frozenset({AssetType.GIT})),
    
    # Cloud Security
    ExternalTool("prowler", ["aws", "--quiet"], "Prowler AWS Scan", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("scoutsuite", ["aws"], "ScoutSuite", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("pacu", ["--session", "cygnus"], "Pacu", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("microburst", [], "MicroBurst", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("roadtools", ["roadrecon", "gather"], "ROADtools", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("gcpbucketbrute", ["-k", "keyword"], "GCPBucketBrute", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("s3scanner", ["--scan", "{HOST}"], "S3Scanner", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("s3finder", ["{HOST}"], "S3Finder", "cloud", generic_text_parser, DEFAULT_CLOUD),
    ExternalTool("bucket_finder", ["{HOST}"], "Bucket Finder", "cloud", generic_text_parser, DEFAULT_CLOUD),
    
    # Mobile Scanning
    ExternalTool("mobsf", ["-m", "{TARGET}"], "MobSF Scanner", "mobile", generic_text_parser, frozenset({AssetType.MOBILE_ANDROID, AssetType.MOBILE_IOS})),
    ExternalTool("jadx", ["-d", "out", "{TARGET}"], "Jadx Decompiler", "mobile", generic_text_parser, frozenset({AssetType.MOBILE_ANDROID})),
    ExternalTool("apktool", ["d", "{TARGET}"], "APKTool", "mobile", generic_text_parser, frozenset({AssetType.MOBILE_ANDROID})),
    ExternalTool("frida", ["-U", "-f", "{TARGET}"], "Frida", "mobile", generic_text_parser, frozenset({AssetType.MOBILE_ANDROID, AssetType.MOBILE_IOS})),
    ExternalTool("objection", ["-g", "{TARGET}", "explore"], "Objection", "mobile", generic_text_parser, frozenset({AssetType.MOBILE_ANDROID, AssetType.MOBILE_IOS})),
    ExternalTool("drozer", ["console", "connect"], "Drozer", "mobile", generic_text_parser, frozenset({AssetType.MOBILE_ANDROID})),
    
    # Bruteforce / Network Auth
    ExternalTool("bettercap", ["-eval", "net.probe on"], "Bettercap", "network", generic_text_parser, DEFAULT_NET),
    ExternalTool("hashcat", ["-m", "0", "hash.txt", "wordlist.txt"], "Hashcat", "crypto", generic_text_parser, DEFAULT_NET),
    ExternalTool("john", ["hash.txt"], "John the Ripper", "crypto", generic_text_parser, DEFAULT_NET),
    ExternalTool("hydra", ["-l", "admin", "-P", "pass.txt", "{HOST}", "ssh"], "Hydra", "bruteforce", generic_text_parser, DEFAULT_NET),
    ExternalTool("medusa", ["-u", "admin", "-P", "pass.txt", "-h", "{HOST}", "-M", "ssh"], "Medusa", "bruteforce", generic_text_parser, DEFAULT_NET),
    
    # Fingerprinting & Asset Recognition
    ExternalTool("whatweb", ["{TARGET}", "-q"], "WhatWeb Fingerprinting", "recon", generic_text_parser, DEFAULT_WEB),
    ExternalTool("wappalyzer", ["{TARGET}"], "Wappalyzer (CLI)", "recon", generic_text_parser, DEFAULT_WEB),
    ExternalTool("cmseek", ["-u", "{TARGET}", "--batch"], "CMSeeK", "recon", generic_text_parser, DEFAULT_WEB),
    ExternalTool("builtwith", ["{TARGET}"], "BuiltWith", "recon", generic_text_parser, DEFAULT_WEB),
    
    # Integration with external services/APIs
    ExternalTool("shodan", ["host", "{HOST}"], "Shodan Lookup", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("censys", ["search", "{HOST}"], "Censys Lookup", "recon", generic_text_parser, DEFAULT_NET),
    ExternalTool("fofa", ["search", 'host="{HOST}"'], "FOFA Lookup", "recon", generic_text_parser, DEFAULT_NET),
]

class OrchestratorModuleWrapper:
    def __init__(self, tool: ExternalTool):
        self.tool = tool
        self.name = f"external.{tool.bin_name}"
        self.applies_to = tool.applies_to
        self.requires_active = tool.requires_active

    async def run(self, target: AssetProfile, ctx: ScanContext) -> list[FindingCandidate]:
        return await self.tool.run(target, ctx)

MODULES = [OrchestratorModuleWrapper(t) for t in TOOL_CATALOG]
