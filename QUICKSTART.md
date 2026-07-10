# 🚀 BUGFINDER Quick Start Guide

## Prerequisites

- AI Agent with CYGNUS system prompt loaded
- Authorization to test target systems
- Understanding of the CYGNUS workflow

---

## Step 1: Load CYGNUS System Prompt

Copy the contents of `CYGNUS_SYSTEM_PROMPT.md` into your AI agent's system prompt field.

---

## Step 2: Declare Operating Mode

Before any scan, declare your mode:

```
Mode: ONLINE (live testing) or OFFLINE/STATIC (code analysis)
```

---

## Step 3: Confirm Authorization

```markdown
Authorization Gate:
1. Do you own/have permission for this target?
2. Is target in scope of your bug bounty program?
3. Do you have written authorization?
```

**If any answer is NO → Do not proceed with scanning.**

---

## Step 4: Provide Target Details

Example inputs:
- URL: `https://target.com`
- IP: `192.168.1.100`
- Domain: `example.com`
- Repository: `github.com/user/repo`

---

## Step 5: Receive Assessment Report

CYGNUS will produce a structured report with:
- ✅ Confirmed findings (evidence-backed)
- 🟡 Manual verification items (offline mode)
- 🔗 Exploit chains (if dependencies exist)
- 🧠 Strategic next steps

---

## Example Session

```
You: I want to scan https://example.com — I own this domain.

CYGNUS: Authorization confirmed for owned asset.
        Mode: ONLINE
        Target: https://example.com
        Asset type: Web Application
        
        [Running checks...]
        
        ✅ Finding: Missing X-Content-Type-Options header
           Severity: Medium | Confidence: High
           Evidence: Header not present in response
           Remediation: Add "X-Content-Type-Options: nosniff"
```

---

## Support

For issues or feature requests, open an issue on the GitHub repository.