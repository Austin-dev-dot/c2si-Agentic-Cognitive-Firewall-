# Cognitive Firewall SDK

Security middleware for LLM agents. Catches prompt injections, enforces policies, and sanitizes inputs before they reach the model.

Built as a POC for the C2SI GSoC 2026 project.

## How it works

```
User prompt → SDK interceptor → Firewall API → Allow / Sanitize / Block → Agent
```

The firewall runs as a separate FastAPI service. The SDK is a Python decorator you slap on your agent's `invoke()` method — one line of code and you're protected.

### What gets checked
- **Detector** — regex patterns + heuristic scoring for known injection techniques
- **Policy engine** — YAML rules you can edit without touching code
- **Sanitizer** — strips dangerous delimiters and injection phrases
- **Risk scorer** — combines all signals into a 0-1 score and makes the call

## Setup

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1   # windows
pip install -r requirements.txt
```

## Usage

Start the firewall server:
```bash
python -m app.server
```

In another terminal, run the demo agent:
```bash
python examples/langgraph_agent.py
```

Interactive API docs at `http://localhost:8000/docs`.

## Defining policies

Edit `policies/default.yaml`:

```yaml
rules:
  - name: block_credentials
    match: "(password|api key|secret key)"
    action: BLOCK
```

## Project structure

```
firewall/
  detector.py     # injection detection (regex + heuristics)
  sanitizer.py    # strips malicious content
  policy.py       # loads and evaluates YAML rules
  risk.py         # combines signals, makes allow/block decision
app/
  server.py       # FastAPI endpoints (/scan, /health)
sdk/
  middleware.py   # @firewall_protected decorator
policies/
  default.yaml    # security rules
examples/
  langgraph_agent.py  # demo agent with firewall integration
```
