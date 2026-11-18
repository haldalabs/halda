<h1 align="center">Halda</h1>

<p align="center"><b>See every AI agent and add-on on your machine, what each one can reach, and what a hijacked one could take.</b><br>Free, open source, and local. Nothing leaves your machine.</p>

<p align="center">
  <a href="https://github.com/haldalabs/halda/releases"><img src="https://img.shields.io/github/v/release/haldalabs/halda?include_prereleases" alt="Release"></a>
  <a href="https://github.com/haldalabs/halda/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/haldalabs/halda/ci.yml" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"></a>
</p>

---

AI agents now run with your login and your keys: Claude Code, Cursor, Codex, and the MCP servers, skills, plugins and extensions they load. Any of them can be turned by one poisoned file, issue or web page, or by a bad release of an add-on you installed months ago.

We read the 1,000 most-downloaded MCP servers on npm. **76% tell you to set them up so your agent fetches and runs the newest release every time it starts. 2% pin a version.** One bad release reaches every user, with their keys, and nothing asks first. That is how postmark-mcp, Nx and Shai-Hulud worked.

Halda shows you where you stand in a minute.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/haldalabs/halda/main/install.sh | sh
```

The script checks every download against its published checksum and installs nothing if it does not match. Read it first if you like: [install.sh](install.sh). Or build from source with `cargo install --path crates/halda-open`.

macOS and Linux.

## What it does

### `halda scan`: every agent and add-on, and what it can do

```
Read local config only. Started nothing, sent nothing.

HIGH  deploy  skill · Claude Code
      its instructions tell agents to run: git push --force origin main
      ~/.claude/skills/deploy

HIGH  github  MCP server · Claude Code
      keeps a long-lived secret in plain text (GITHUB_PERSONAL_ACCESS_TOKEN)
      can change code and repositories
      installs its newest version on every start, so a bad release reaches you automatically
      ~/.claude.json

HIGH  postgres  MCP server · Claude Code
      has a password or key written into its command line, which any local process can read
      can change data in a database, and may DROP tables
      installs its newest version on every start, so a bad release reaches you automatically
      ~/.claude.json

HIGH  stripe  MCP server · Cursor
      can move money
      ~/.cursor/mcp.json
```

It reads the config of Claude Code, Claude Desktop, Cursor, Codex, Windsurf, VS Code and Gemini CLI, and the code of the MCP servers, skills, plugins, hooks and extensions they load. It flags secrets in plain text by name only and never prints them. It never starts an add-on.

`--json` and `--sarif` for scripts and code scanning. `--fail-on high` to fail a CI job. `--catalog` to keep an approved list and catch any add-on that changes after you approved it.

### `halda exposure`: what a hijacked agent on your machine could get out

Plays a hijacked agent: 18 ways an attacker tells an agent to get a secret off the machine, such as hiding it in a Makefile, an install script, a test setup file or a git hook. It uses a **fake secret** and a **listener on your own machine**, in throwaway folders with an empty environment. Your real keys are never in reach, and nothing leaves.

```
  Sent directly with curl                                  GOT OUT
  Hidden in a postinstall script, then `npm install`       GOT OUT
  Hidden in conftest.py, then `pytest`                     GOT OUT
  Poisoned package that runs on Python startup             GOT OUT
  ...
15 of 15 ways got the fake secret out, with nothing in the way.

Real credential files any agent running as you can open (5). Checked that they exist, never opened:
  ~/.aws/credentials
  ~/.ssh/id_rsa
  ...
```

### `halda map`: one view of every agent

Everything `scan` found, grouped by agent, with what each can reach and what the map cannot see. Add `--github <org>` to read your GitHub Actions workflows for AI agents, read-only.

### `halda replay`: what your agents really did

Reads Claude Code's history on this machine and judges every command your agents ran with Halda's rules: how many were safe, how many would need a check, and which would have been refused. Read-only. Run nothing, send nothing.

## What stays on your machine

Everything. `scan`, `exposure` and `replay` make no network requests at all. `map --github` and `map --microsoft` call only GitHub or Microsoft, read-only, with your own token, and only when you ask.

## Halda for companies

This tool shows one machine. **Halda** is the AI security team that defends your whole company: it finds and attacks what is exposed across your people, cloud, code, SaaS apps and AI agents, investigates every alert, and stops attacks and costly mistakes in seconds. It runs inside your company, and your data never leaves it.

To try it at your company: [haldalabs.xyz](https://haldalabs.xyz) or hello@haldalabs.xyz.

## Contributing

New add-on checks, agents to read and attack routes are welcome. Each rule needs a test that plants a fake machine and checks what is found. See [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately: [SECURITY.md](SECURITY.md).

## License

Apache-2.0.
