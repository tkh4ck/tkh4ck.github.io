# CyberQuest 2025 - Cinder Repo Ghost

## Description

**Cinder Repo — Ghost Index (Player Handout) - HARD**

**Type:** Git forensics (repo archaeology)

**TASK**

Generate a local Git repo using the provided script(s). Three tokens are hidden in three different Git artefacts. NOTE → STASH → TAG. Combine the three tokens to produce a flag.

**Note**: Each token is labeled where it appears: tkn1: …, tkn2: …, tkn3: ….

**RUN**

**Linux/macOS**

```
bash setup_cinder_repo.sh
cd cinder_repo_ghost
```

**Windows (PowerShell)**

```
powershell
powershell -ExecutionPolicy Bypass -File .\setup_cinder_repo.ps1
Set-Location .\cinder_repo_ghost
```

**RULES**

- No brute force; everything is local.
- Don’t modify the repo; reading is enough.
- Submit format: CQ25{TOKEN1_TOKEN2_TOKEN3}.

## Metadata

- Filename: [`setup_cinder_repo.ps1`](files/setup_cinder_repo.ps1), [`setup_cinder_repo.sh`](files/setup_cinder_repo.sh)
- Tags: `git`, `base64`

## Solution

I didn't really understand the task, because the parts of the flag is present in the files:

```bash
NOTE=$(printf 'dGtuMTogUEg0TlQwTQ==' | base64 -d)
STASHW=$(printf 'dGtuMjogMU5EM1g='   | base64 -d)
TAGW=$(printf 'dGtuMzogMFIxRzFO'     | base64 -d)
```

```
tkn1: PH4NT0M
tkn2: 1ND3X
tkn3: 0R1G1N
```

Flag: `CQ25{PH4NT0M_1ND3X_0R1G1N}`