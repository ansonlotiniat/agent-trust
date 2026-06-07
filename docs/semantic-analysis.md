# Semantic Command Analysis

Agent Trust should not behave like a keyword blacklist. The core question is not "did the command contain `rm`?" The core question is:

> What is the command trying to do, and what scope will it touch?

That is why `rm -rf dist` should stay fast while `rm -rf /`, `rm -rf ~`, `cat ~/.ssh/id_rsa`, and writes to `~/.zshrc` should brake.

## Current Model

The analyzer classifies commands into three layers.

### Intent

Examples:

- `destructive`: removes data or changes filesystem state destructively.
- `recursive`: applies across directory trees.
- `forceful`: bypasses ordinary safety prompts or protections.
- `write`: writes file content.
- `permission-change`: changes ownership or permissions.
- `privilege-escalation`: asks for elevated privileges.
- `disk-operation`: targets raw disks, mounts, formats, or low-level filesystem operations.

### Scope

Examples:

- `project-local`: target is inside the current project.
- `outside-project`: target leaves the current project.
- `home`: target is the user's home directory or broad home subtree.
- `credential`: target is credential material such as SSH, cloud, npm, Docker, Kubernetes, Git credentials, or private keys.
- `shell-config`: target is a shell startup file such as `.zshrc`, `.bashrc`, or `.profile`.
- `system`: target is a system path such as `/etc`, `/usr`, `/bin`, `/sbin`, `/Library`, or `/System`.
- `root`: target is `/`.

### Derived Brakes

Examples:

- `catastrophic`: high-blast-radius destructive action such as recursive force delete against `/`, home, system paths, or outside-project targets.
- `credential-access`: reads credential material.
- `credential-mutation`: writes or deletes credential material.
- `system-mutation`: writes, deletes, or changes permissions under system paths.
- `shell-config-mutation`: modifies shell startup behavior.

Policy rules operate on these semantic tags.

## Examples

```bash
agent-trust decide -- rm -rf dist
# allow: destructive, recursive, forceful, project-local

agent-trust decide -- rm -rf /
# deny: destructive, recursive, forceful, root, catastrophic

agent-trust decide -- cat ~/.ssh/id_rsa
# ask: credential, credential-access

agent-trust decide -- bash -c 'echo x > ~/.zshrc'
# ask: write, shell-config, shell-config-mutation

agent-trust decide -- sudo rm -rf /etc
# ask: privilege-escalation, destructive, recursive, forceful, system, system-mutation
```

## Known Limitations

The current analyzer is heuristic. It handles common dangerous-mode agent behavior, but it is not yet a complete shell AST, filesystem, or language runtime model.

Important gaps:

- full shell grammar for command substitution, heredocs, subshells, process substitution, arrays, and complex quoting;
- symlink-aware target scope with realpath resolution;
- glob expansion risk scoring;
- deeper semantics for tools such as `find`, `git clean`, `rsync`, `xargs`, package managers, `node -e`, and `python -c`;
- runtime behavior hidden behind scripts or binaries.

The roadmap is to make the analyzer more parser-backed and filesystem-aware while preserving the default product posture: keep dangerous mode fast, brake only when intent and scope justify it.
