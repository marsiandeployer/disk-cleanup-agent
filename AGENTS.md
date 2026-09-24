# Project instructions

Read any applicable parent `AGENTS.md` first. This repository is a portable Linux disk-cleanup
tool. Its scanner and deletion guards use only the Python standard library.
The local model is advisory: model output cannot authorize deletion or invoke
shell commands. Deletion requires an explicitly enabled category rule or an
exact path and identity approval, followed by fresh checks immediately before
the operation. Unknown visibility or failed checks preserve the target.

Run tests with `python3 -m unittest discover -s tests -v`. Keep test fixtures
inside temporary directories. Never run `apply` against production paths during
development or CI. The release bundle must run without root, PM2, systemd, or
network access after installation.
