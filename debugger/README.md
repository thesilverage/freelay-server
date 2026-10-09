# Legacy upstream debugger

This y-sweet debugger is retained for upstream compatibility. It is not wired
to Freelay's Ed25519 control plane, and legacy document-creation/authentication
routes are disabled in integrated mode. Do not deploy it as a Freelay admin UI.
The administrator uses the local `freelay control` commands documented in
[OPERATIONS.md](../docs/OPERATIONS.md).
