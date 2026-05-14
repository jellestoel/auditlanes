# Architecture Profile

This profile is metadata-only in AuditLanes v0.4.12.

It exists to prove the core/profile split and to reserve a compact lane taxonomy
for future architecture audits. The bundled validator rejects it by default
because the report contracts and reducer semantics are still security-profile
specific.

`--allow-experimental` may be used to check that the architecture profile and
lane catalog load, but it does not make architecture sidecars runnable. The
current executable report schema does not include architecture-specific modes
such as `impact-synthesis`.
