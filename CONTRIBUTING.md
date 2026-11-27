# Contributing

Open an issue for a reproducible problem or a proposed workflow change. Include the Windows PowerShell version, the manager commit or release, the affected tab and the smallest sanitized example that demonstrates the behavior.

Use a topic branch and keep changes scoped to the issue. Preserve Windows PowerShell 5.1 compatibility, live checks before writes and explicit confirmation of approvals, removals and group restoration. When changing user-facing behavior or launch instructions, update both the [German](README.md) and [English](README.en.md) READMEs.

Run the regression checks from the repository root in both supported PowerShell versions.

```powershell
powershell.exe -NoProfile -File .\Test-WSUSManager.ps1
pwsh.exe -NoProfile -File .\Test-WSUSManager.ps1
```

For GUI changes, describe the checks you ran in a desktop session. For deployment changes, test the preview and cancellation paths with a pilot group. If you tested a write operation in a lab, include the observed WSUS result. For changes to pagination, check the first, next and last pages as well as a canceled query.
