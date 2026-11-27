# Publish a WSUS Manager release

Use this guide when preparing a release of [chr1s5/WSUS-Manager](https://github.com/chr1s5/WSUS-Manager).

## Validate the release candidate

Open the candidate commit and check its **Validate WSUS Manager** run in GitHub Actions. It runs the regression suite in Windows PowerShell 5.1 and PowerShell 7. To repeat those checks locally, follow the [contribution guide](../CONTRIBUTING.md).

In a Windows desktop session connected to a test WSUS server, load a target group, search the dashboard, and cancel a pilot approval preview. Record the operating system, PowerShell and WSUS versions used and which operations you exercised.

Check that the version, launch commands and feature descriptions agree in the [German](../README.md) and [English](../README.en.md) READMEs.

## Draft the GitHub release

Create a draft release and select a version tag pointing to the tested commit. Describe changes that affect operators, the tested environment and any known limitations. Attach `WSUS-Manager.ps1` from that commit for administrators who download the standalone script. Review the draft and its attachment before publishing.

## Repository settings

Use the About panel for topics such as `wsus`, `powershell`, `windows-server`, `patch-management` and `sysadmin`. The repository security settings control private vulnerability reporting. The [security policy](../SECURITY.md) explains how a reporter can request a private channel.
