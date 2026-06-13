# NetworkRuler Legacy Code

The original CLI and GUI remain as legacy reference material. They must not be
imported by v2 code.

## Wrappers

Old wrapper launchers that conflicted with the v2 `nr` console entry point were
moved to `legacy/wrappers/`:

- `nr.bat`
- `network_ruler.ps1`

These wrappers still point at the legacy script and are kept only for reference.
Use the installed v2 console script for current development:

```powershell
nr doctor
```
