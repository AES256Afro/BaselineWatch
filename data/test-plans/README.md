# Test-plan templates

Each YAML file here is one template the test-plan page (`/baselines/<platform>/tests`) adds to
the checks it derives from the STIG and mSCP procedures. They are the owner's starting points,
labelled as such on the page and in every export; every step cites the publisher's document it
follows. Add a file to extend them; the page reads the folder on every request.

```yaml
id: filevault-escrow            # stable; the step ids are <id> 1, <id> 2...
title: FileVault with recovery-key escrow
platforms: [macos]              # windows, macos, linux, or all
area: encryption                # authentication, browsers, encryption, logging, network, updates, mdm, other
notes: optional, shown above the steps
steps:
  - do: what to do, as an instruction
    expect: what a pass looks like (optional)
    source:                     # optional; both fields or neither; https only
      title: Apple Platform Deployment, "Use FileVault"
      url: https://support.apple.com/guide/deployment/...
```
