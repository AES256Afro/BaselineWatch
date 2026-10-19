# Test-plan templates

Each YAML file here is one template the test-plan page (`/baselines/<platform>/tests`) adds to
the checks it derives from the STIG and mSCP procedures. They are the owner's starting points,
labelled as such on the page and in every export; every step cites the publisher's document it
follows and says what to do when it does not pass. Add a file to extend them; the page reads the
folder on every request.

A template, or one step of it, can say which releases and which hardware it is for. The page
reads the fleet (`data/platforms.yaml`: each operating system's releases and the hardware each
runs on) and, once a version and hardware are chosen, leaves out what does not apply, saying
why: a Secure Enclave check on an Intel Mac without a T2 chip, an Administrator protection check
on Windows 11 23H2. With nothing chosen, everything applies.

```yaml
id: hardware-root-macos         # stable; the step ids are <id> 1, <id> 2...
title: Secure Enclave, secure boot and the signed system on a Mac
platforms: [macos]              # windows, macos, linux, ios, ipados, android, collaboration, or all
area: hardware                  # hardware, sso, authentication, encryption, mdm, updates, network,
                                # browsers, logging, collaboration, other
applies:                        # optional, for the whole template
  versions:
    macos: [">=14"]             # release ids from data/platforms.yaml; >=, <= or exact
  hardware: [apple-silicon, intel-t2]   # hardware ids from data/platforms.yaml
notes: optional, shown above the steps
steps:
  - do: what to do, as an instruction (quote it when it contains a colon and a space)
    expect: what a pass looks like (optional)
    fail: what to do when it does not pass (optional)
    applies:                    # optional, for this step only; narrows the template's
      hardware: [apple-silicon]
    source:                     # optional; both fields or neither; https only
      title: Apple Platform Security, "Startup Disk security policy control"
      url: https://support.apple.com/guide/security/...
```

Version rules are judged by the order of releases in `data/platforms.yaml`, newest first, so
`>=24H2` and `>=26` need no number parsing and Windows feature updates sort right.

The exports (printable checklist, Markdown, CSV, JSON, LaTeX, Word, PDF) carry the kept checks
with their success and failure branches, the checks left out and why, a findings table and a
sign-off block. Areas unticked on the page stay out of the exports and are listed as not tested
this time.
