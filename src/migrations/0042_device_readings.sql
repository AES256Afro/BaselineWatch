-- Device readings (added 2026-10-21, Scan 2.0 S7): what the owner's devices were found to run
-- and what applied, one row per reading, so the next reading can say what changed and Today can
-- say how many devices are exposed. The facts kept are the verdicts and the CVE ids, never the
-- report itself (no package list, no browser list); the owner names the device.
CREATE TABLE device_readings (
  id            INTEGER PRIMARY KEY,
  device        TEXT NOT NULL,                   -- the owner's name for it: "laptop", "the study PC"
  os            TEXT NOT NULL,                   -- windows | macos | linux
  os_label      TEXT,                            -- "Windows 11 Version 24H2, build 10.0.26100.9445"
  read_at       TEXT NOT NULL,
  worst         TEXT NOT NULL CHECK (worst IN ('ok', 'warn', 'bad', 'na')),
  findings_json TEXT NOT NULL                    -- [{id, title, state, text, refs:[{id, href}]}], refs capped
);
CREATE INDEX device_readings_by_device ON device_readings (device, read_at DESC);
