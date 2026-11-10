-- Public pages carried build notes: "(M12.3)", a milestone number, inside the canary sources' notes.
-- A reader of /register and /sources has no plan to look it up in.
UPDATE sources SET notes = REPLACE(notes, 'The network check (M12.3) resolves', 'The network check resolves') WHERE notes LIKE '%(M12.3)%';
