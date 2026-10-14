import { unzipSync } from "fflate";

export interface ZipEntry {
  name: string;
  bytes: Uint8Array;
}

/** Every file in a zip (directories skipped), in archive order. */
export function unzipAll(bytes: Uint8Array): ZipEntry[] {
  const files = unzipSync(bytes);
  return Object.entries(files)
    .filter(([name, data]) => !name.endsWith("/") && data.byteLength > 0)
    .map(([name, data]) => ({ name, bytes: data }));
}

/** The first entry whose name matches, or null. */
export function findEntry(entries: ZipEntry[], pattern: RegExp): ZipEntry | null {
  return entries.find((e) => pattern.test(e.name)) ?? null;
}

/** Text of an entry, honouring a UTF-8 or UTF-16 byte-order mark; Microsoft's older files are UTF-16. */
export function entryText(entry: ZipEntry): string {
  const b = entry.bytes;
  let text: string;
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) text = new TextDecoder("utf-16le").decode(b.subarray(2));
  else if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) text = new TextDecoder("utf-16be").decode(b.subarray(2));
  else text = new TextDecoder("utf-8").decode(b);
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
