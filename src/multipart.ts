/**
 * A small multipart/form-data reader for the one upload form the app has (a CIS Benchmark PDF).
 * Reads the whole body into memory (the route caps it) and returns the fields and files.
 */
export interface UploadedFile {
  field: string;
  filename: string;
  contentType: string;
  bytes: Uint8Array;
}

export interface ParsedForm {
  fields: Record<string, string>;
  files: UploadedFile[];
}

function indexOf(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

export function boundaryOf(contentType: string | undefined): string | null {
  if (!contentType) return null;
  const m = /multipart\/form-data;.*boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  return m ? (m[1] ?? m[2] ?? "").trim() || null : null;
}

export function parseMultipart(body: Uint8Array, boundary: string): ParsedForm {
  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8");
  const delimiter = enc.encode(`--${boundary}`);
  const fields: Record<string, string> = {};
  const files: UploadedFile[] = [];
  let position = indexOf(body, delimiter);
  while (position >= 0) {
    let start = position + delimiter.length;
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break; // the closing "--"
    if (body[start] === 0x0d && body[start + 1] === 0x0a) start += 2;
    const headerEnd = indexOf(body, enc.encode("\r\n\r\n"), start);
    if (headerEnd < 0) break;
    const headers = dec.decode(body.subarray(start, headerEnd));
    const next = indexOf(body, delimiter, headerEnd + 4);
    if (next < 0) break;
    let contentEnd = next;
    if (body[contentEnd - 2] === 0x0d && body[contentEnd - 1] === 0x0a) contentEnd -= 2;
    const content = body.subarray(headerEnd + 4, contentEnd);
    const disposition = /content-disposition:\s*form-data;([^\r\n]*)/i.exec(headers)?.[1] ?? "";
    const name = /name="([^"]*)"/i.exec(disposition)?.[1] ?? "";
    const filename = /filename="([^"]*)"/i.exec(disposition)?.[1];
    const type = /content-type:\s*([^\r\n]+)/i.exec(headers)?.[1]?.trim() ?? "application/octet-stream";
    if (filename !== undefined) files.push({ field: name, filename: filename.replace(/.*[\\/]/, ""), contentType: type, bytes: content });
    else fields[name] = dec.decode(content);
    position = next;
  }
  return { fields, files };
}
