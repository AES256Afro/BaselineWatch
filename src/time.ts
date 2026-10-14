const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "3 min ago", "2 h ago", "Mon 14 Oct", "14 Oct 2025": what a person wants to see in a list. */
export function relativeTime(iso: string | null, now: Date): string {
  if (!iso) return "";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "";
  const seconds = Math.round((now.getTime() - then.getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 24 * 3600) return `${Math.round(seconds / 3600)} h ago`;
  if (seconds < 7 * 24 * 3600) return `${dayNames[then.getUTCDay()]} ${then.getUTCDate()} ${monthNames[then.getUTCMonth()]}`;
  if (then.getUTCFullYear() === now.getUTCFullYear()) return `${then.getUTCDate()} ${monthNames[then.getUTCMonth()]}`;
  return `${then.getUTCDate()} ${monthNames[then.getUTCMonth()]} ${then.getUTCFullYear()}`;
}

/** "2026-10-14 06:58" in UTC. */
export function shortStamp(iso: string | null): string {
  if (!iso) return "";
  return iso.slice(0, 16).replace("T", " ");
}
