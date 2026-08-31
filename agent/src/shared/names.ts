const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

export function isValidName(name: unknown): name is string {
  return typeof name === "string" && NAME_RE.test(name);
}

export type RoomClass = "private" | "mailbox_private" | "mailbox" | "ownable" | "open";
export function roomClass(room: string): RoomClass | null {
  if (!isValidName(room)) return null;
  if (room.startsWith("mb-p-")) return "mailbox_private";
  if (room.startsWith("mb-")) return "mailbox";
  if (room.startsWith("p-")) return "private";
  if (room.startsWith("d-")) return "ownable";
  return "open";
}

export function nameIsBearerSecret(room: string): boolean {
  const c = roomClass(room);
  return c === "private" || c === "mailbox_private";
}
