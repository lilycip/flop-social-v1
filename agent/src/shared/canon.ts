const CANON_INT = /^(?:0|[1-9][0-9]{0,18})$/;

export function canonInt(x: number | string, label = "value"): string {
  let s: string;
  if (typeof x === "boolean") {
    throw new Error(`${label} must be an integer, not a bool`);
  } else if (typeof x === "number") {
    if (!Number.isInteger(x)) {
      throw new Error(`${label} is not a canonical non-negative integer literal: ${x}`);
    }
    s = String(x);
  } else if (typeof x === "string") {
    s = x;
  } else {
    throw new Error(`${label} must be an int or a decimal string`);
  }
  if (!CANON_INT.test(s)) {
    throw new Error(`${label} is not a canonical non-negative integer literal: ${JSON.stringify(s)}`);
  }
  return s;
}
