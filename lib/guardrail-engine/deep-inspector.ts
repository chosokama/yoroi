/**
 * Deep Inspector
 *
 * Recursively traverses a nested args/content object and extracts all string
 * values along with their dot-paths. This ensures that injection payloads or
 * credentials embedded in deeply nested structures are not missed by scanners
 * that only check top-level keys.
 */

export interface StringField {
  /** Dot-path to this field, e.g. "args.body.message" */
  path: string;
  /** The string value at this path */
  value: string;
}

// Maximum recursion depth to prevent DoS via deeply nested inputs
const MAX_DEPTH = 12;
// Maximum total string fields to extract (prevents pathological inputs)
const MAX_FIELDS = 256;

/**
 * Extracts all string values (and stringified non-string primitives) from a
 * nested args object, returning each as { path, value }.
 *
 * Arrays are traversed with numeric index paths (e.g. "messages[0].content").
 */
export function extractStringFields(
  obj: unknown,
  parentPath = "",
  depth = 0,
  collected: StringField[] = []
): StringField[] {
  if (depth > MAX_DEPTH || collected.length >= MAX_FIELDS) {
    return collected;
  }

  if (typeof obj === "string") {
    if (parentPath && obj.trim().length > 0) {
      collected.push({ path: parentPath, value: obj });
    }
    return collected;
  }

  if (typeof obj === "number" || typeof obj === "boolean") {
    if (parentPath) {
      collected.push({ path: parentPath, value: String(obj) });
    }
    return collected;
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length && collected.length < MAX_FIELDS; i++) {
      const itemPath = parentPath ? `${parentPath}[${i}]` : `[${i}]`;
      extractStringFields(obj[i], itemPath, depth + 1, collected);
    }
    return collected;
  }

  if (obj !== null && typeof obj === "object") {
    const record = obj as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (collected.length >= MAX_FIELDS) break;
      const fieldPath = parentPath ? `${parentPath}.${key}` : key;
      extractStringFields(record[key], fieldPath, depth + 1, collected);
    }
    return collected;
  }

  return collected;
}

/**
 * Extracts only string values longer than a minimum length.
 * Used for content-heavy scans that don't need to check short strings.
 */
export function extractLongStrings(
  obj: unknown,
  minLength = 20
): StringField[] {
  const all = extractStringFields(obj);
  return all.filter((f) => f.value.length >= minLength);
}

/**
 * Converts a content payload (string or object) into a flat list of string fields.
 */
export function normalizeContent(
  content: string | Record<string, unknown>
): StringField[] {
  if (typeof content === "string") {
    return content.trim().length > 0
      ? [{ path: "_content", value: content }]
      : [];
  }
  return extractStringFields(content);
}

/**
 * Concatenates all string values into a single string for bulk pattern matching.
 * Useful when the exact field path doesn't matter (e.g. keyword scan).
 */
export function flattenToString(obj: unknown): string {
  return extractStringFields(obj)
    .map((f) => f.value)
    .join(" ");
}
