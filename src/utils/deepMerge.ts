/**
 * Utility for deep merging objects, especially useful for configuration
 */

/**
 * Deeply merge two objects, with values from 'source' overriding 'target'
 * Arrays are replaced, not merged
 * 
 * @param target Base object to merge into
 * @param source Object with values to merge
 * @returns A new object with merged properties
 */
export function deepMerge<T extends Record<string, any>>(
  target: T,
  source?: Partial<T>
): T {
  // If source is undefined or null, return a copy of target
  if (!source) {
    return { ...target };
  }

  // Create a new object to avoid mutating either input
  const result: Record<string, any> = { ...target };

  // Iterate through source properties
  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      const sourceValue = source[key];
      const targetValue = target[key];

      // Handle null case
      if (sourceValue === null) {
        result[key] = null;
        continue;
      }

      // If both values are objects and not arrays, merge them recursively
      if (
        typeof sourceValue === 'object' && 
        !Array.isArray(sourceValue) &&
        typeof targetValue === 'object' && 
        !Array.isArray(targetValue) &&
        targetValue !== null
      ) {
        result[key] = deepMerge(targetValue, sourceValue);
      } else {
        // For arrays and primitives, replace the value
        result[key] = sourceValue;
      }
    }
  }

  return result as T;
}