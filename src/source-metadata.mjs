function parseJson(bytes) { try { return JSON.parse(bytes.toString()); } catch { return null; } }
export function inspect(bytes) { return { format: 'DLT', storageHeader: bytes.subarray(0,4).toString('hex'), ecu: bytes.length >= 16 ? bytes.subarray(12,16).toString() : null }; }
