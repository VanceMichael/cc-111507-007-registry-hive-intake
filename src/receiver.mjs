import { receiveBytes } from './http-client.mjs';
import { inspect } from './source-metadata.mjs';
import { parseHive } from './hive-parser.mjs';

// 资料接收：raw 保留原始字节与元信息；structured 在原文证据之上做受控 REGF 结构解释。
export async function collect({ input, descriptor, sourceBase, store }) {
  if (!['raw', 'structured'].includes(input.mode)) {
    return { httpStatus: 400, error: '接收方式无效' };
  }
  const source = await receiveBytes(`${sourceBase}/files/${encodeURIComponent(descriptor.entry)}`);
  const blob = await store.blob(source.bytes);

  if (input.mode === 'raw') {
    const receipt = await store.save({ state: 'received', mode: 'raw', product: descriptor.product,
      source: descriptor.entry, sourceVersion: source.etag, metadata: inspect(source.bytes),
      blobs: [blob], records: [], issues: [],
      coverage: { structured: false, downloadedBytes: source.bytes.length } });
    return { receipt };
  }

  let parsed;
  try {
    parsed = parseHive(source.bytes, descriptor.entry);
  } catch (error) {
    // 完全无法解释时保留原文证据，形成 rejected 收件，而不是抛异常丢弃字节。
    const receipt = await store.save({
      state: 'rejected', mode: 'structured', product: descriptor.product,
      source: descriptor.entry, sourceVersion: source.etag, metadata: inspect(source.bytes),
      blobs: [blob], records: [],
      issues: [{ code: error.code || 'UNREADABLE_HIVE', message: error.message,
        location: error.location || null, scope: 'hive', severity: 'gap' }],
      coverage: { structured: true, downloadedBytes: source.bytes.length,
        sourceSha256: blob.digest, synchronized: false, traversal: 'unavailable',
        freeCellsScanned: false, deletedRecovered: false, environmentExpanded: false,
        credentialExtraction: false },
    });
    return { receipt };
  }

  const receipt = await store.save({
    state: parsed.state, // complete | partial | rejected
    mode: 'structured',
    product: descriptor.product,
    source: descriptor.entry,
    sourceVersion: source.etag,
    metadata: inspect(source.bytes),
    blobs: [blob],
    records: parsed.records,
    issues: parsed.issues,
    rootKey: parsed.rootKey,
    header: parsed.header,
    coverage: {
      ...parsed.coverage,
      downloadedBytes: source.bytes.length,
      blobDigest: blob.digest,
      sourceVersion: source.etag,
    },
  });
  return { receipt };
}
