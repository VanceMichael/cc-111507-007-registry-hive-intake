// REGF 蜂巢离线解析器：只做只读结构解释，不挂载、不执行、不回放事务日志。
// 所有单元引用均相对 4096 起始的 hive bin 区域；只沿声明的索引访问已分配单元，
// 不扫描空闲单元、不搜索相似标记、不恢复已删除记录。
import { createHash } from 'node:crypto';

export const HIVE_BIN_BASE = 0x1000;
const NONE_OFFSET = 0xffffffff;

const VALUE_TYPES = new Map([
  [0, 'REG_NONE'],
  [1, 'REG_SZ'],
  [2, 'REG_EXPAND_SZ'],
  [3, 'REG_BINARY'],
  [4, 'REG_DWORD'],
  [5, 'REG_DWORD_BIG_ENDIAN'],
  [6, 'REG_LINK'],
  [7, 'REG_MULTI_SZ'],
  [8, 'REG_RESOURCE_LIST'],
  [9, 'REG_FULL_RESOURCE_DESCRIPTOR'],
  [10, 'REG_RESOURCE_REQUIREMENTS_LIST'],
  [11, 'REG_QWORD'],
]);
const SUPPORTED_TYPES = new Set(['REG_NONE', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY',
  'REG_DWORD', 'REG_DWORD_BIG_ENDIAN', 'REG_MULTI_SZ', 'REG_QWORD']);

const INDEX_SIGNATURES = new Set(['li', 'lf', 'lh', 'ri']);
const KNOWN_SIGNATURES = new Set(['nk', 'vk', 'sk', 'db', 'li', 'lf', 'lh', 'ri']);

// 空引用哨兵：文档布局使用 0（首个 hbin 单元），经典/历史蜂巢使用 NONE(-1)。
const isNoneReference = (ref) => ref === NONE_OFFSET || ref === 0;

export function toHex(buffer) {
  return Buffer.from(buffer).toString('hex');
}

function decodeName(buffer, compressed) {
  return compressed ? buffer.toString('latin1') : buffer.toString('utf16le');
}

// REGF 解析错误：携带中文说明、代码与可定位位置。
export class HiveParseError extends Error {
  constructor(code, message, location = null, details = null) {
    super(message);
    this.name = 'HiveParseError';
    this.code = code;
    this.location = location;
    this.details = details;
  }
}

function issueFromError(error, scope) {
  return { code: error.code, message: error.message, location: error.location, scope, severity: 'gap' };
}

// 蜂巢视图：负责边界、单元归属和只读访问，任何越界或跨单元读取都会被拒绝。
class HiveView {
  constructor(bytes) {
    this.bytes = bytes;
    this.binsSize = 0;
    this.cellIndex = new Map(); // 单元相对偏移 -> { size, allocated, bin, sig, start }
  }

  u16(off) {
    if (off + 2 > this.bytes.length) throw new HiveParseError('TRUNCATED_FILE', '文件在读取字段时截断', { offset: off });
    return this.bytes.readUInt16LE(off);
  }

  u32(off) {
    if (off + 4 > this.bytes.length) throw new HiveParseError('TRUNCATED_FILE', '文件在读取字段时截断', { offset: off });
    return this.bytes.readUInt32LE(off);
  }

  i32(off) {
    if (off + 4 > this.bytes.length) throw new HiveParseError('TRUNCATED_FILE', '文件在读取字段时截断', { offset: off });
    return this.bytes.readInt32LE(off);
  }

  // 校验文件头并返回头部声明，不触碰 bins 内容。
  loadHeader() {
    const b = this.bytes;
    if (b.length < 512) throw new HiveParseError('TRUNCATED_FILE', '文件短于 REGF 基础头部，无法解释');
    if (b.subarray(0, 4).toString('latin1') !== 'regf') {
      throw new HiveParseError('BAD_SIGNATURE', '文件头不是 regf，不是 REGF 蜂巢', { offset: 0 });
    }
    const major = this.u32(0x14);
    const minor = this.u32(0x18);
    if (!(major === 1 && (minor === 3 || minor === 5))) {
      throw new HiveParseError('UNSUPPORTED_VERSION', `不支持的 REGF 版本 ${major}.${minor}，仅支持 1.3/1.5`, { offset: 0x14 });
    }
    const primarySequence = this.u32(0x04);
    const secondarySequence = this.u32(0x08);
    const rootCellOffset = this.u32(0x24);
    const binsSize = this.u32(0x28);
    let checksum = 0;
    for (let off = 0; off < 0x1fc; off += 4) checksum = (checksum ^ b.readUInt32LE(off)) >>> 0;
    const storedChecksum = this.u32(0x1fc);
    const checksumValid = checksum === storedChecksum;
    if (b.length < HIVE_BIN_BASE + binsSize) {
      throw new HiveParseError('TRUNCATED_BINS', '文件长度不足以容纳声明的 hive bins',
        { offset: 0x28, declaredBinsSize: binsSize });
    }
    this.binsSize = binsSize;
    return { major, minor, primarySequence, secondarySequence, rootCellOffset, binsSize,
      checksumValid, checksum: storedChecksum, calculatedChecksum: checksum,
      hiveFileName: b.subarray(0x30, 0x70).toString('utf16le').replace(/\u0000+$/u, '') };
  }

  // 顺序遍历 hbin，登记每个单元的边界（含空闲单元，但绝不读取其内容做恢复）。
  loadBins() {
    let binRel = 0;
    while (binRel < this.binsSize) {
      const binStart = HIVE_BIN_BASE + binRel;
      if (binStart + 32 > this.bytes.length) {
        throw new HiveParseError('TRUNCATED_BINS', 'hbin 头部超出文件范围', { hiveBinOffset: binRel });
      }
      if (this.bytes.subarray(binStart, binStart + 4).toString('latin1') !== 'hbin') {
        throw new HiveParseError('BAD_HBIN_SIGNATURE', 'hbin 签名无效', { hiveBinOffset: binRel });
      }
      const declaredRel = this.u32(binStart + 4);
      if (declaredRel !== binRel) {
        throw new HiveParseError('HBIN_OFFSET_MISMATCH', 'hbin 声明的相对偏移与其位置不一致',
          { hiveBinOffset: binRel, declaredOffset: declaredRel });
      }
      const size = this.u32(binStart + 8);
      if (size < 32 || (size & 7) !== 0 || binRel + size > this.binsSize) {
        throw new HiveParseError('BAD_HBIN_SIZE', 'hbin 大小无效或超出 bins 区域',
          { hiveBinOffset: binRel, size });
      }
      let cursor = binStart + 32;
      const binEnd = binStart + size;
      while (cursor < binEnd) {
        if (cursor + 4 > binEnd) {
          throw new HiveParseError('BAD_CELL_ALIGNMENT', '单元长度字段跨越 hbin 边界',
            { hiveBinOffset: binRel, cellOffset: cursor - HIVE_BIN_BASE });
        }
        const raw = this.i32(cursor);
        const cellSize = Math.abs(raw);
        if (cellSize < 4 || cellSize % 8 !== 0 || cursor + cellSize > binEnd) {
          throw new HiveParseError('BAD_CELL_SIZE', '单元大小无效、未按 8 字节对齐或跨越 hbin 边界',
            { hiveBinOffset: binRel, cellOffset: cursor - HIVE_BIN_BASE, cellSize: raw });
        }
        const rel = cursor - HIVE_BIN_BASE;
        const allocated = raw < 0;
        let sig = null;
        // 仅登记已知两字节签名；值列表等无签名单元保持 null，避免把计数字节误判成签名。
        if (allocated && cellSize >= 6) {
          const candidate = this.bytes.subarray(cursor + 4, cursor + 6).toString('latin1');
          if (KNOWN_SIGNATURES.has(candidate)) sig = candidate;
        }
        this.cellIndex.set(rel, { size: cellSize, allocated, bin: binRel, sig, start: cursor });
        cursor += cellSize;
      }
      binRel += size;
    }
  }

  referenceResolves(ref) {
    if (isNoneReference(ref)) return true;
    if (!Number.isInteger(ref) || ref < 0 || (ref & 7) !== 0) return false;
    const cell = this.cellIndex.get(ref);
    return Boolean(cell && cell.allocated);
  }

  referenceSignature(ref) {
    if (isNoneReference(ref)) return null;
    const cell = this.cellIndex.get(ref);
    return cell && cell.allocated ? cell.sig : null;
  }

  // 结构校验：无签名单元的数据区是否为 declaredCount 个连续、全部指向 vk 的引用。
  // 该值列表布局不内嵌数量，数量以 nk 声明为准，杜绝把首个引用低位误读为计数。
  valueListLooksValid(ref, declaredCount) {
    if (isNoneReference(ref)) return declaredCount === 0;
    if (!Number.isInteger(ref) || ref < 0 || (ref & 7) !== 0) return false;
    const cell = this.cellIndex.get(ref);
    if (!cell || !cell.allocated || cell.sig !== null) return false;
    if (!Number.isInteger(declaredCount) || declaredCount < 0 || declaredCount >= 0x100000) return false;
    if (cell.size - 4 < declaredCount * 4) return false;
    const dataStart = HIVE_BIN_BASE + ref + 4;
    for (let i = 0; i < declaredCount; i += 1) {
      if (this.referenceSignature(this.bytes.readUInt32LE(dataStart + i * 4)) !== 'vk') return false;
    }
    return true;
  }

  // 解析单元引用：必须落在已分配单元内，且请求读取长度不得跨出该单元。
  resolveCell(ref, neededLength, context) {
    if (!Number.isInteger(ref) || ref < 0 || ref >= this.binsSize) {
      return { error: new HiveParseError('OFFSET_OUT_OF_BOUNDS', '单元引用越界，无法确认该范围',
        { reference: ref, ...context }) };
    }
    const cell = this.cellIndex.get(ref);
    if (!cell) {
      return { error: new HiveParseError('OFFSET_NOT_CELL_ALIGNED', '单元引用未指向 8 字节对齐的单元起点',
        { reference: ref, ...context }) };
    }
    if (!cell.allocated) {
      return { error: new HiveParseError('REFERENCE_TO_FREE_CELL', '引用指向空闲单元，不恢复空闲残留',
        { reference: ref, ...context }) };
    }
    if (cell.size < neededLength + 4) {
      return { error: new HiveParseError('CELL_CROSS_READ', '读取范围跨越单元边界，拒绝跨单元读取',
        { reference: ref, cellSize: cell.size, neededLength: neededLength + 4, ...context }) };
    }
    return { cell, dataStart: HIVE_BIN_BASE + ref + 4 };
  }

  slice(dataStart, length) {
    return this.bytes.subarray(dataStart, dataStart + length);
  }
}

// 按声明类型解释值数据；EXPAND_SZ 只保留表达式不展开。
function decodeValue(typeName, data) {
  switch (typeName) {
    case 'REG_DWORD':
      if (data.length !== 4) return { value: toHex(data), valueEncoding: 'hex', valid: false, reason: 'DWORD 数据长度不是 4 字节' };
      return { value: data.readUInt32LE(0), valueEncoding: 'uint32-le', valid: true };
    case 'REG_DWORD_BIG_ENDIAN':
      if (data.length !== 4) return { value: toHex(data), valueEncoding: 'hex', valid: false, reason: 'DWORD_BIG_ENDIAN 数据长度不是 4 字节' };
      return { value: data.readUInt32BE(0), valueEncoding: 'uint32-be', valid: true };
    case 'REG_QWORD':
      if (data.length !== 8) return { value: toHex(data), valueEncoding: 'hex', valid: false, reason: 'QWORD 数据长度不是 8 字节' };
      return { value: data.readBigUInt64LE(0).toString(), valueEncoding: 'uint64-le', valid: true };
    case 'REG_SZ':
    case 'REG_EXPAND_SZ': {
      // 保留原始 UTF-16LE 表达，仅按声明编码解释文本；REG_EXPAND_SZ 不在本机展开。
      const text = data.toString('utf16le').replace(/\u0000+$/u, '');
      return { value: text, valueEncoding: 'utf16le', valid: true, expanded: false };
    }
    case 'REG_MULTI_SZ': {
      const tail = data.toString('utf16le').replace(/\u0000+$/u, '');
      const strings = tail.length === 0 ? [] : tail.split('\u0000');
      return { value: strings, valueEncoding: 'utf16le', valid: true, orderPreserved: true };
    }
    case 'REG_BINARY':
    case 'REG_NONE':
      return { value: toHex(data), valueEncoding: 'hex', valid: true };
    default:
      return { value: toHex(data), valueEncoding: 'hex', valid: false,
        reason: `支持范围外的值类型 ${typeName}，原字节保留可定位` };
  }
}

// 解释 db 分段大值：按段列表顺序拼接，任何一段不可达即整体未决。
function readBigData(view, dbDataStart, issueContext, issues) {
  const segmentCount = view.u32(dbDataStart + 4);
  const segmentListRef = view.u32(dbDataStart + 8);
  // 段列表单元无文本签名，数据区即 segmentCount 个连续 u32 段描述符引用。
  const list = view.resolveCell(segmentListRef, segmentCount * 4,
    { ...issueContext, purpose: 'db-segment-list' });
  if (list.error) { issues.push(issueFromError(list.error, 'big-data')); return null; }
  const parts = [];
  let total = 0;
  for (let i = 0; i < segmentCount; i += 1) {
    const segRef = view.u32(list.dataStart + i * 4);
    const seg = view.resolveCell(segRef, 8, { ...issueContext, purpose: 'db-segment', segmentIndex: i });
    if (seg.error) { issues.push(issueFromError(seg.error, 'big-data')); return null; }
    const segSize = view.u32(seg.dataStart);
    const segOffset = view.u32(seg.dataStart + 4);
    const payload = view.resolveCell(segOffset, segSize,
      { ...issueContext, purpose: 'db-segment-data', segmentIndex: i });
    if (payload.error) { issues.push(issueFromError(payload.error, 'big-data')); return null; }
    parts.push(view.slice(payload.dataStart, segSize));
    total += segSize;
  }
  return Buffer.concat(parts, total);
}

// 解析单个 vk 单元并形成可查询记录；证据不足时返回缺口而非猜测。
function readValue(view, vkRef, keyPath, keyCellRef, issues) {
  const vk = view.resolveCell(vkRef, 0x14, { purpose: 'vk', keyPath });
  if (vk.error) { issues.push(issueFromError(vk.error, 'value')); return null; }
  const d = vk.dataStart;
  if (view.bytes.subarray(d, d + 2).toString('latin1') !== 'vk') {
    issues.push({ code: 'BAD_CELL_SIGNATURE', message: '值列表指向的单元不是 vk',
      location: { reference: vkRef, keyPath }, scope: 'value', severity: 'gap' });
    return null;
  }
  const nameLength = view.u16(d + 2);
  const rawDataLength = view.u32(d + 4);
  const dataOffsetField = view.u32(d + 8);
  const dataType = view.u32(d + 0xc);
  const valueFlags = view.u16(d + 0x10);
  const inline = (rawDataLength & 0x80000000) !== 0;
  const dataLength = rawDataLength & 0x7fffffff;
  if (vk.cell.size < 4 + 0x14 + nameLength) {
    issues.push({ code: 'CELL_CROSS_READ', message: '值名长度跨越 vk 单元边界',
      location: { reference: vkRef, keyPath }, scope: 'value', severity: 'gap' });
    return null;
  }
  const compressedName = (valueFlags & 0x0001) !== 0;
  const valueName = nameLength === 0 ? '' : decodeName(view.slice(d + 0x14, nameLength), compressedName);
  const typeName = VALUE_TYPES.get(dataType) || `UNKNOWN_0x${dataType.toString(16)}`;
  const supportedType = SUPPORTED_TYPES.has(typeName);

  const baseRecord = {
    keyPath, valueName,
    valueNameEncoding: nameLength === 0 ? 'default' : (compressedName ? 'latin1' : 'utf16le'),
    type: typeName, keyCellOffset: keyCellRef, valueCellOffset: vkRef, inline,
    dataLocation: inline ? { kind: 'inline', offset: dataOffsetField } : null,
  };

  // 长度 0 是空数据（REG_NONE 语义），不能当成整数 0。
  if (dataLength === 0) {
    return { ...baseRecord, dataLocation: inline ? baseRecord.dataLocation : { kind: 'empty' },
      ...decodeValue(typeName, Buffer.alloc(0)), typeSupported: supportedType };
  }

  let data;
  if (inline) {
    if (dataLength > 4) {
      issues.push({ code: 'BAD_INLINE_LENGTH', message: '内联值声明长度超过 4 字节，无法确认',
        location: { reference: vkRef, keyPath, valueName }, scope: 'value', severity: 'gap' });
      return null;
    }
    // 内联数据放在 offset 字段的 4 字节内，长度不足 4 时使用低位字节。
    data = view.bytes.subarray(d + 8, d + 8 + dataLength);
  } else {
    const target = view.resolveCell(dataOffsetField, 4, { purpose: 'value-data', keyPath, valueName });
    if (target.error) {
      issues.push({ ...issueFromError(target.error, 'value'),
        location: { ...target.error.location, keyPath, valueName } });
      return null;
    }
    if (target.cell.sig === 'db') {
      const db = view.resolveCell(dataOffsetField, 12, { purpose: 'db', keyPath, valueName });
      if (db.error) { issues.push(issueFromError(db.error, 'big-data')); return null; }
      data = readBigData(view, db.dataStart, { reference: dataOffsetField, keyPath, valueName }, issues);
      if (!data) return null;
      baseRecord.dataLocation = { kind: 'big-data', dbCellOffset: dataOffsetField };
      if (data.length !== dataLength) {
        issues.push({ code: 'BIG_DATA_LENGTH_MISMATCH',
          message: '分段大值拼接长度与 vk 声明长度不一致，按已拼接字节保留并标记未决',
          location: { reference: dataOffsetField, keyPath, valueName, declared: dataLength, actual: data.length },
          scope: 'value', severity: 'gap' });
      }
      data = data.subarray(0, Math.min(data.length, dataLength));
    } else {
      const sized = view.resolveCell(dataOffsetField, dataLength,
        { purpose: 'value-data', keyPath, valueName });
      if (sized.error) {
        issues.push({ ...issueFromError(sized.error, 'value'),
          location: { ...sized.error.location, keyPath, valueName } });
        return null;
      }
      data = view.slice(sized.dataStart, dataLength);
      baseRecord.dataLocation = { kind: 'external', cellOffset: dataOffsetField };
    }
  }
  if (data.length !== dataLength) {
    issues.push({ code: 'VALUE_DATA_TRUNCATED', message: '值数据实际长度短于 vk 声明长度',
      location: { reference: vkRef, keyPath, valueName, declared: dataLength, actual: data.length },
      scope: 'value', severity: 'gap' });
  }
  return { ...baseRecord, ...decodeValue(typeName, data), typeSupported: supportedType };
}

// 解析值列表：数据区为 declaredCount 个连续 u32 vk 引用（无内嵌数量），顺序不作为身份。
function readValues(view, listRef, declaredCount, keyPath, keyCellRef, issues) {
  if (isNoneReference(listRef)) return [];
  const list = view.resolveCell(listRef, declaredCount * 4, { purpose: 'value-list', keyPath });
  if (list.error) { issues.push(issueFromError(list.error, 'value-list')); return []; }
  const records = [];
  for (let i = 0; i < declaredCount; i += 1) {
    const vkRef = view.u32(list.dataStart + i * 4);
    const record = readValue(view, vkRef, keyPath, keyCellRef, issues);
    if (record) records.push(record);
  }
  return records;
}

// 沿 li/lf/lh/ri 索引收集子键引用；ri 递归展开，其他索引直接领取。
function readIndex(view, indexRef, issues, contextPath) {
  const seen = new Set();
  const refs = [];
  const stack = [indexRef];
  while (stack.length) {
    const ref = stack.pop();
    if (isNoneReference(ref)) continue;
    if (seen.has(ref)) {
      issues.push({ code: 'INDEX_CYCLE', message: '子键索引内部出现循环，重复分支不再展开',
        location: { reference: ref, keyPath: contextPath }, scope: 'subkey-index', severity: 'gap' });
      continue;
    }
    seen.add(ref);
    const probe = view.resolveCell(ref, 6, { purpose: 'subkey-index', keyPath: contextPath });
    if (probe.error) { issues.push(issueFromError(probe.error, 'subkey-index')); continue; }
    const sig = view.bytes.subarray(probe.dataStart, probe.dataStart + 2).toString('latin1');
    if (!INDEX_SIGNATURES.has(sig)) {
      issues.push({ code: 'BAD_INDEX_SIGNATURE',
        message: `子键索引单元签名为 ${sig}，不是 li/lf/lh/ri`,
        location: { reference: ref, keyPath: contextPath }, scope: 'subkey-index', severity: 'gap' });
      continue;
    }
    const count = view.u16(probe.dataStart + 2);
    const full = view.resolveCell(ref, 4 + count * 4, { purpose: 'subkey-index', keyPath: contextPath });
    if (full.error) { issues.push(issueFromError(full.error, 'subkey-index')); continue; }
    for (let i = 0; i < count; i += 1) {
      const entryBase = full.dataStart + 4 + i * 4;
      if (sig === 'li') {
        // li 条目直接是 nk 偏移。
        refs.push(view.u32(entryBase));
      } else if (sig === 'ri') {
        // ri 条目指向下一层 li/lf/lh/ri 索引。
        stack.push(view.u32(entryBase));
      } else {
        // lf/lh 条目为 4 字节 hash + 4 字节 nk 偏移；lh 的偏移高位还带 hash 标志，需掩码。
        const nkOffset = sig === 'lh' ? (view.u32(entryBase + 4) & 0x0fffffff)
          : view.u32(entryBase + 4);
        refs.push(nkOffset);
      }
    }
  }
  return refs;
}

// NK 字段布局有两类，差异在 0x10-0x28 段的计数/引用顺序。
// classic：子键/易失计数为 u32（0xffffffff 为空哨兵），值数量为 data+0x24 的 2 字节，
//          值列表引用位于 data+0x28。
// documented：引用在前，值列表位于 data+0x20，值数量为 data+0x24 的 4 字节，sk 在 data+0x28。
// 用“候选值列表引用是否真的指向条目全为 vk 的无签名单元”这一结构证据判别，不靠猜测。
const NK_LAYOUTS = {
  classic: {
    subCount: 0x10, subList: 0x14, volCount: 0x18, volList: 0x1c,
    valueCount: 0x24, valueList: 0x28, sk: null, valueCountIsU16: true,
  },
  documented: {
    subList: 0x10, subCount: 0x14, volList: 0x18, volCount: 0x1c,
    valueList: 0x20, valueCount: 0x24, sk: 0x28, valueCountIsU16: false,
  },
};

function detectNkLayout(view, d) {
  const evaluate = (layout) => {
    // 子键/易失计数始终是 u32，哨兵归一化；值计数按布局声明的宽度读取。
    const readKeyCount = (offset) => {
      const value = view.u32(d + offset);
      return value === NONE_OFFSET ? 0 : value;
    };
    const readValueCount = (offset) => {
      if (layout.valueCountIsU16) {
        const value = view.u16(d + offset);
        return value === 0xffff ? 0 : value;
      }
      const value = view.u32(d + offset);
      return value === NONE_OFFSET ? 0 : value;
    };
    const subList = view.u32(d + layout.subList);
    const volList = view.u32(d + layout.volList);
    const valueList = view.u32(d + layout.valueList);
    const valueCount = readValueCount(layout.valueCount);
    const subCount = readKeyCount(layout.subCount);
    const volCount = readKeyCount(layout.volCount);

    let feasible = true;
    let score = 0;
    for (const ref of [subList, volList]) {
      if (!view.referenceResolves(ref)) feasible = false;
      else score += 2;
    }
    for (const count of [subCount, volCount, valueCount]) {
      if (!Number.isInteger(count) || count < 0 || count >= 0x100000) feasible = false;
      else score += 1;
    }
    // 决定性结构证据。
    if (!view.valueListLooksValid(valueList, valueCount)) feasible = false;
    else score += 6;
    const indexSig = view.referenceSignature(subList);
    if (indexSig !== null && !INDEX_SIGNATURES.has(indexSig)) feasible = false;
    for (const [count, list] of [[subCount, subList], [volCount, volList]]) {
      if ((count > 0) === !isNoneReference(list)) score += 2;
    }
    if ((valueCount > 0) === !isNoneReference(valueList)) score += 2;
    return { feasible, score };
  };
  const classic = evaluate(NK_LAYOUTS.classic);
  const documented = evaluate(NK_LAYOUTS.documented);
  if (classic.feasible && !documented.feasible) return NK_LAYOUTS.classic;
  if (documented.feasible && !classic.feasible) return NK_LAYOUTS.documented;
  return classic.score >= documented.score ? NK_LAYOUTS.classic : NK_LAYOUTS.documented;
}

// 从文件声明的根键出发，沿有效索引遍历可达键值；visited 防止键图循环导致重复或死循环。
function traverse(view, rootRef, issues) {
  const records = [];
  const visitedKeys = new Set();
  const stack = [{ ref: rootRef, path: null, parentRef: null }];
  let rootKey = null;
  while (stack.length) {
    const { ref, path, parentRef } = stack.pop();
    if (visitedKeys.has(ref)) {
      issues.push({ code: 'KEY_CYCLE',
        message: '子键遍历回到已访问的键单元，存在循环；该分支标记未决且不重复计数',
        location: { reference: ref, keyPath: path }, scope: 'subkey', severity: 'gap' });
      continue;
    }
    const nk = view.resolveCell(ref, 0x4c + 4, { purpose: 'nk', keyPath: path || '<root>' });
    if (nk.error) { issues.push(issueFromError(nk.error, 'key')); continue; }
    const d = nk.dataStart;
    if (view.bytes.subarray(d, d + 2).toString('latin1') !== 'nk') {
      issues.push({ code: 'BAD_CELL_SIGNATURE', message: '索引指向的单元不是 nk',
        location: { reference: ref, keyPath: path || '<root>' }, scope: 'key', severity: 'gap' });
      continue;
    }
    const flags = view.u16(d + 2);
    const layout = detectNkLayout(view, d);
    // 子键/易失计数为 u32 并归一化哨兵；值计数按布局宽度读取。
    const readKeyCount = (offset) => {
      const value = view.u32(d + offset);
      return value === NONE_OFFSET ? 0 : value;
    };
    const readValueCount = (offset) => {
      if (layout.valueCountIsU16) {
        const value = view.u16(d + offset);
        return value === 0xffff ? 0 : value;
      }
      const value = view.u32(d + offset);
      return value === NONE_OFFSET ? 0 : value;
    };
    const subkeyCount = readKeyCount(layout.subCount);
    const subkeyListRef = view.u32(d + layout.subList);
    const volatileCount = readKeyCount(layout.volCount);
    const volatileListRef = view.u32(d + layout.volList);
    const valueCount = readValueCount(layout.valueCount);
    const valueListRef = view.u32(d + layout.valueList);
    const securityRef = layout.sk === null ? NONE_OFFSET : view.u32(d + layout.sk);
    const nameLength = view.u16(d + 0x48);
    if (nk.cell.size < 4 + 0x4c + nameLength) {
      issues.push({ code: 'CELL_CROSS_READ', message: '键名长度跨越 nk 单元边界',
        location: { reference: ref, keyPath: path || '<root>' }, scope: 'key', severity: 'gap' });
      continue;
    }
    const compressedKeyName = (flags & 0x20) !== 0;
    const keyName = decodeName(view.slice(d + 0x4c, nameLength), compressedKeyName);
    const keyPath = path === null ? keyName : `${path}\\${keyName}`;
    visitedKeys.add(ref);
    const keyInfo = {
      keyPath, keyCellOffset: ref, parentCellOffset: parentRef,
      keyNameEncoding: compressedKeyName ? 'latin1' : 'utf16le',
      subkeyCount, volatileSubkeyCount: volatileCount, valueCount,
      securityCellOffset: isNoneReference(securityRef) ? null : securityRef,
    };
    if (path === null) rootKey = keyInfo;

    // sk 安全描述符内容按范围忽略，只保留引用证据。
    if (!isNoneReference(securityRef)) {
      const sk = view.resolveCell(securityRef, 4, { purpose: 'sk-reference', keyPath });
      if (sk.error) {
        issues.push({ ...issueFromError(sk.error, 'security'),
          location: { ...sk.error.location, keyPath } });
      }
    }

    const values = readValues(view, valueListRef, valueCount, keyPath, ref, issues);
    if (values.length !== valueCount) {
      issues.push({ code: 'VALUE_COUNT_MISMATCH',
        message: '可确认值数量与 nk 声明不一致，缺失范围保持未决（不当作空键）',
        location: { reference: ref, keyPath, declared: valueCount, confirmed: values.length },
        scope: 'value-list', severity: 'gap' });
    }
    for (const record of values) records.push(record);

    const childRefs = [];
    if (subkeyCount > 0 || !isNoneReference(subkeyListRef)) {
      if (isNoneReference(subkeyListRef)) {
        issues.push({ code: 'MISSING_INDEX',
          message: 'nk 声明存在稳定子键但未给出索引，子键范围未决（不当作空键）',
          location: { reference: ref, keyPath, declared: subkeyCount },
          scope: 'subkey-index', severity: 'gap' });
      } else if (subkeyListRef === ref || visitedKeys.has(subkeyListRef)) {
        issues.push({ code: 'KEY_CYCLE',
          message: '子键索引直接回到当前或已访问的键单元，存在自引用循环；该子键范围未决',
          location: { reference: subkeyListRef, keyPath }, scope: 'subkey-index', severity: 'gap' });
      } else if (!Number.isInteger(subkeyListRef) || (subkeyListRef & 7) !== 0
        || !view.referenceResolves(subkeyListRef)) {
        issues.push({ code: 'OFFSET_OUT_OF_BOUNDS',
          message: '子键索引引用越界或未指向 8 字节对齐单元，子键范围未决（不搜索邻近标记补齐）',
          location: { reference: subkeyListRef, keyPath, declared: subkeyCount },
          scope: 'subkey-index', severity: 'gap' });
      } else {
        const targetSig = view.referenceSignature(subkeyListRef);
        if (targetSig === 'nk') {
          // 索引槽直接指向一个 nk（而非 li/lf/lh/ri），且该 nk 已在当前路径上即构成循环。
          issues.push({ code: 'KEY_CYCLE',
            message: '子键索引指向键单元而非索引单元，键图存在循环；该子键范围未决',
            location: { reference: subkeyListRef, keyPath }, scope: 'subkey-index', severity: 'gap' });
        } else {
          childRefs.push(...readIndex(view, subkeyListRef, issues, keyPath));
        }
      }
    }
    if (volatileCount > 0) {
      if (isNoneReference(volatileListRef)) {
        issues.push({ code: 'MISSING_INDEX',
          message: 'nk 声明存在易失子键但未给出索引，子键范围未决（不当作空键）',
          location: { reference: ref, keyPath, declared: volatileCount },
          scope: 'subkey-index', severity: 'gap' });
      } else {
        issues.push({ code: 'VOLATILE_SUBKEYS_PRESENT',
          message: '蜂巢声明易失子键；离线快照中该范围不具持久配置语义，标记未决',
          location: { reference: ref, keyPath }, scope: 'subkey-index', severity: 'gap' });
      }
    }
    for (const childRef of childRefs) stack.push({ ref: childRef, path: keyPath, parentRef: ref });
  }
  return { records, rootKey };
}

// 稳定身份：键路径 + 值名 + 来源单元位置，不使用数组下标。
function recordIdentity(source, record) {
  const basis = JSON.stringify([source, record.keyPath, record.valueName,
    record.keyCellOffset, record.valueCellOffset]);
  return createHash('sha256').update(basis).digest('hex').slice(0, 32);
}

// 解析入口：返回状态、记录、缺口与覆盖说明；调用方保留原始字节作为证据。
export function parseHive(bytes, sourceName = 'hive') {
  const issues = [];
  const view = new HiveView(bytes);
  const header = view.loadHeader();
  view.loadBins();

  if (!header.checksumValid) {
    issues.push({ code: 'CHECKSUM_MISMATCH', message: 'REGF 头部 XOR32 校验不通过，头部完整性无法确认',
      location: { offset: 0x1fc, stored: header.checksum, calculated: header.calculatedChecksum },
      scope: 'header', severity: 'gap' });
  }
  const synchronized = header.primarySequence === header.secondarySequence;
  if (!synchronized) {
    issues.push({ code: 'SEQUENCE_MISMATCH',
      message: '主/次序列号不一致，文件不是已同步快照，结构结果仅作未同步证据',
      location: { offset: 0x04, primary: header.primarySequence, secondary: header.secondarySequence },
      scope: 'header', severity: 'gap' });
  }

  const rootProbe = view.resolveCell(header.rootCellOffset, 0x50, { purpose: 'root-nk' });
  if (rootProbe.error) {
    issues.push(issueFromError(rootProbe.error, 'root'));
    return finalize({ header, synchronized, issues, records: [], rootKey: null, sourceName, bytes, fatal: true });
  }
  if (rootProbe.cell.sig !== 'nk') {
    issues.push({ code: 'BAD_ROOT_SIGNATURE',
      message: `根单元签名为 ${rootProbe.cell.sig}，不是 nk`,
      location: { reference: header.rootCellOffset }, scope: 'root', severity: 'gap' });
    return finalize({ header, synchronized, issues, records: [], rootKey: null, sourceName, bytes, fatal: true });
  }

  const { records, rootKey } = traverse(view, header.rootCellOffset, issues);
  return finalize({ header, synchronized, issues, records, rootKey, sourceName, bytes, fatal: false });
}

function finalize({ header, synchronized, issues, records, rootKey, sourceName, bytes, fatal }) {
  const digest = createHash('sha256').update(bytes).digest('hex');
  const stableRecords = records.map(record => ({
    id: recordIdentity(sourceName, record),
    ...record,
    valid: record.valid !== false,
    source: sourceName,
  }));
  let state = 'complete';
  if (fatal || !rootKey) state = 'rejected';
  else if (issues.length > 0 || stableRecords.some(r => !r.valid || !r.typeSupported)) state = 'partial';
  return {
    state,
    records: stableRecords,
    issues,
    rootKey,
    header: {
      format: 'REGF',
      version: `${header.major}.${header.minor}`,
      primarySequence: header.primarySequence,
      secondarySequence: header.secondarySequence,
      synchronized,
      rootCellOffset: header.rootCellOffset,
      binsSize: header.binsSize,
      checksumValid: header.checksumValid,
      hiveFileName: header.hiveFileName,
    },
    coverage: {
      structured: true,
      source: sourceName,
      sourceBytes: bytes.length,
      sourceSha256: digest,
      recordCount: stableRecords.length,
      validRecordCount: stableRecords.filter(r => r.valid && r.typeSupported).length,
      issueCount: issues.length,
      synchronized,
      traversal: rootKey ? 'root-reachable-only' : 'unavailable',
      freeCellsScanned: false,
      deletedRecovered: false,
      environmentExpanded: false,
      credentialExtraction: false,
    },
  };
}
