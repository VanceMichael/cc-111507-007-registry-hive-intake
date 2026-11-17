// 测试辅助：在内存中按 classic NK 字段布局合成 REGF 蜂巢，覆盖 fixtures 未包含的
// 多类型值、子键索引（li/ri）、db 分段大值与 UTF-16 名称。仅用于单元测试，不接触 fixtures。
const BASE = 0x1000;
const NONE = 0xffffffff;
const align8 = (n) => (n + 7) & ~7;
// 构造一个已分配单元的完整字节（含 4 字节负长度）。
function allocatedCell(body) {
  const size = align8(4 + body.length);
  const buf = Buffer.alloc(size);
  buf.writeInt32LE(-size, 0);
  body.copy(buf, 4);
  return buf;
}

// vk 单元（external 数据偏移由 patch 回填）。
function vkCell({ name, type, dataLength, inlineData = null, dataOffset = 0, compressedName = true }) {
  const nameBuf = compressedName ? Buffer.from(name, 'latin1') : Buffer.from(name, 'utf16le');
  const body = Buffer.alloc(0x14 + nameBuf.length);
  body.write('vk', 0, 'latin1');
  body.writeUInt16LE(nameBuf.length, 2);
  const lengthField = inlineData !== null ? (dataLength | 0x80000000) >>> 0 : dataLength;
  body.writeUInt32LE(lengthField, 4);
  if (inlineData !== null) inlineData.copy(body, 8, 0, Math.min(4, dataLength));
  else body.writeUInt32LE(dataOffset, 8);
  body.writeUInt32LE(type, 0xc);
  body.writeUInt16LE(compressedName ? 1 : 0, 0x10);
  nameBuf.copy(body, 0x14);
  return allocatedCell(body);
}

function dataCell(data) {
  return allocatedCell(Buffer.from(data));
}

// nk 单元（classic 布局）。
function nkCell({ name, flags, subCount = 0, subList = 0, volCount = 0, volList = NONE,
  valueCount = 0, valueList = 0, compressed = true }) {
  const nameBuf = compressed ? Buffer.from(name, 'latin1') : Buffer.from(name, 'utf16le');
  const effectiveFlags = flags ?? (compressed ? 0x20 : 0x00);
  const body = Buffer.alloc(0x4c + nameBuf.length);
  body.write('nk', 0, 'latin1');
  body.writeUInt16LE(effectiveFlags, 2);
  body.writeUInt32LE(subCount === 0 ? NONE : subCount, 0x10);
  body.writeUInt32LE(subList, 0x14);
  body.writeUInt32LE(volCount === 0 ? 0 : volCount, 0x18);
  body.writeUInt32LE(volList, 0x1c);
  body.writeUInt16LE(valueCount, 0x24);
  body.writeUInt32LE(valueList, 0x28);
  body.writeUInt16LE(nameBuf.length, 0x48);
  nameBuf.copy(body, 0x4c);
  return allocatedCell(body);
}

// 值列表单元：连续 count 个 u32 vk 引用（无内嵌数量）。
function valueListCell(vkRefs) {
  const body = Buffer.alloc(vkRefs.length * 4);
  vkRefs.forEach((ref, i) => body.writeUInt32LE(ref, i * 4));
  return allocatedCell(body);
}

// li 索引单元。
function liCell(childRefs) {
  const body = Buffer.alloc(4 + childRefs.length * 4);
  body.write('li', 0, 'latin1');
  body.writeUInt16LE(childRefs.length, 2);
  childRefs.forEach((ref, i) => body.writeUInt32LE(ref, 4 + i * 4));
  return allocatedCell(body);
}

// 把若干单元顺序排布进单个 hbin，尾部用一个空闲单元填满，返回 { bytes, refs }。
function assemble(cells, { rootCellOffset, primary = 7, secondary = 7, binsSize = 4096 }) {
  const file = Buffer.alloc(BASE + binsSize);
  file.write('regf', 0, 'latin1');
  file.writeUInt32LE(primary, 0x04);
  file.writeUInt32LE(secondary, 0x08);
  file.writeUInt32LE(1, 0x14);
  file.writeUInt32LE(5, 0x18);
  file.writeUInt32LE(rootCellOffset, 0x24);
  file.writeUInt32LE(binsSize, 0x28);
  file.writeUInt32LE(1, 0x2c);
  let checksum = 0;
  for (let off = 0; off < 0x1fc; off += 4) checksum = (checksum ^ file.readUInt32LE(off)) >>> 0;
  file.writeUInt32LE(checksum, 0x1fc);
  file.write('hbin', BASE, 'latin1');
  file.writeUInt32LE(0, BASE + 4);
  file.writeUInt32LE(binsSize, BASE + 8);
  let cursor = BASE + 0x20;
  const refs = [];
  for (const cell of cells) {
    cell.copy(file, cursor);
    refs.push(cursor - BASE);
    cursor += cell.length;
  }
  // 尾部空闲单元：正长度，内容保持零（模拟空闲残留，解析器不得读取其内容）。
  const freeSize = binsSize - (cursor - BASE);
  if (freeSize >= 8) {
    file.writeInt32LE(freeSize, cursor); // 正长度表示空闲
  }
  return { bytes: file, refs, used: cursor - BASE };
}

export {
  allocatedCell, vkCell, dataCell, nkCell, valueListCell, liCell, assemble,
};

// 两阶段构建器：先 push 占位单元并计算 8 字节对齐偏移，再在 cell 缓冲上回填，
// 最后 assemble。避免“先复制后回填导致修改丢失”的问题。
export class HiveAssembler {
  constructor() {
    this.entries = []; // { cell, rel }
    this.nextRel = 0x20;
  }

  add(cell) {
    const rel = this.nextRel;
    this.entries.push({ cell, rel });
    this.nextRel += cell.length; // allocatedCell 已保证长度为 8 的倍数
    return rel;
  }

  // 在指定单元的数据区（跳过 4 字节长度头）写 u32。
  patchU32(rel, dataOffset, value) {
    const entry = this.entries.find(e => e.rel === rel);
    if (!entry) throw new Error(`未知单元偏移 ${rel}`);
    entry.cell.writeUInt32LE(value, 4 + dataOffset);
  }

  assemble(options) {
    const cells = this.entries.map(e => e.cell);
    const refs = this.entries.map(e => e.rel);
    const result = assemble(cells, { ...options, rootCellOffset: options.rootCellOffset });
    // assemble 重新计算的 refs 应与登记的 rel 一致。
    for (let i = 0; i < refs.length; i += 1) {
      if (refs[i] !== result.refs[i]) throw new Error('单元布局偏移不一致');
    }
    return result.bytes;
  }
}
