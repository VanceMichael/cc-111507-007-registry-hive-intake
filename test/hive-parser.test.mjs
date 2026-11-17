import test from 'node:test';
import assert from 'node:assert/strict';
import {
  HiveAssembler, vkCell, dataCell, nkCell, valueListCell, liCell, allocatedCell,
} from './hive-builder.mjs';
import { parseHive } from '../src/hive-parser.mjs';

// 验证全部受支持值类型在同一蜂巢中形成同构可查询记录，且环境字符串不展开。
test('合成蜂巢：八类值类型、内联/外置与来源位置均可查询', () => {
  const asm = new HiveAssembler();
  const dword = Buffer.alloc(4); dword.writeUInt32LE(1234, 0);
  const dwordBe = Buffer.from([0x12, 0x34, 0x56, 0x78]);
  const qword = Buffer.alloc(8); qword.writeBigUInt64LE(1234567890123n, 0);
  const sz = Buffer.from('标签\0', 'utf16le');
  const expand = Buffer.from('%SYNTH_ROOT%\\app\0', 'utf16le');
  const multi = Buffer.from('alpha\0beta\0\0', 'utf16le');
  const binary = Buffer.from([0xde, 0xad, 0xbe, 0xef]);

  const specs = [
    { name: 'Dword', type: 4, data: dword, inline: true, expect: 1234, expectType: 'REG_DWORD' },
    { name: 'DwordBe', type: 5, data: dwordBe, expect: 0x12345678, expectType: 'REG_DWORD_BIG_ENDIAN' },
    { name: 'Qword', type: 11, data: qword, expect: '1234567890123', expectType: 'REG_QWORD' },
    { name: 'Sz', type: 1, data: sz, expect: '标签', expectType: 'REG_SZ' },
    { name: 'Expand', type: 2, data: expand, expect: '%SYNTH_ROOT%\\app', expectType: 'REG_EXPAND_SZ' },
    { name: 'Multi', type: 7, data: multi, expect: ['alpha', 'beta'], expectType: 'REG_MULTI_SZ' },
    { name: 'Binary', type: 3, data: binary, expect: 'deadbeef', expectType: 'REG_BINARY' },
  ];
  const dataRefs = specs.map(s => asm.add(dataCell(s.data)));
  const vkRefs = specs.map((s, i) => asm.add(vkCell({
    name: s.name, type: s.type, dataLength: s.data.length,
    inlineData: s.inline ? s.data : null, dataOffset: 0,
  })));
  const noneRef = asm.add(vkCell({ name: 'None', type: 0, dataLength: 0 }));
  const listRef = asm.add(valueListCell(new Array(specs.length + 1).fill(0)));
  const rootRef = asm.add(nkCell({ name: 'Root', valueCount: specs.length + 1 }));

  specs.forEach((s, i) => { if (!s.inline) asm.patchU32(vkRefs[i], 8, dataRefs[i]); });
  [...vkRefs, noneRef].forEach((ref, i) => asm.patchU32(listRef, i * 4, ref));
  asm.patchU32(rootRef, 0x28, listRef);

  const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'types.hive');
  assert.equal(result.state, 'complete');
  assert.equal(result.records.length, specs.length + 1);
  const byName = new Map(result.records.map(r => [r.valueName, r]));
  for (const s of specs) {
    const rec = byName.get(s.name);
    assert.ok(rec, `缺少值 ${s.name}`);
    assert.equal(rec.type, s.expectType);
    assert.deepEqual(rec.value, s.expect);
    assert.equal(rec.valid, true);
    assert.equal(typeof rec.valueCellOffset, 'number');
    assert.equal(rec.keyPath, 'Root');
  }
  // EXPAND_SZ 只保留表达，不展开环境变量。
  assert.equal(byName.get('Expand').expanded, false);
  assert.match(byName.get('Expand').value, /^%SYNTH_ROOT%/);
  // MULTI_SZ 保留顺序。
  assert.deepEqual(byName.get('Multi').value, ['alpha', 'beta']);
  assert.equal(byName.get('Multi').orderPreserved, true);
  // 长度 0 的 REG_NONE 不被当成整数 0，而是空数据。
  assert.equal(byName.get('None').dataLocation.kind, 'empty');
  assert.equal(byName.get('None').value, '');
  // 内联与外置的来源位置区分。
  assert.equal(byName.get('Dword').inline, true);
  assert.equal(byName.get('Sz').inline, false);
  assert.equal(byName.get('Sz').dataLocation.kind, 'external');
});

// 验证 lf（hash+偏移）与 ri（多层）索引都能沿有效引用到达子键值。
test('合成蜂巢：lf 哈希索引与 ri 多层索引正确遍历', () => {
  const buildChild = (asm, leafName) => {
    const d = Buffer.alloc(4); d.writeUInt32LE(9, 0);
    const dataRef = asm.add(dataCell(d));
    const vkRef = asm.add(vkCell({ name: leafName, type: 4, dataLength: 4, dataOffset: 0 }));
    const listRef = asm.add(valueListCell([0]));
    const nkRef = asm.add(nkCell({ name: leafName, valueCount: 1 }));
    asm.patchU32(vkRef, 8, dataRef);
    asm.patchU32(listRef, 0, vkRef);
    asm.patchU32(nkRef, 0x28, listRef);
    return nkRef;
  };

  // lf：条目为 4 字节 hash + 4 字节 nk 偏移，hash 不得被当成偏移。
  {
    const asm = new HiveAssembler();
    const childRef = buildChild(asm, 'L');
    const body = Buffer.alloc(4 + 8);
    body.write('lf', 0, 'latin1');
    body.writeUInt16LE(1, 2);
    body.writeUInt32LE(0xdeadbeef, 4);
    body.writeUInt32LE(childRef, 8);
    const lfRef = asm.add(allocatedCell(body));
    const rootRef = asm.add(nkCell({ name: 'Root', subCount: 1, subList: 0 }));
    asm.patchU32(rootRef, 0x14, lfRef);
    const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'lf.hive');
    assert.equal(result.state, 'complete');
    assert.equal(result.records[0].keyPath, 'Root\\L');
  }

  // ri：ri 单元指向 li，li 再指向 nk。
  {
    const asm = new HiveAssembler();
    const childRef = buildChild(asm, 'R');
    const liRef = asm.add(liCell([0]));
    asm.patchU32(liRef, 4, childRef);
    const riBody = Buffer.alloc(4 + 4);
    riBody.write('ri', 0, 'latin1');
    riBody.writeUInt16LE(1, 2);
    riBody.writeUInt32LE(liRef, 4);
    const riRef = asm.add(allocatedCell(riBody));
    const rootRef = asm.add(nkCell({ name: 'Root', subCount: 1, subList: 0 }));
    asm.patchU32(rootRef, 0x14, riRef);
    const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'ri.hive');
    assert.equal(result.state, 'complete');
    assert.equal(result.records[0].keyPath, 'Root\\R');
  }
});

// 验证 ri 索引自引用形成循环时被识别为缺口，不进入死循环。
test('合成蜂巢：ri 自引用循环被识别且不重复计数', () => {
  const asm = new HiveAssembler();
  const riBody = Buffer.alloc(4 + 4);
  riBody.write('ri', 0, 'latin1');
  riBody.writeUInt16LE(1, 2);
  const riRef = asm.add(allocatedCell(riBody)); // 先占位拿偏移
  asm.patchU32(riRef, 4, riRef); // 自引用
  const rootRef = asm.add(nkCell({ name: 'Root', subCount: 1, subList: 0 }));
  asm.patchU32(rootRef, 0x14, riRef);
  const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'ri-cycle.hive');
  assert.equal(result.state, 'partial');
  assert.ok(result.issues.some(i => i.code === 'INDEX_CYCLE' || i.code === 'KEY_CYCLE'));
});

// 验证解析器对畸形计数与越界偏移的健壮性：不越界读取、不崩溃、形成可定位缺口或拒绝。
test('合成蜂巢：畸形计数与越界根偏移被安全拒绝', () => {
  // 声明 60000 个值但列表单元仅一个条目：跨单元读取被拒，不越界。
  {
    const asm = new HiveAssembler();
    const d = Buffer.alloc(4);
    const dataRef = asm.add(dataCell(d));
    const vkRef = asm.add(vkCell({ name: 'X', type: 4, dataLength: 4, dataOffset: 0 }));
    const listRef = asm.add(valueListCell([vkRef]));
    const rootRef = asm.add(nkCell({ name: 'Root', valueCount: 60000 }));
    asm.patchU32(vkRef, 8, dataRef);
    asm.patchU32(rootRef, 0x28, listRef);
    const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'huge.hive');
    assert.equal(result.state, 'partial');
    assert.ok(result.issues.some(i => i.code === 'CELL_CROSS_READ'));
  }

  // 根偏移指向 bins 内但非单元起点 -> rejected。
  {
    const asm = new HiveAssembler();
    const rootRef = asm.add(nkCell({ name: 'Root' }));
    const bytes = asm.assemble({ rootCellOffset: rootRef });
    bytes.writeUInt32LE(4000, 0x24);
    const result = parseHive(bytes, 'misaligned-root.hive');
    assert.equal(result.state, 'rejected');
    assert.ok(result.issues.some(i => i.code === 'OFFSET_NOT_CELL_ALIGNED'));
  }

  // 根偏移完全超出 bins -> rejected。
  {
    const asm = new HiveAssembler();
    const rootRef = asm.add(nkCell({ name: 'Root' }));
    const bytes = asm.assemble({ rootCellOffset: rootRef });
    bytes.writeUInt32LE(0xfffffffc, 0x24);
    const result = parseHive(bytes, 'far-root.hive');
    assert.equal(result.state, 'rejected');
    assert.ok(result.issues.some(i => i.code === 'OFFSET_OUT_OF_BOUNDS'));
  }

  // 非 regf 魔数与过短文件抛出可读中文错误，不产生越界读取。
  assert.throws(() => parseHive(Buffer.from([1, 2, 3]), 'tiny.hive'), /无法解释/);
  const badMagic = Buffer.alloc(8192);
  badMagic.write('xxxx', 0, 'latin1');
  assert.throws(() => parseHive(badMagic, 'bad-magic.hive'), /regf/);
});

// 验证 li 子键索引沿有效引用遍历，键路径可追溯。
test('合成蜂巢：li 子键索引沿有效引用到达子键值', () => {
  const asm = new HiveAssembler();
  const childData = Buffer.alloc(4); childData.writeUInt32LE(7, 0);
  const childDataRef = asm.add(dataCell(childData));
  const childVkRef = asm.add(vkCell({ name: 'Leaf', type: 4, dataLength: 4, dataOffset: 0 }));
  const childListRef = asm.add(valueListCell([0]));
  const childNkRef = asm.add(nkCell({ name: 'Child', valueCount: 1 }));
  const liRef = asm.add(liCell([0]));
  const rootRef = asm.add(nkCell({ name: 'Root', subCount: 1, subList: 0, valueCount: 0 }));

  asm.patchU32(childVkRef, 8, childDataRef);
  asm.patchU32(childListRef, 0, childVkRef);
  asm.patchU32(childNkRef, 0x28, childListRef);
  asm.patchU32(liRef, 4, childNkRef);
  asm.patchU32(rootRef, 0x14, liRef);

  const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'li.hive');
  assert.equal(result.state, 'complete');
  const leaf = result.records.find(r => r.valueName === 'Leaf');
  assert.ok(leaf);
  assert.equal(leaf.keyPath, 'Root\\Child');
  assert.equal(leaf.value, 7);
  assert.equal(result.rootKey.subkeyCount, 1);
});

// 验证 db 分段大值跨段拼接，记录与外置值同构可查询。
test('合成蜂巢：db 分段大值按段顺序拼接为单一记录', () => {
  const payload = Buffer.from('0123456789ABCDEFGHIJKLMNOPQRSTUVWX'); // 34 字节 -> 16/16/2 三段
  const SEG = 16;
  const segPayloads = [];
  for (let o = 0; o < payload.length; o += SEG) segPayloads.push(payload.subarray(o, o + SEG));
  const asm = new HiveAssembler();
  const segDataRefs = segPayloads.map(p => asm.add(dataCell(p)));
  const segDescRefs = segPayloads.map(() => asm.add(allocatedCell(Buffer.alloc(8))));
  const segListRef = asm.add(allocatedCell(Buffer.alloc(segPayloads.length * 4)));
  const dbRef = asm.add(allocatedCell(Buffer.alloc(12)));
  const vkRef = asm.add(vkCell({ name: 'Big', type: 3, dataLength: payload.length }));
  const listRef = asm.add(valueListCell([0]));
  const rootRef = asm.add(nkCell({ name: 'Root', valueCount: 1 }));

  segDescRefs.forEach((ref, i) => {
    asm.patchU32(ref, 0, segPayloads[i].length);
    asm.patchU32(ref, 4, segDataRefs[i]);
    asm.patchU32(segListRef, i * 4, ref);
  });
  asm.entries.find(e => e.rel === dbRef).cell.write('db', 4, 'latin1');
  asm.patchU32(dbRef, 4, segPayloads.length);
  asm.patchU32(dbRef, 8, segListRef);
  asm.patchU32(vkRef, 8, dbRef);
  asm.patchU32(listRef, 0, vkRef);
  asm.patchU32(rootRef, 0x28, listRef);

  const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'db.hive');
  assert.equal(result.state, 'complete');
  assert.equal(result.records.length, 1);
  const rec = result.records[0];
  assert.equal(rec.dataLocation.kind, 'big-data');
  assert.equal(rec.value, payload.toString('hex'));
});

// 验证 UTF-16LE 键名/值名按声明编码保留，不按本机区域设置猜测。
test('合成蜂巢：未置压缩标志的名称按 UTF-16LE 解释', () => {
  const asm = new HiveAssembler();
  const data = Buffer.from('值\0', 'utf16le');
  const dataRef = asm.add(dataCell(data));
  const vkRef = asm.add(vkCell({ name: '数值', type: 1, dataLength: data.length, compressedName: false }));
  const listRef = asm.add(valueListCell([0]));
  const rootRef = asm.add(nkCell({ name: '根键', valueCount: 1, compressed: false }));
  asm.patchU32(vkRef, 8, dataRef);
  asm.patchU32(listRef, 0, vkRef);
  asm.patchU32(rootRef, 0x28, listRef);

  const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'utf16.hive');
  assert.equal(result.state, 'complete');
  assert.equal(result.rootKey.keyPath, '根键');
  assert.equal(result.rootKey.keyNameEncoding, 'utf16le');
  const rec = result.records[0];
  assert.equal(rec.valueName, '数值');
  assert.equal(rec.valueNameEncoding, 'utf16le');
});

// 验证空闲单元中的残留字节不会被恢复：空闲单元写入诱饵 vk 签名但不可达。
test('合成蜂巢：空闲单元残留不被扫描恢复', () => {
  const asm = new HiveAssembler();
  const data = Buffer.alloc(4); data.writeUInt32LE(1, 0);
  const dataRef = asm.add(dataCell(data));
  const vkRef = asm.add(vkCell({ name: 'Live', type: 4, dataLength: 4, inlineData: data }));
  const listRef = asm.add(valueListCell([0]));
  const rootRef = asm.add(nkCell({ name: 'Root', valueCount: 1 }));
  // 一个空闲单元，内部伪造 vk 签名与名称，试图诱导恢复。
  const decoy = Buffer.alloc(40);
  decoy.write('vk', 4, 'latin1');
  decoy.write('Ghost', 4 + 0x14, 'latin1');
  decoy.writeInt32LE(decoy.length, 0); // 正长度表示空闲
  const decoyRef = asm.add(decoy);
  asm.patchU32(listRef, 0, vkRef);
  asm.patchU32(rootRef, 0x28, listRef);

  const result = parseHive(asm.assemble({ rootCellOffset: rootRef }), 'decoy.hive');
  assert.equal(result.state, 'complete');
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].valueName, 'Live');
  assert.equal(result.coverage.freeCellsScanned, false);
  assert.equal(result.coverage.deletedRecovered, false);
});
