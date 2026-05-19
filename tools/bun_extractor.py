#!/usr/bin/env python3
"""
Bun 打包 exe 提取工具 — 基于 StandaloneModuleGraph.zig 结构

从 Bun 打包的可执行文件中提取所有 JS 模块、source map 和 .node 原生模块。

结构定义（来自 StandaloneModuleGraph.zig）:
  - Offsets: byte_count(u64) + modules_ptr + entry_point_id + argv_ptr + flags (32字节)
  - CompiledModuleGraphFile: 4个 StringPointer + 4个 enum (36字节)
  - StringPointer: {offset: u32, length: u32} (8字节)

用法:
    python bun_extractor.py <bun_exe> [output_dir]
"""

import sys
import os
import re
import struct
from pathlib import Path

# ── 常量 ──────────────────────────────────────────────
TRAILER = b"\n---- Bun! ----\n"
OFFSETS_SIZE = 32
MODULE_STRUCT_SIZE = 36

# Offsets 结构 (Little Endian): byte_count(u64) + modules_ptr(2×u32) + entry_point_id(u32) + argv_ptr(2×u32) + flags(u32)
OFFSETS_FMT = "<Q II I II I"

# CompiledModuleGraphFile: 4×StringPointer(2×u32) + 4×u8 enum
MODULE_FMT = "<II II II II B B B B"

# PE 常量
DOS_SIGNATURE = 0x5A4D
NT_SIGNATURE = 0x00004550

# Bun 虚拟文件系统前缀
BUNFS_PREFIXES = ("/$bunfs/", "B:\\~BUN\\", "B:/~BUN/", "file:///")


class StringPointer:
    """字符串/数据指针，指向 blob 中的一段数据"""
    __slots__ = ('offset', 'length')

    def __init__(self, offset, length):
        self.offset = offset
        self.length = length

    def read(self, blob):
        if self.length == 0:
            return b""
        if self.offset + self.length > len(blob):
            return b""
        return blob[self.offset:self.offset + self.length]

    def __repr__(self):
        return f"<Ptr off={self.offset:#x} len={self.length}>"


# ── PE 解析 ──────────────────────────────────────────

def parse_pe_sections(data):
    """解析 PE 文件节区表，返回节区列表"""
    if len(data) < 64:
        raise ValueError(f"文件太小 ({len(data)} 字节)，不是有效的 PE 文件")

    if struct.unpack('<H', data[0:2])[0] != DOS_SIGNATURE:
        raise ValueError("无效的 DOS 签名，不是 PE 文件")

    nt_offset = struct.unpack('<I', data[60:64])[0]
    if len(data) < nt_offset + 24:
        raise ValueError("NT 头超出文件范围")

    if struct.unpack('<I', data[nt_offset:nt_offset + 4])[0] != NT_SIGNATURE:
        raise ValueError("无效的 NT 签名")

    num_sections = struct.unpack('<H', data[nt_offset + 6:nt_offset + 8])[0]
    opt_header_size = struct.unpack('<H', data[nt_offset + 20:nt_offset + 22])[0]
    section_table = nt_offset + 24 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec_off = section_table + i * 40
        if len(data) < sec_off + 40:
            break
        sections.append({
            'name': data[sec_off:sec_off + 8].rstrip(b'\x00').decode('ascii', errors='ignore'),
            'offset': struct.unpack('<I', data[sec_off + 20:sec_off + 24])[0],
            'size': struct.unpack('<I', data[sec_off + 16:sec_off + 20])[0],
        })
    return sections


# ── Bun trailer / Offsets 解析 ────────────────────────

def find_trailer(data, bun_section):
    """在 .bun 节区末尾搜索 Bun trailer"""
    search_start = max(bun_section['offset'],
                       bun_section['offset'] + bun_section['size'] - 10240)
    search_end = bun_section['offset'] + bun_section['size']
    tail_chunk = data[search_start:search_end]

    pos = tail_chunk.find(TRAILER)
    if pos == -1:
        raise ValueError("未找到 Bun trailer，可能不是标准 Bun 打包格式")
    return search_start + pos


def parse_offsets(data, trailer_pos):
    """解析 trailer 前面的 Offsets 结构"""
    raw = data[trailer_pos - OFFSETS_SIZE:trailer_pos]
    byte_count, mod_off, mod_len, entry_id, argv_off, argv_len, flags = \
        struct.unpack(OFFSETS_FMT, raw)

    return {
        'byte_count': byte_count,
        'modules_ptr': StringPointer(mod_off, mod_len),
        'entry_point_id': entry_id,
        'argv_ptr': StringPointer(argv_off, argv_len),
        'flags': flags,
        'blob_start': trailer_pos - OFFSETS_SIZE - byte_count,
    }


# ── 模块解析 ──────────────────────────────────────────

def parse_modules(blob, modules_ptr):
    """解析模块表，返回模块列表"""
    modules_bytes = modules_ptr.read(blob)
    if not modules_bytes:
        raise ValueError("模块表数据为空")

    num_modules = len(modules_bytes) // MODULE_STRUCT_SIZE
    modules = []

    for i in range(num_modules):
        off = i * MODULE_STRUCT_SIZE
        fields = struct.unpack(MODULE_FMT, modules_bytes[off:off + MODULE_STRUCT_SIZE])
        modules.append({
            'id': i,
            'name_ptr': StringPointer(fields[0], fields[1]),
            'content_ptr': StringPointer(fields[2], fields[3]),
            'map_ptr': StringPointer(fields[4], fields[5]),
            'bytecode_ptr': StringPointer(fields[6], fields[7]),
            'encoding': fields[8],
            'loader': fields[9],
            'format': fields[10],
            'side': fields[11],
        })
    return modules


# ── 路径清理 ──────────────────────────────────────────

def clean_module_path(raw_path):
    """清理 Bun 虚拟文件系统路径，转为可用的相对路径"""
    clean = raw_path

    for prefix in BUNFS_PREFIXES:
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
            break

    # 移除残留的根路径标记
    clean = clean.lstrip("/\\")

    # 处理 Windows 盘符路径 (如 C:/xxx → xxx)
    if len(clean) >= 2 and clean[1] == ':' and clean[0].isalpha():
        clean = clean[2:].lstrip("/\\")

    # 安全性：防止路径遍历
    clean = clean.replace("..", "_").replace("\\", "/")
    return clean


# ── Native .node 模块提取 ─────────────────────────────

def extract_native_modules(blob, output_dir):
    """从 blob 中扫描 PE/DLL 文件（.node 原生模块）并提取"""
    extracted = []

    idx = 0
    while True:
        pos = blob.find(b'MZ', idx)
        if pos == -1:
            break
        idx = pos + 2

        # 验证 PE 签名
        if pos + 64 >= len(blob):
            continue
        pe_off = struct.unpack('<I', blob[pos + 60:pos + 64])[0]
        if pe_off >= 1024 or pos + pe_off + 4 >= len(blob):
            continue
        if blob[pos + pe_off:pos + pe_off + 4] != b'PE\x00\x00':
            continue

        # 从节区表计算 PE 文件实际大小
        nt_pos = pos + pe_off
        num_sec = struct.unpack('<H', blob[nt_pos + 6:nt_pos + 8])[0]
        opt_hdr = struct.unpack('<H', blob[nt_pos + 20:nt_pos + 22])[0]
        sec_table = nt_pos + 24 + opt_hdr
        pe_end = pos
        for i in range(num_sec):
            s = sec_table + i * 40
            if s + 40 > len(blob):
                break
            raw_off = struct.unpack('<I', blob[s + 20:s + 24])[0]
            raw_sz = struct.unpack('<I', blob[s + 16:s + 20])[0]
            sec_end = pos + raw_off + raw_sz
            if sec_end > pe_end:
                pe_end = sec_end

        # 从前置字节中查找 .node 文件名
        preceding = blob[max(0, pos - 200):pos]
        m = re.search(rb'B:/~BUN/root/([a-zA-Z0-9_\-\.]+\.node)\x00', preceding)
        if not m:
            m = re.search(rb'([a-zA-Z0-9_\-\.]+\.node)\x00', preceding)
        name = m.group(1).decode('ascii') if m else f"native_{pos:x}.node"

        clean_name = clean_module_path(name)
        save_path = output_dir / clean_name
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(blob[pos:pe_end])

        extracted.append({'name': name, 'path': clean_name, 'offset': pos,
                          'size': pe_end - pos})
        idx = pe_end  # 跳过当前 PE 继续搜索

    return extracted


# ── 主提取流程 ────────────────────────────────────────

def extract_bun_exe(exe_path, output_dir=None):
    """从 Bun 打包的 exe 中提取所有模块文件

    返回:
        dict: {
            'output_dir': Path,
            'entry_point': str | None,
            'js_modules': int,
            'native_modules': int,
        }
    """
    exe_path = Path(exe_path).resolve()
    if not exe_path.exists():
        raise FileNotFoundError(f"文件不存在: {exe_path}")

    if output_dir is None:
        output_dir = exe_path.parent / f'{exe_path.stem}_extracted'
    else:
        output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[提取] {exe_path.name}  ({exe_path.stat().st_size/1024/1024:.1f}MB)")
    print(f"[输出] {output_dir}")

    # 1. 读取文件 & 解析 PE
    data = exe_path.read_bytes()
    sections = parse_pe_sections(data)

    bun_sec = next((s for s in sections if s['name'] == '.bun'), None)
    if not bun_sec:
        raise ValueError("未找到 .bun 节区，可能不是 Bun 打包的 exe")

    # 2. 定位 trailer & 解析 offsets
    trailer_pos = find_trailer(data, bun_sec)
    offsets = parse_offsets(data, trailer_pos)

    # 3. 提取 blob
    blob_start = offsets['blob_start']
    blob = data[blob_start:blob_start + offsets['byte_count']]
    print(f"[Blob] {len(blob)/1024/1024:.1f}MB")

    # 4. 解析 & 提取模块
    modules = parse_modules(blob, offsets['modules_ptr'])
    print(f"[模块] 共 {len(modules)} 个")

    entry_point = None
    js_count = 0

    for mod in modules:
        raw_name = mod['name_ptr'].read(blob)
        if not raw_name:
            continue

        try:
            filename = raw_name.decode('utf-8')
        except UnicodeDecodeError:
            filename = f"unknown_{mod['id']}.bin"

        if mod['id'] == offsets['entry_point_id']:
            entry_point = filename

        content = mod['content_ptr'].read(blob)
        if not content:
            content = mod['bytecode_ptr'].read(blob)

        save_path = output_dir / clean_module_path(filename)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_bytes(content)
        js_count += 1

        # Source map
        if mod['map_ptr'].length > 0:
            map_path = save_path.with_suffix(save_path.suffix + '.map')
            map_path.write_bytes(mod['map_ptr'].read(blob))

    # 5. 提取 .node 原生模块
    native_list = extract_native_modules(blob, output_dir)
    for n in native_list:
        print(f"  [native] {n['name']} ({n['size']/1024:.1f}KB)")

    # 6. 保存编译参数
    argv_data = offsets['argv_ptr'].read(blob)
    if argv_data:
        (output_dir / 'compile_argv.txt').write_bytes(argv_data)

    print(f"\n[完成] {js_count} 个 JS 模块 + {len(native_list)} 个 native 模块")
    if entry_point:
        print(f"[入口] {entry_point}")

    return {
        'output_dir': output_dir,
        'entry_point': entry_point,
        'js_modules': js_count,
        'native_modules': len(native_list),
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    try:
        extract_bun_exe(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    except FileNotFoundError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[错误] 提取失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
