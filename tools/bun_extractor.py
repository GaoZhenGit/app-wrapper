#!/usr/bin/env python3
"""
Bun打包exe提取工具 - 基于StandaloneModuleGraph.zig结构

核心原理（基于参考工具）：
1. 从.bun section末尾查找Bun trailer: "\n---- Bun! ----\n"
2. 解析Offsets结构（32字节）
3. 定位blob数据和模块表
4. 解析每个CompiledModuleGraphFile结构
5. 提取所有模块文件

结构定义（来自StandaloneModuleGraph.zig）：
- Offsets: byte_count(u64) + modules_ptr + entry_point_id + argv_ptr + flags (32字节)
- CompiledModuleGraphFile: 4个StringPointer + 4个enum (36字节)
- StringPointer: {offset: u32, length: u32} (8字节)

用法：
    python bun_extractor_reliable.py <bun_exe> [output_dir]
"""

import sys
import os
import struct
from pathlib import Path

# Bun标准结构常量
TRAILER = b"\n---- Bun! ----\n"
OFFSETS_SIZE = 32  # Offsets extern struct
MODULE_STRUCT_SIZE = 36  # CompiledModuleGraphFile

# Offsets结构（Little Endian）
# byte_count: u64 (8)
# modules_ptr: {offset: u32, length: u32} (8)
# entry_point_id: u32 (4)
# compile_exec_argv_ptr: {offset: u32, length: u32} (8)
# flags: u32 (4)
OFFSETS_FMT = "<Q II I II I"

# CompiledModuleGraphFile结构（Little Endian）
# 4x StringPointer (8字节×4 = 32字节)
# 4x u8 enum (4字节)
MODULE_FMT = "<II II II II B B B B"

class StringPointer:
    """字符串/数据指针结构"""
    def __init__(self, offset, length):
        self.offset = offset
        self.length = length

    def read(self, blob_data):
        """从blob中读取数据"""
        if self.length == 0:
            return b""

        if self.offset + self.length > len(blob_data):
            print(f"[警告] 指针超出blob范围: offset={self.offset}, length={self.length}, blob_size={len(blob_data)}")
            return b""

        return blob_data[self.offset: self.offset + self.length]

    def __repr__(self):
        return f"<Ptr off={self.offset} len={self.length}>"

def find_pe_sections(data):
    """解析PE节区表"""
    if len(data) < 64:
        raise ValueError("文件太小")

    dos_sig = struct.unpack('<H', data[0:2])[0]
    if dos_sig != 0x5A4D:
        raise ValueError(f"无效DOS签名: {dos_sig:#x}")

    nt_offset = struct.unpack('<I', data[60:64])[0]

    if len(data) < nt_offset + 24:
        raise ValueError("文件太小")

    nt_sig = struct.unpack('<I', data[nt_offset:nt_offset+4])[0]
    if nt_sig != 0x00004550:
        raise ValueError(f"无效NT签名: {nt_sig:#x}")

    opt_header_size = struct.unpack('<H', data[nt_offset+20:nt_offset+22])[0]
    num_sections = struct.unpack('<H', data[nt_offset+6:nt_offset+8])[0]
    section_table = nt_offset + 24 + opt_header_size

    sections = []
    for i in range(num_sections):
        sec_offset = section_table + i * 40

        if len(data) < sec_offset + 40:
            break

        sec_name = data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        raw_size = struct.unpack('<I', data[sec_offset+16:sec_offset+20])[0]
        raw_offset = struct.unpack('<I', data[sec_offset+20:sec_offset+24])[0]

        sections.append({
            'name': sec_name,
            'offset': raw_offset,
            'size': raw_size
        })

    return sections

def find_bun_trailer_in_section(data, bun_section):
    """在.bun section内查找trailer"""
    bun_offset = bun_section['offset']
    bun_size = bun_section['size']

    print(f"\n[步骤1] 在.bun section内查找Bun trailer...")
    print(f"搜索范围: offset {bun_offset:#x} 到 {bun_offset+bun_size:#x}")

    # 从section末尾向前搜索
    search_start = bun_offset + bun_size - 10240  # 搜索末尾10KB
    search_end = bun_offset + bun_size

    if search_start < bun_offset:
        search_start = bun_offset

    tail_data = data[search_start:search_end]

    pos = tail_data.find(TRAILER)
    if pos == -1:
        raise ValueError("未找到Bun trailer，可能不是标准Bun打包格式")

    trailer_abs_pos = search_start + pos
    trailer_rel_pos = trailer_abs_pos - bun_offset

    print(f"[OK] 找到trailer:")
    print(f"  绝对位置: {trailer_abs_pos:#x}")
    print(f"  Section内位置: {trailer_rel_pos}字节 ({trailer_rel_pos/1024/1024:.2f}MB)")

    return trailer_abs_pos

def parse_offsets_struct(data, trailer_pos):
    """解析Offsets结构"""
    print(f"\n[步骤2] 解析Offsets结构...")

    offsets_start = trailer_pos - OFFSETS_SIZE

    if len(data) < offsets_start + OFFSETS_SIZE:
        raise ValueError("Offsets结构超出文件范围")

    offsets_data = data[offsets_start:offsets_start+OFFSETS_SIZE]

    byte_count, mod_off, mod_len, entry_id, argv_off, argv_len, flags = \
        struct.unpack(OFFSETS_FMT, offsets_data)

    print(f"[OK] Offsets结构解析成功:")
    print(f"  byte_count: {byte_count}字节 ({byte_count/1024/1024:.2f}MB)")
    print(f"  modules_ptr: offset={mod_off:#x}, length={mod_len}字节")
    print(f"  entry_point_id: {entry_id}")
    print(f"  argv_ptr: offset={argv_off:#x}, length={argv_len}字节")
    print(f"  flags: {flags:#x}")

    return {
        'byte_count': byte_count,
        'modules_ptr': StringPointer(mod_off, mod_len),
        'entry_point_id': entry_id,
        'argv_ptr': StringPointer(argv_off, argv_len),
        'flags': flags,
        'blob_start': offsets_start - byte_count
    }

def parse_modules(blob_data, modules_ptr):
    """解析模块表"""
    print(f"\n[步骤3] 解析模块表...")

    modules_bytes = modules_ptr.read(blob_data)

    if len(modules_bytes) == 0:
        raise ValueError("模块表数据为空")

    num_modules = len(modules_bytes) // MODULE_STRUCT_SIZE

    print(f"[OK] 模块数量: {num_modules}")
    print(f"  模块表大小: {len(modules_bytes)}字节")

    modules = []
    for i in range(num_modules):
        offset = i * MODULE_STRUCT_SIZE
        m_data = modules_bytes[offset: offset + MODULE_STRUCT_SIZE]

        # 解析模块结构
        name_off, name_len, \
        content_off, content_len, \
        map_off, map_len, \
        bytecode_off, bytecode_len, \
        encoding, loader, mod_fmt, side = struct.unpack(MODULE_FMT, m_data)

        module = {
            'id': i,
            'name_ptr': StringPointer(name_off, name_len),
            'content_ptr': StringPointer(content_off, content_len),
            'map_ptr': StringPointer(map_off, map_len),
            'bytecode_ptr': StringPointer(bytecode_off, bytecode_len),
            'encoding': encoding,
            'loader': loader,
            'format': mod_fmt,
            'side': side
        }

        modules.append(module)

    return modules

def clean_module_path(filename):
    """清理模块路径"""
    # Bun虚拟路径处理
    clean = filename

    # 移除虚拟路径前缀（支持正斜杠和反斜杠）
    if clean.startswith("/$bunfs/"):
        clean = clean[8:]
    elif clean.startswith("B:\\~BUN\\"):
        clean = clean[8:]
    elif clean.startswith("B:/~BUN/"):
        clean = clean[8:]
    elif clean.startswith("file:///"):
        clean = clean[8:]

    # 移除绝对路径前缀
    clean = clean.lstrip("/\\")
    if ":" in clean:
        parts = clean.split(":")
        clean = parts[-1].lstrip("/\\")

    # 安全路径处理
    clean = clean.replace("..", "_").replace("\\", "/")

    return clean

def extract_bun_exe(exe_path, output_dir=None):
    """主提取流程"""
    exe_path = Path(exe_path).resolve()

    if not exe_path.exists():
        raise FileNotFoundError(f"文件不存在: {exe_path}")

    if output_dir is None:
        output_dir = exe_path.parent / f'{exe_path.stem}_bun_modules'
    else:
        output_dir = Path(output_dir).resolve()

    output_dir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("Bun打包exe提取工具 - 基于StandaloneModuleGraph结构")
    print("="*70)
    print(f"输入文件: {exe_path}")
    print(f"输出目录: {output_dir}")
    print(f"文件大小: {exe_path.stat().st_size/1024/1024:.2f}MB")
    print("="*70)

    # 读取文件
    print(f"\n[读取文件]...")
    with open(exe_path, 'rb') as f:
        data = f.read()

    # 解析PE节区
    print(f"\n[解析PE结构]...")
    sections = find_pe_sections(data)

    print(f"PE节区数量: {len(sections)}")
    for sec in sections:
        print(f"  {sec['name']:8s}: Size={sec['size']/1024:.1f}KB Offset={sec['offset']:#x}")

    # 查找.bun节区
    bun_section = None
    for sec in sections:
        if sec['name'] == '.bun':
            bun_section = sec
            break

    if not bun_section:
        raise ValueError("未找到.bun节区")

    # 查找trailer
    trailer_pos = find_bun_trailer_in_section(data, bun_section)

    # 解析Offsets
    offsets = parse_offsets_struct(data, trailer_pos)

    # 提取blob数据
    print(f"\n[步骤4] 提取数据blob...")
    blob_start = offsets['blob_start']
    blob_size = offsets['byte_count']

    print(f"  Blob起始: {blob_start:#x}")
    print(f"  Blob大小: {blob_size/1024/1024:.2f}MB")

    if blob_start < 0 or blob_start + blob_size > len(data):
        raise ValueError(f"Blob范围异常: start={blob_start}, size={blob_size}, file_size={len(data)}")

    blob_data = data[blob_start: blob_start + blob_size]
    print(f"[OK] Blob数据提取成功")

    # 解析模块表
    modules = parse_modules(blob_data, offsets['modules_ptr'])

    # 提取所有模块
    print(f"\n[步骤5] 提取模块文件...")

    extracted_count = 0
    entry_point_name = None

    for module in modules:
        # 读取模块名称
        raw_name = module['name_ptr'].read(blob_data)

        # 跳过空文件名的模块
        if len(raw_name) == 0:
            print(f"  [{module['id']}] [跳过] 文件名为空，可能是padding或无效模块")
            continue

        try:
            filename = raw_name.decode('utf-8')
        except UnicodeDecodeError:
            filename = f"unknown_{module['id']}.bin"

        # 记录入口点
        if module['id'] == offsets['entry_point_id']:
            entry_point_name = filename
            print(f"\n  [入口点] ID={module['id']}: {filename}")

        # 读取内容
        content = module['content_ptr'].read(blob_data)

        # 如果没有JS源码（content为空），则使用bytecode
        if len(content) == 0:
            bytecode = module['bytecode_ptr'].read(blob_data)
            if len(bytecode) > 0:
                content = bytecode
                print(f"       [注意] 无JS源码，使用bytecode ({len(bytecode)/1024:.1f}KB)")

        # 清理路径
        clean_name = clean_module_path(filename)
        save_path = output_dir / clean_name

        # 创建目录
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # 写入文件
        with open(save_path, 'wb') as f:
            f.write(content)

        print(f"  [{module['id']}] {filename:60s} -> {len(content)/1024:.1f}KB")
        extracted_count += 1

        # 提取source map
        if module['map_ptr'].length > 0:
            map_data = module['map_ptr'].read(blob_data)
            map_path = save_path.with_suffix(save_path.suffix + '.map')
            with open(map_path, 'wb') as f:
                f.write(map_data)
            print(f"       + SourceMap: {len(map_data)/1024:.1f}KB")

    # 提取编译参数
    argv_data = offsets['argv_ptr'].read(blob_data)
    if len(argv_data) > 0:
        argv_path = output_dir / 'compile_argv.txt'
        with open(argv_path, 'wb') as f:
            f.write(argv_data)
        print(f"\n[OK] 编译参数: {argv_data.decode('utf-8', errors='replace')}")

    # 生成报告
    report = f"""Bun打包exe提取报告
{'='*70}

源文件: {exe_path.name}
源大小: {exe_path.stat().st_size/1024/1024:.2f}MB

.bun节区信息:
- Offset: {bun_section['offset']:#x}
- Size: {bun_section['size']/1024/1024:.2f}MB

数据Blob信息:
- Trailer位置: {trailer_pos:#x}
- Blob起始: {blob_start:#x}
- Blob大小: {blob_size/1024/1024:.2f}MB

模块提取信息:
- 模块总数: {len(modules)}
- 成功提取: {extracted_count}
- 入口点: {entry_point_name or '未指定'}

提取方法:
基于StandaloneModuleGraph.zig结构解析：
1. 查找Bun trailer: "\n---- Bun! ----\n"
2. 解析Offsets结构（32字节）
3. 定位blob数据和模块表
4. 解析每个CompiledModuleGraphFile结构
5. 提取模块文件和source maps

输出文件位置: {output_dir}

{'='*70}
"""

    report_path = output_dir / '提取报告.txt'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print("\n" + "="*70)
    print(f"[OK] 提取完成！共提取{extracted_count}个模块")
    print("="*70)
    print(f"\n输出目录: {output_dir}")
    print(f"入口文件: {entry_point_name or '未指定'}")
    print("="*70)

    return output_dir

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n用法: python bun_extractor_reliable.py <bun_exe> [output_dir]")
        sys.exit(1)

    exe_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        extract_bun_exe(exe_path, output_dir)
    except Exception as e:
        print(f"\n[ERROR] 提取失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()