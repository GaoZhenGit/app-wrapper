#!/usr/bin/env python3
"""
Bun JS Wrapper 修复工具

从 Bun 打包的 exe 中提取的 JS 文件，去掉 IIFE 外壳，注入模块 polyfill，
使其可以重新用 bun build --compile 打包。

前置条件:
    - Bun >= 1.3.14 (修复了 CJS loader bug)
    - .node 原生模块需在同目录 (工具会自动搜索复制)

用法:
    python bun_wrapper_fix.py <input.js> [output.js]
"""

import re
import sys
import shutil
from pathlib import Path

# 需要 polyfill 的 Node.js 内置模块
NODE_BUILTINS = [
    'fs', 'path', 'url', 'crypto', 'os', 'net', 'tls',
    'http', 'https', 'zlib', 'buffer', 'stream', 'events', 'util',
    'querystring', 'string_decoder', 'punycode', 'readline',
    'child_process', 'constants', 'domain', 'vm', 'assert', 'tty',
    'dgram', 'module', 'perf_hooks', 'v8', 'async_hooks',
    'worker_threads', 'diagnostics_channel', 'trace_events', 'http2', 'wasi',
    'dns', 'timers', 'inspector', 'cluster', 'repl', 'console',
]

IIFE_HEADER = '(function(exports, require, module, __filename, __dirname) {'
BUN_PRAGMA = '// @bun @bytecode @bun-cjs\n'


def detect_wrapper_name(content):
    """自动检测 Bun wrapper 函数名（兼容大小写字母）"""
    m = re.search(r'([A-Za-z]\w{0,10})\(\);\}\)\s*$', content.rstrip())
    return m.group(1) if m else None


def generate_polyfill():
    """生成模块系统 polyfill"""
    lines = [
        'const mod = {',
        '  exports: {},',
        '  id: "cli.js",',
        '  filename: "cli.js",',
        '  require: function(id) {',
        "    if (id === 'node:process' || id === 'process') return process;",
    ]
    for m in NODE_BUILTINS:
        lines.append(f"    if (id === 'node:{m}' || id === '{m}') return require('{m}');")
    lines.extend([
        "    if (id.startsWith('node:')) id = id.substring(5);",
        "    return require(id);",
        "  }",
        "};",
    ])
    return '\n'.join(lines)


def generate_globals():
    """生成全局变量注入代码"""
    lines = [
        'global.module = mod;',
        'global.exports = mod.exports;',
        'global.require = mod.require;',
        'global.__filename = "cli.js";',
        'global.__dirname = ".";',
    ]
    return '\n'.join(lines)


def copy_native_modules(input_dir, output_dir):
    """从 input_dir 及父目录搜索 .node 文件并复制到 output_dir"""
    copied = []
    search_dirs = [Path(input_dir).resolve()]
    parent = search_dirs[0].parent
    for _ in range(3):
        if parent.is_dir():
            search_dirs.append(parent)
            parent = parent.parent

    seen = set()
    for d in search_dirs:
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.suffix == '.node' and f.name not in seen:
                seen.add(f.name)
                dst = Path(output_dir) / f.name
                if not dst.exists():
                    shutil.copy2(f, dst)
                copied.append(f.name)
    return copied


def replace_vfs_paths(content):
    """替换 Bun 虚拟文件系统路径 → 相对路径"""
    for quote in ('"', "'"):
        content = content.replace(f'require({quote}B:/~BUN/root/', f'require({quote}./')
    return content


def process_js_file(input_path, output_path=None):
    """处理 JS 文件：去 IIFE 外壳 + 注入 polyfill + 替换 VFS 路径

    返回:
        dict: {'output': Path, 'wrapper': str, 'native_modules': [str]}
    """
    input_path = Path(input_path).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"文件不存在: {input_path}")

    if output_path is None:
        output_path = input_path.parent / f'{input_path.stem}_fixed.js'
    else:
        output_path = Path(output_path).resolve()

    print(f"[读取] {input_path.name}  ({input_path.stat().st_size/1024/1024:.1f}MB)")

    content = input_path.read_text(encoding='utf-8')
    content = content.rstrip()

    # 1. 检测 wrapper 函数名
    func_name = detect_wrapper_name(content)
    if not func_name:
        raise ValueError("未检测到 Bun wrapper 函数名，可能不是有效的 Bun 打包文件")
    print(f"[Wrapper] {func_name}()")

    # 2. 验证结尾
    expected_end = f'{func_name}();}})'
    if not content.endswith(expected_end):
        print(f"[警告] 文件不以预期的 wrapper 结尾")

    # 3. 移除 Bun pragma
    if content.startswith(BUN_PRAGMA):
        content = content[len(BUN_PRAGMA):]

    # 4. 剥离 IIFE 外壳
    if not content.startswith(IIFE_HEADER):
        print(f"[警告] 文件不以预期的 IIFE 头部开始")
    else:
        content = content[len(IIFE_HEADER):]

    if content.endswith('})'):
        content = content[:-2]

    # 5. 替换 VFS 路径
    content = replace_vfs_paths(content)

    # 6. 复制 .node 原生模块
    out_dir = output_path.parent
    native_mods = copy_native_modules(input_path.parent, out_dir)
    if native_mods:
        print(f"[Native] {', '.join(native_mods)}")

    # 7. 组装最终代码: polyfill + globals + 源码体
    final_code = '\n'.join([
        generate_polyfill(),
        generate_globals(),
        '',
        content,
    ])

    output_path.write_text(final_code, encoding='utf-8')
    print(f"[写入] {output_path.name}  ({output_path.stat().st_size/1024/1024:.1f}MB)")

    return {
        'output': output_path,
        'wrapper': func_name,
        'native_modules': native_mods,
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    try:
        result = process_js_file(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
        print(f"\n[完成] {result['output']}")
        print(f"[测试] bun run {result['output']} --version")
        print(f"[编译] bun build {result['output']} --compile --bytecode --outfile output.exe")
    except FileNotFoundError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[错误] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
