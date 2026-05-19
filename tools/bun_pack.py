#!/usr/bin/env python3
"""
Bun Exe 一键提取 + 修复 + 编译工具

从 Bun 打包的 exe 出发，自动完成:
  1. 提取所有 JS 模块和 .node 原生模块
  2. 修复入口 JS（去 IIFE 外壳 + 注入模块 polyfill + 替换 VFS 路径）
  3. 检测并安装外部 npm 依赖
  4. 可选编译为新的 exe

用法:
    python bun_pack.py <input.exe> [选项]
    python bun_pack.py --help

选项:
    -o, --output FILE      输出 exe 文件名 (默认: output.exe)
    --no-compile           只提取修复，不编译
    --target TARGET        Bun 编译目标 (如 bun-windows-x64-modern)
    --bytecode             启用 bytecode 编译 (默认关闭，更快更稳定)

中间文件保留在 build/ 目录，每次运行会自动清空重建。

示例:
    python bun_pack.py samples/claude.v2.1.142.bin
    python bun_pack.py samples/claude.v2.1.142.bin -o myapp.exe --target bun-windows-x64-modern
    python bun_pack.py samples/claude.v2.1.142.bin --no-compile
"""

import sys
import os
import re
import json
import shutil
import subprocess
import argparse
from pathlib import Path

# 确保可以导入同目录的工具模块
TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
BUILD_DIR = PROJECT_ROOT / 'build'

if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from bun_extractor import extract_bun_exe
from bun_wrapper_fix import process_js_file, copy_native_modules, NODE_BUILTINS

# 不视为外部 npm 包的模块
INTERNAL_PREFIXES = ('B:', '/', './', '../', 'node:')
NON_NPM_MODULES = {
    'bun:ffi', 'bun:sqlite', 'bun:jsc',
    'bun:ffi', 'bun', 'process',
} | set(f'node:{m}' for m in NODE_BUILTINS) | set(NODE_BUILTINS)


def find_entry_js(extract_dir, entry_point_name):
    """在提取目录中定位入口 JS 文件"""
    if entry_point_name:
        # 尝试多种可能的路径
        candidates = [
            extract_dir / entry_point_name,
            extract_dir / 'root' / 'src' / 'entrypoints' / Path(entry_point_name).name,
        ]
        # 递归搜索
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                if f == Path(entry_point_name).name:
                    candidates.append(Path(root) / f)

        for c in candidates:
            if c.exists():
                return c

    # 回退：搜索最大的 .js 文件（通常是入口）
    js_files = list(extract_dir.rglob('*.js'))
    if not js_files:
        raise FileNotFoundError(f"在 {extract_dir} 中未找到 .js 文件")
    return max(js_files, key=lambda f: f.stat().st_size)


def check_bun():
    """检查 bun 是否可用"""
    try:
        result = subprocess.run(['bun', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def detect_npm_dependencies(js_path):
    """从 JS 文件中检测需要安装的 npm 依赖

    返回:
        dict: {package_name: version_spec}
    """
    content = Path(js_path).read_text(encoding='utf-8')
    requires = re.findall(r"""require\(['"]([^'"]+)['"]\)""", content)
    packages = {}
    for r in requires:
        r = r.strip()
        # 跳过内部路径、bun: 协议
        if any(r.startswith(p) for p in INTERNAL_PREFIXES):
            continue
        # 提取基础包名（处理子路径如 ajv/dist/runtime/equal → ajv）
        if r.startswith('@'):
            parts = r.split('/')
            pkg_name = f'{parts[0]}/{parts[1]}' if len(parts) >= 2 else r
        else:
            pkg_name = r.split('/')[0]
        # 跳过 Node 内置模块
        if pkg_name in NON_NPM_MODULES:
            continue
        if pkg_name not in packages:
            packages[pkg_name] = '*'
    return packages


def install_npm_dependencies(build_dir, packages):
    """在 build 目录创建 package.json 并安装依赖"""
    if not packages:
        print("[依赖] 无需安装外部 npm 包")
        return

    build_dir = Path(build_dir)
    pkg_json = build_dir / 'package.json'

    # 如果已存在 package.json，检查是否包含所有依赖
    existing = {}
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding='utf-8'))
            existing = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        except (json.JSONDecodeError, KeyError):
            pass

    all_deps = {**packages}
    all_deps.update(existing)

    package_data = {
        'name': 'cli-app',
        'version': '1.0.0',
        'private': True,
        'dependencies': {k: (v if v else '*') for k, v in all_deps.items()},
    }
    pkg_json.write_text(json.dumps(package_data, indent=2) + '\n', encoding='utf-8')

    print(f"[依赖] 检测到 {len(packages)} 个 npm 包: {', '.join(packages)}")
    print("[依赖] 运行 bun install...")
    result = subprocess.run(['bun', 'install'], cwd=str(build_dir),
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[依赖] 安装输出:\n{result.stdout}{result.stderr}")
        raise RuntimeError(f"bun install 失败 (exit code {result.returncode})")
    print(f"[依赖] 安装完成")


def run_bun_build(input_js, output_exe, target=None, bytecode=False):
    """直接使用 bun build --compile 编译"""
    cmd = ['bun', 'build', str(input_js), '--compile', '--outfile', str(output_exe)]
    if bytecode:
        cmd.insert(3, '--bytecode')
    if target:
        cmd.extend(['--target', target])

    print(f"\n[编译] {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(input_js.parent))
    if result.returncode != 0:
        raise RuntimeError(f"bun build 失败 (exit code {result.returncode})")
    return output_exe


def pack_bun_exe(input_exe, output_exe=None, compile_flag=True,
                 target=None, bytecode=False):
    """一键提取 + 修复 + 编译

    参数:
        input_exe: Bun 打包的 exe 文件路径
        output_exe: 输出的 exe 文件名 (默认: output.exe)
        compile_flag: 是否执行 bun build --compile
        target: Bun 编译目标 (如 bun-windows-x64-modern)
        bytecode: 是否启用 --bytecode

    返回:
        Path: 最终输出的 exe 路径 (如果 compile_flag=True)
    """
    input_path = Path(input_exe).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    if output_exe is None:
        output_exe = Path.cwd() / 'output.exe'
    else:
        output_exe = Path(output_exe).resolve()

    # ── 1. 检查 bun ──────────────────────────────
    bun_ver = check_bun()
    if compile_flag and not bun_ver:
        raise RuntimeError("未找到 bun，请先安装 Bun >= 1.3.14")
    if bun_ver:
        print(f"[Bun] v{bun_ver}")

    # ── 2. 提取 ──────────────────────────────────
    # 每次运行前先清空旧的 build 目录
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    extract_dir = BUILD_DIR / f'{input_path.stem}_extracted'

    print(f"\n{'='*60}")
    print(f"步骤 1/4: 提取")
    print(f"{'='*60}")
    result = extract_bun_exe(input_path, extract_dir)

    # ── 3. 修复 ──────────────────────────────────
    print(f"\n{'='*60}")
    print(f"步骤 2/4: 修复")
    print(f"{'='*60}")

    entry_js = find_entry_js(extract_dir, result['entry_point'])
    print(f"[入口] {entry_js.relative_to(extract_dir)}")

    fixed_js = BUILD_DIR / 'cli_fixed.js'
    fix_result = process_js_file(entry_js, fixed_js)

    # 确保 .node 文件在修复后的 JS 同目录
    for name in fix_result.get('native_modules', []):
        src = extract_dir / name
        dst = fixed_js.parent / name
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)

    # ── 3. 安装 npm 依赖 ──────────────────────
    print(f"\n{'='*60}")
    print(f"步骤 3/4: 安装 npm 依赖")
    print(f"{'='*60}")
    packages = detect_npm_dependencies(fixed_js)
    install_npm_dependencies(BUILD_DIR, packages)

    # ── 4. 编译（可选）──────────────────────────
    if compile_flag:
        print(f"\n{'='*60}")
        print(f"步骤 4/4: 编译")
        print(f"{'='*60}")
        run_bun_build(fixed_js, output_exe, target, bytecode)
        print(f"\n[完成] {output_exe}  ({output_exe.stat().st_size/1024/1024:.1f}MB)")
    else:
        print(f"\n[完成] 修复后的 JS: {fixed_js}")
        print(f"[提示] 手动编译: bun build {fixed_js} --compile --outfile output.exe")

    return output_exe if compile_flag else fixed_js


def main():
    parser = argparse.ArgumentParser(
        description='Bun Exe 一键提取 + 修复 + 编译工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python bun_pack.py app.exe
    python bun_pack.py app.exe -o myapp.exe --target bun-windows-x64-modern
    python bun_pack.py app.exe --no-compile
        """,
    )
    parser.add_argument('input', nargs='?', help='Bun 打包的 exe 文件')
    parser.add_argument('-o', '--output', default=None, help='输出 exe 文件名 (默认: output.exe)')
    parser.add_argument('--no-compile', action='store_true', help='只提取修复，不编译')
    parser.add_argument('--target', default=None, help='Bun 编译目标 (如 bun-windows-x64-modern)')
    parser.add_argument('--bytecode', action='store_true', help='启用 bytecode 编译 (慢但可能减小体积)')

    args = parser.parse_args()

    if args.input is None:
        parser.print_help()
        sys.exit(0)

    try:
        pack_bun_exe(
            input_exe=args.input,
            output_exe=args.output,
            compile_flag=not args.no_compile,
            target=args.target,
            bytecode=args.bytecode,
        )
    except FileNotFoundError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[错误] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
