# Bun Wrap Tools

用于从 Bun 打包的可执行文件中提取和重打包 JavaScript 的工具。

## 目的

本项目从 Bun 编译的可执行文件（如 `claude.exe`）中提取 JavaScript 源码，并重新打包为可运行的可执行文件。

## 项目结构

```
bun-wrap-tools/
├── tools/           # Python 工具
│   ├── bun_extractor.py    # 从 Bun exe 提取 JS
│   └── bun_wrapper_fix.py  # 修复并重打包 JS
├── samples/         # 示例 Bun 可执行文件
│   ├── build/       # 提取的 JS 文件
│   ├── claude.v2.1.116.bin
│   └── claude.v2.1.117.bin
└── docs/            # 文档
```

## 快速开始

```bash
# 1. 从 Bun exe 提取 JS
python tools/bun_extractor.py samples/claude.v2.1.117.bin samples/build/

# 2. 修复并重打包 JS
python tools/bun_wrapper_fix.py samples/build/root/src/entrypoints/cli.js cli_fixed.js

# 3. 测试
bun run cli_fixed.js --version

# 4. 构建新 exe
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --bytecode --outfile app.exe
```

## 工具说明

### bun_extractor.py

使用官方 StandaloneModuleGraph.zig 结构从 Bun 打包的可执行文件中提取 JavaScript 源码。

### bun_wrapper_fix.py

修复 CommonJS wrapper 调用，添加模块 polyfill，使提取的 JS 可独立运行。

详细文档请参见 `docs/README.md`。
