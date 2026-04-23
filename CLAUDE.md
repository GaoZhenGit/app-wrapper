# Bun Wrap Tools

## 项目目标

从 Bun 打包的可执行文件中提取 JavaScript 源码，并重新打包为可运行的可执行文件。

## 核心成果

已成功实现目标：
1. 使用官方 StandaloneModuleGraph.zig 结构从 Bun exe 提取 JS
2. 修复 CommonJS wrapper 调用，传入正确参数
3. 使用 `bun build --compile` 重新打包

## 项目结构

```
bun-wrap-tools/
├── tools/           # Python 工具
│   ├── bun_extractor.py    # 从 Bun exe 提取 JS
│   └── bun_wrapper_fix.py  # 修复并重打包 JS
├── samples/         # 示例可执行文件和提取的文件
└── docs/            # 文档
```

## 核心文件

- `tools/bun_extractor.py` - 使用 PE 解析 + Bun 结构提取 JS
- `tools/bun_wrapper_fix.py` - 修复 wrapper + 添加模块 polyfill
- `samples/claude.v2.1.117.bin` - 示例 Bun exe (247MB)
- `samples/build/` - 提取的 JS 文件

## 使用方法

```bash
# 提取
python tools/bun_extractor.py samples/claude.v2.1.117.bin samples/build/

# 修复
python tools/bun_wrapper_fix.py samples/build/root/src/entrypoints/cli.js cli_fixed.js

# 打包
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --bytecode --outfile app.exe
```

## 技术细节

### Bun 结构检测
- Trailer: `\n---- Bun! ----\n`
- Offsets: 32字节结构，包含 byte_count、modules_ptr 等
- 模块表: 260字节 (7个模块 × 36字节)

### Wrapper 修复
- 通过正则自动检测函数名: `([A-Z][A-Z0-9_]{1,6})\(\);\}\)`
- 不同 Bun 版本有不同的函数名 (E_9, K4A 等)
- 注入正确的 5 个参数: exports, require, module, __filename, __dirname

## 不自动提交 Git

用户手动操作所有 git 提交。
