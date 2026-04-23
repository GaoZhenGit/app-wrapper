# Bun打包exe提取与修复工具使用说明

## 工具概述

本工具集包含两个脚本，用于处理 Bun 打包的 exe 文件：

1. **bun_extractor_reliable.py** - 从 Bun 打包的 exe 中提取 JS 源码
2. **bun_wrapper_fix.py** - 修复提取的 JS 文件，使其可以独立运行和重新打包

## 工作流程

```
原始 exe (claude.exe)
    ↓ [bun_extractor_reliable.py]
提取的 JS 文件 (cli.js)
    ↓ [bun_wrapper_fix.py]
可运行的 JS 文件 (cli_inline.js)
    ↓ [bun build --compile]
最终 exe (claude-wrapped.exe)
```

## 第一步：提取 JS 源码

```bash
python bun_extractor_reliable.py <bun_exe> [output_dir]
```

示例：
```bash
python bun_extractor_reliable.py claude.exe bun_extracted
```

输出：
- `root/src/entrypoints/cli.js` - 主入口 JS 文件（通常最大那个）
- `提取报告.txt` - 提取详情

## 第二步：修复 JS 文件

```bash
python bun_wrapper_fix.py <input.js> [output.js]
```

示例：
```bash
python bun_wrapper_fix.py bun_extracted/root/src/entrypoints/cli.js cli_inline.js
```

**工具自动完成：**
1. 检测 Bun wrapper 函数名（如 `K4A`, `E_9` 等，每个版本不同）
2. 修复 CommonJS wrapper 调用，传入正确参数
3. 添加 Node.js/Bun 内置模块 polyfill
4. 将代码 base64 编码内嵌，生成自包含文件

## 第三步：测试运行

```bash
# 使用 bun 运行
bun run cli_inline.js --version
bun run cli_inline.js --help

# 交互模式
bun run cli_inline.js
```

## 第四步：编译为 exe

```bash
bun build cli_inline.js --compile --target=bun-windows-x64-modern --outfile claude-wrapped.exe
```

测试生成的 exe：
```bash
.\claude-wrapped.exe --version
.\claude-wrapped.exe --help
```

## 完整示例

```bash
# 1. 提取 JS
python bun_extractor_reliable.py claude.v2.1.117.bin extracted

# 2. 修复 JS
python bun_wrapper_fix.py extracted/root/src/entrypoints/cli.js cli_inline.js

# 3. 测试
bun run cli_inline.js --version

# 4. 打包为 exe
bun build cli_inline.js --compile --target=bun-windows-x64-modern --outfile claude-wrapped.exe

# 5. 测试 exe
.\claude-wrapped.exe --version
```

## 技术原理

### Bun Wrapper 函数

Bun 打包的 CommonJS 模块使用随机函数名包装：
```javascript
// 原始代码结构
(function(exports, require, module, __filename, __dirname) {
    // 模块代码
})K4A();})
```

- `K4A` 是随机生成的函数名（每次打包可能不同）
- 需要检测并修复 wrapper 调用，传入 5 个参数

### 自动检测

脚本使用正则表达式自动检测 wrapper 函数名：
```python
pattern = r'([A-Z][A-Z0-9_]{1,6})\(\);\}\)'
```

### 模块 Polyfill

由于代码被打包成单文件，需要提供 Node.js/Bun 内置模块的 polyfill：
- `fs`, `path`, `process`, `crypto`, `os` 等

## 注意事项

1. **不同版本有不同的函数名** - 每次 Bun 更新可能改变
2. **Bun runtime 依赖** - 生成的 exe 仍需要 Bun runtime
3. **内置模块覆盖** - 已覆盖常用模块，可能需根据实际情况调整

## 文件说明

- `bun_extractor_reliable.py` - PE 解析 + Bun 结构提取
- `bun_wrapper_fix.py` - JS wrapper 修复
- `bun_extractor使用说明_v2.md` - 提取工具详细文档
