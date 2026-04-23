# Bun JS Wrapper 修复工具使用说明

## 工具概述

`bun_wrapper_fix.py` - 修复 Bun 打包的 JS 文件，使其可以独立运行和重新打包

**特点：**
- 无 base64 编解码 - 直接修改 JS 内容，性能无损
- 自动检测 wrapper 函数名（`K4A`, `E_9` 等）
- 支持 bytecode 编译提升性能

## 使用方法

```bash
# 基本用法
python bun_wrapper_fix.py <input.js> [output.js]

# 示例：提取的 cli.js 修复
python bun_wrapper_fix.py cli.js cli_fixed.js
```

## 完整工作流程

```bash
# 1. 提取 JS（使用 bun_extractor_reliable.py）
python bun_extractor_reliable.py claude.exe extracted/

# 2. 修复 JS
python bun_wrapper_fix.py extracted/root/src/entrypoints/cli.js cli_fixed.js

# 3. 测试运行
bun run cli_fixed.js --version
bun run cli_fixed.js --help

# 4. 打包为 exe
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --outfile app.exe

# 5. 使用 bytecode（更快启动）
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --bytecode --outfile app.exe
```

## 技术原理

### 原始结构
```javascript
// cli.js
(function(exports, require, module, __filename, __dirname) {
    // 模块代码
})K4A();})
```

### 修复后
```javascript
// cli_fixed.js
const mod = { exports: {}, ... require: (id) => {...} };
global.module = mod;
global.require = mod.require;
// ... 其他 globals

// 使用 eval 执行，传入正确参数
const wrappedCode = originalCode + 'K4A();})(mod.exports, mod.require, mod, "cli.js", ".")';
eval(wrappedCode);
```

### 关键点

1. **自动检测** - 正则匹配 `([A-Z][A-Z0-9_]{1,6})\(\);\}\)`
2. **移除原调用** - 去掉 `K4A();})`
3. **添加参数** - 拼接 `K4A();})(mod.exports, require, module, __filename, __dirname)`
4. **eval 执行** - 在设置 globals 后执行

## 性能优化

使用 `--bytecode` 标志编译，可以：
- 减小文件大小
- 加快启动速度
- 保护源代码

```bash
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --bytecode --outfile app.exe
```

## 注意事项

1. **函数名因版本而异** - 每次 Bun 更新可能改变
2. **仍需 Bun runtime** - 生成的 exe 依赖 Bun 运行时
3. **模块 polyfill** - 已覆盖常用 Node.js/Bun 内置模块
