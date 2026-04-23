# 工具文档

## bun_extractor.py

从 Bun 打包的可执行文件中提取 JavaScript 源码。

### 用法

```bash
python bun_extractor.py <bun_exe> [output_dir]
```

### 示例

```bash
python bun_extractor.py claude.v2.1.117.bin extracted/
```

### 输出

- `root/src/entrypoints/cli.js` - 主入口 JavaScript 文件
- `unknown_N.bin` - 其他模块文件
- `提取报告.txt` - 提取报告

### 工作原理

1. 解析 PE 结构，查找 `.bun` 节区
2. 定位 Bun trailer 标记 `\n---- Bun! ----\n`
3. 读取 32 字节 Offsets 结构 (byte_count, modules_ptr 等)
4. 解析 260 字节模块表 (7个模块 × 36字节 + padding)
5. 提取每个模块的 JavaScript 源码

---

## bun_wrapper_fix.py

修复提取的 JavaScript，使其可独立运行。

### 用法

```bash
python bun_wrapper_fix.py <input.js> [output.js]
```

### 示例

```bash
python bun_wrapper_fix.py extracted/root/src/entrypoints/cli.js cli_fixed.js
```

### 功能特点

- 自动检测 Bun wrapper 函数名（如 `K4A`, `E_9`）
- 修复 CommonJS wrapper 调用，传入正确参数
- 添加 Node.js/Bun 内置模块 polyfill
- 无 base64 编码 - 直接修改 JS，性能最优
- 支持 bytecode 编译，启动更快

### 打包为可执行文件

```bash
# 基本编译
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --outfile app.exe

# 使用 bytecode（启动更快，体积更小）
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --bytecode --outfile app.exe
```

### 工作原理

**原始 Bun 包装的代码:**
```javascript
(function(exports, require, module, __filename, __dirname) {
    // 模块代码
})K4A();})
```

**修复后的代码:**
```javascript
const mod = { exports: {}, require: (id) => {...} };
global.module = mod;
global.require = mod.require;
// ...
eval(code + 'K4A();})(mod.exports, mod.require, mod, "cli.js", ".")');
```

wrapper 函数名（`K4A`）通过正则自动检测: `([A-Z][A-Z0-9_]{1,6})\(\);\}\)`

---

## 完整工作流程

```bash
# 1. 提取
python tools/bun_extractor.py samples/claude.v2.1.117.bin samples/build/

# 2. 修复
python tools/bun_wrapper_fix.py samples/build/root/src/entrypoints/cli.js cli_fixed.js

# 3. 测试
bun run cli_fixed.js --version

# 4. 打包 exe
bun build cli_fixed.js --compile --target=bun-windows-x64-modern --bytecode --outfile app.exe

# 5. 测试 exe
./app.exe --version
```

---

## 技术说明

### Bun Wrapper 函数名

Bun 为 CommonJS wrapper 生成随机函数名：
- v2.1.116: `E_9`
- v2.1.117: `K4A`

脚本通过正则模式匹配自动检测这些函数名。

### 模块 Polyfill

wrapper 修复为常用 Node.js/Bun 模块提供 polyfill：
- `fs`, `path`, `process`, `crypto`, `os`, `net`, `tls`
- `http`, `https`, `zlib`, `buffer`, `stream`, `events`
- 等等...

### 性能优化

- 无 base64 编解码 - 直接修改 JS
- `--bytecode` 标志编译为字节码，启动更快
