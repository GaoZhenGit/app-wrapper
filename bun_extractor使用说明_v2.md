# Bun打包exe提取工具使用说明

## 工具概述

`bun_extractor_reliable.py` - 基于Bun官方StandaloneModuleGraph.zig结构的可靠提取工具

## 工作原理

工具基于Bun官方打包格式（StandaloneModuleGraph.zig）进行结构化解析：

1. **查找Bun trailer**: 在.bun section末尾查找标准标记 `\n---- Bun! ----\n`
2. **解析Offsets结构**: 从trailer前读取32字节Offsets元数据
3. **定位数据blob**: 根据byte_count和modules_ptr定位模块表和数据区
4. **解析模块表**: 读取260字节模块表，解析每个CompiledModuleGraphFile结构
5. **提取模块文件**: 根据StringPointer读取每个模块的JS源码、bytecode和source map

## 技术细节

### Bun结构定义

```python
# Bun trailer标记
TRAILER = b"\n---- Bun! ----\n"

# Offsets结构（32字节）
byte_count: u64         # 数据blob总大小
modules_ptr: StringPointer  # 模块表位置
entry_point_id: u32     # 入口模块ID
argv_ptr: StringPointer     # 编译参数
flags: u32              # 标志位

# CompiledModuleGraphFile结构（36字节）
name_ptr: StringPointer     # 文件名
content_ptr: StringPointer  # JS源码
map_ptr: StringPointer      # Source map
bytecode_ptr: StringPointer # Bytecode数据
encoding: u8, loader: u8, format: u8, side: u8

# StringPointer结构（8字节）
offset: u32  # 数据在blob中的偏移
length: u32  # 数据长度
```

### 优先级策略

提取时优先使用JS源码（content），只有在content为空时才使用bytecode。

## 使用方法

### 基础用法

```bash
python bun_extractor_reliable.py <bun_exe> [output_dir]
```

### 示例

```bash
# 默认输出目录
python bun_extractor_reliable.py claude.exe
# 输出到: ./claude_bun_modules/

# 指定输出目录
python bun_extractor_reliable.py claude.exe my_output
# 输出到: ./my_output/

# 完整路径
python bun_extractor_reliable.py D:/path/to/app.exe D:/path/to/output
```

## 输出文件

提取完成后会生成：

1. **模块文件** (按原始路径组织)
   - 例如: `root/src/entrypoints/cli.js` (13MB JS源码)
   - 例如: `unknown_1.bin` (其他模块)

2. **Source map文件** (如果有)
   - 例如: `unknown_1.bin.map`

3. **提取报告.txt**
   - 详细的技术信息和统计数据

## 运行提取的代码

提取的JS代码需要在Bun环境下运行，使用minimal_loader.js加载：

### minimal_loader.js原理

```javascript
// Wrapper函数需要5个参数：exports, require, module, __filename, __dirname
// 提取的代码结尾是 "E_9();})" （wrapper闭合）
// 需要手动调用wrapper，传入正确参数
const code = fs.readFileSync(cli.js).trimEnd();
code = code.replace(/E_9\(\);\}\)\)$/, 
    'E_9();})(mod.exports, require, mod, modulePath, moduleDir)');
eval(code);
```

### 运行命令

```bash
cd bun_extracted_final

# 查看版本
bun minimal_loader.js --version
# 输出: 2.1.116 (Claude Code)

# 查看帮助
bun minimal_loader.js --help
# 输出完整帮助信息

# 交互式使用
bun minimal_loader.js
bun minimal_loader.js -c  # 继续上次会话
```

## 成功案例（claude.exe）

- **提取结果**: 成功提取13MB JS源码
- **入口模块**: B:/~BUN/root/src/entrypoints/cli.js
- **模块数量**: 7个（实际有效模块约4个）
- **跳过模块**: 文件名为空的padding模块自动跳过
- **运行测试**: ✅ --version、--help等命令完全正常

## 工具优势

### 对比其他方法

| 方法 | 基于原理 | 准确性 | 通用性 |
|------|----------|--------|--------|
| 手动边界查找 | JS代码特征 | 低 | 低 |
| 统计特征法 | ASCII比例 | 中 | 低 |
| 结构化解析 | Bun官方结构 | **高** | **高** |

### 核心优势

- **官方结构支持**: 基于Bun源码StandaloneModuleGraph.zig
- **精确定位**: 使用trailer标记和Offsets元数据
- **通用性强**: 适用于所有标准Bun打包程序
- **自动清理**: 跳过无效模块，避免错误

## 适用范围

### ✅ 适用场景

- Bun build --compile生成的exe
- 标准Bun打包的CLI工具
- 包含JS源码的Bun程序

### ⚠️ 可能不适用

- 非标准打包格式（无trailer标记）
- 纯bytecode程序（无JS源码）
- 使用特殊加密的打包

## 技术限制

1. **Bun版本依赖**: 提取的JS依赖Bun runtime
2. **Bytecode不可逆**: bytecode部分无法反编译为JS
3. **模块解析问题**: 部分模块结构可能异常（自动跳过处理）

## 故障排查

### 未找到.bun节区

**原因**: 不是Bun打包的程序
**解决**: 使用DIE工具验证是否为Bun Pack

### 未找到Bun trailer

**原因**: 使用了非标准打包方式
**解决**: 检查.bun section末尾是否有标准标记

### 模块提取失败

**原因**: 模块表结构异常或数据损坏
**解决**: 查看提取报告，检查跳过的模块数量

## 对比之前的工具

### bun_extractor.py（基于E_9函数名）

- 依赖特定函数名E_9
- 仅适用于claude.exe
- 不通用

### bun_extractor_final.py（统计特征法）

- 基于ASCII比例识别边界
- 对claude.exe边界识别失败
- 不稳定

### bun_extractor_reliable.py（结构化解析）

- ✅ 基于官方结构
- ✅ 精确可靠
- ✅ 通用性强
- ✅ 成功提取claude.exe

## 完整流程示例

```bash
# 1. 提取claude.exe
python bun_extractor_reliable.py claude.exe bun_extracted

# 2. 查看提取结果
ls bun_extracted/root/src/entrypoints/
# 输出: cli.js (13MB)

# 3. 创建minimal_loader.js（如工具未生成）
cat > bun_extracted/minimal_loader.js << 'EOF'
global.require = require;
const code = require('fs').readFileSync(__dirname + '/root/src/entrypoints/cli.js', 'utf-8');
eval(code);
EOF

# 4. 测试运行
cd bun_extracted
bun minimal_loader.js --version
bun minimal_loader.js --help
```

## 开发信息

- **基于**: Bun源码 StandaloneModuleGraph.zig
- **Python**: 3.x，无外部依赖
- **版本**: 1.0
- **日期**: 2026-04-22

## 总结

bun_extractor_reliable.py是目前最可靠的Bun打包exe提取工具，基于官方结构进行精确解析，成功提取claude.exe的13MB JS源码，具备良好的通用性和准确性。