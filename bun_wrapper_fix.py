#!/usr/bin/env python3
"""
Bun JS Wrapper Fix Tool

Usage:
    python bun_wrapper_fix.py <input.js> [output.js]
"""

import re
import sys
import base64


def find_wrapper_function(content):
    """Auto-detect Bun wrapper function name"""
    content = content.rstrip()
    pattern = r'([A-Z][A-Z0-9_]{1,6})\(\);\}\)'
    matches = list(re.finditer(pattern, content))
    if not matches:
        return None, content
    last_match = matches[-1]
    func_name = last_match.group(1)
    return func_name, content


def generate_polyfill():
    """Generate module polyfill with explicit if statements"""
    modules = [
        'fs', 'path', 'url', 'crypto', 'os', 'net', 'tls',
        'http', 'https', 'zlib', 'buffer', 'stream', 'events', 'util',
        'querystring', 'string_decoder', 'punycode', 'readline',
        'child_process', 'constants', 'domain', 'vm', 'assert', 'tty',
        'dgram', 'module', 'perf_hooks', 'v8', 'async_hooks',
        'worker_threads', 'diagnostics_channel', 'trace_events',
        'http2', 'wasi',
    ]

    lines = ["const mod = {", "  exports: {},", '  id: "cli.js",', '  filename: "cli.js",', "  require: (id) => {",
             "    if (id === 'node:process' || id === 'process') return process;"]
    for m in modules:
        lines.append("    if (id === 'node:" + m + "' || id === '" + m + "') return require('" + m + "');")
    lines.extend([
        "    if (id.startsWith('node:')) id = id.substring(5);",
        "    return require(id);",
        "  }",
        "};",
    ])
    return '\n'.join(lines)


def process_js_file(input_path, output_path=None):
    if output_path is None:
        if input_path.endswith('.js'):
            output_path = input_path[:-3] + '_inline.js'
        else:
            output_path = input_path + '_inline.js'

    print("Reading: " + input_path)
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()

    print("Size: " + str(len(content)) + " bytes")

    func_name, content = find_wrapper_function(content)
    if func_name is None:
        print("Warning: No Bun wrapper found")
        func_name = "UNKNOWN"
        wrapper_end = ""
    else:
        print("Found wrapper: " + func_name)
        wrapper_end = func_name + "();})"

    encoded = base64.b64encode(content.encode('utf-8')).decode('ascii')
    polyfill = generate_polyfill()

    wrapper_call = func_name + '();})(mod.exports, mod.require, mod, "cli.js", ".")'

    lines = [
        '// Bun Wrapper Fixed (auto-generated)',
        '// Wrapper function: ' + func_name,
        '',
        'const CODE = decodeURIComponent(escape(atob("' + encoded + '")));',
        '',
        polyfill,
        '',
        'let execCode = CODE.trimEnd();',
        'const WRAPPER_END = \'' + wrapper_end + '\';',
        '',
        'if (execCode.endsWith(WRAPPER_END)) {',
        '  execCode = execCode.slice(0, -WRAPPER_END.length) + \'' + wrapper_call + '\';',
        '}',
        '',
        'global.module = mod;',
        'global.exports = mod.exports;',
        'global.require = mod.require;',
        'global.__filename = "cli.js";',
        'global.__dirname = ".";',
        '',
        'eval(execCode);',
    ]

    final_code = '\n'.join(lines)

    print("Writing: " + output_path)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(final_code)

    return output_path, func_name


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        output, func_name = process_js_file(input_path, output_path)
        print("\nDone!")
        print("Output: " + output)
        print("Wrapper: " + func_name)
        print("\nTest:")
        print("  bun run " + output + " --version")
        print("  bun run " + output + " --help")
        print("\nBuild exe:")
        print("  bun build " + output + " --compile --target=bun-windows-x64-modern --outfile output.exe")
    except FileNotFoundError:
        print("Error: File not found - " + input_path)
        sys.exit(1)
    except Exception as e:
        print("Error: " + str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
