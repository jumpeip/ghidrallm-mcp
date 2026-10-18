# GhidraMCP

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Ghidra](https://img.shields.io/badge/Ghidra-12.1.4-red)
![Transport](https://img.shields.io/badge/MCP-Streamable_HTTP-green)
![Tools](https://img.shields.io/badge/tools-70-purple)

A Ghidra extension (for **Ghidra 12.1.4**) that embeds a **Model Context Protocol (MCP)**
server directly inside Ghidra. It lets an external LLM agent — Claude Code, Codex, Cline, or
any MCP client — drive Ghidra for reverse engineering, vulnerability assessment, penetration
testing, and binary patching.

The server speaks the **MCP Streamable-HTTP transport (JSON-RPC 2.0 over HTTP)** natively in
Java. There is **no Python bridge** and no third-party dependency: it uses only the JDK's
built-in `com.sun.net.httpserver` and the Gson that already ships with Ghidra.

> Intended for authorized security work (your own binaries, engagements you are permitted to
> perform, CTFs, research). The endpoint binds to `127.0.0.1` and is unauthenticated — treat
> it like a local debug port.

---

## 1. Build

Prerequisites: a JDK (21+) and Gradle, and a Ghidra 12.1.4 install.

```bash
set GHIDRA_INSTALL_DIR=D:\ghidra_12.1.4_PUBLIC   # Windows (PowerShell: $env:GHIDRA_INSTALL_DIR=...)
gradle -p d:\claude_work\ghidrallm\mcp-server buildExtension
```

The installable extension zip is written to `dist/`, e.g.:

```
dist/ghidra_12.1.4_PUBLIC_<date>_mcp-server.zip
```

## 2. Install into Ghidra

1. Start Ghidra.
2. `File > Install Extensions…`
3. Click the **+** (Add extension) and select the zip from `dist/`.
4. Restart Ghidra when prompted.
5. Open the **CodeBrowser** tool (open any program, or `Tools`/empty CodeBrowser).
6. `File > Configure…` → **Miscellaneous** → tick **GhidraMcpPlugin** → OK.

The server **auto-starts** when the tool opens. You'll see a status-bar message like
`GhidraMCP listening at http://127.0.0.1:8765/mcp (70 tools)`.

Menu **GhidraMCP** (in the CodeBrowser menu bar):
- **Start MCP Server** / **Stop MCP Server**
- **Server Status…** — shows the endpoint URL and client command.

Settings live under `Edit > Tool Options > GhidraMCP`:
- **Port** (default `8765`)
- **Bind Address** (default `127.0.0.1` — keep it unless you understand the exposure)
- **Auto-start** (default `true`)

Quick check (with the server running):

```bash
curl http://127.0.0.1:8765/health
```

## 3. Connect an LLM client

**Claude Code**

```bash
claude mcp add --transport http ghidra http://127.0.0.1:8765/mcp
```

**Generic MCP client config** (shape varies by client):

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

Then ask the agent to, e.g., *"list the open programs in Ghidra,"* *"import
`C:\samples\thing.exe` and analyze it,"* or *"decompile the function at 0x401000."*

---

## 4. Tools

Every tool takes an optional `program` argument (a name from `list_open_programs`); when
omitted it acts on the program currently active in Ghidra. Addresses are hex strings
(e.g. `0x401000`).

### Program / project
| Tool | Purpose |
|------|---------|
| `list_open_programs` | Programs currently open, with path and function count. |
| `get_current_program` | Metadata for the active program. |
| `program_info` | Full metadata (format, language, compiler spec, hashes, image base, range). |
| `list_memory_blocks` | Memory segments with ranges, `rwx` permissions, init state. |
| `import_binary` | Import a file from disk, open it, optionally auto-analyze. |
| `list_project_files` | List program files in the active project. |
| `open_program` | Open an existing project program by path. |
| `close_program` | Close an open program (`force` to discard changes). |

### Analysis control
| Tool | Purpose |
|------|---------|
| `analyze_program` | Run / re-run auto-analysis with the enabled analyzers. |
| `list_analyzers` | List analyzers and whether each is enabled. |
| `set_analyzer_enabled` | Enable/disable a named analyzer before analysis. |
| `get_analysis_options` | List analysis options (name, type, value). |
| `set_analysis_option` | Set one analysis option (value coerced to its type). |

### Functions
| Tool | Purpose |
|------|---------|
| `list_functions` | List functions (filter + paging). |
| `decompile_function` | Decompile a function to C (by address or name). |
| `disassemble` | Instructions from an address or function entry, with bytes. |
| `disassemble_at` | Force-disassemble bytes at an address (e.g. shellcode). |
| `get_comments` | List comments across a function body or address range. |
| `rename_function` | Rename a function. |
| `set_comment` | Set/clear a comment (`eol`/`pre`/`post`/`plate`/`repeatable`). |
| `get_xrefs_to` | References pointing to an address (callers). |
| `get_xrefs_from` | References from an address. |
| `create_function` | Create a function at an address (optionally named). |
| `delete_function` | Delete a function (by address or name). |
| `set_function_prototype` | Apply a full C prototype (return/name/params) to a function. |
| `rename_variable` | Rename a local/parameter (decompiler name) in a function. |
| `set_variable_type` | Retype a local/parameter in a function. |
| `get_callers` | Functions that call this function. |
| `get_callees` | Functions this function calls. |
| `get_pcode` | Raw P-code per instruction (function body or address range). |
| `list_variables` | A function's parameters and locals, with types and storage. |
| `set_function_noreturn` | Mark/clear a function as non-returning. |
| `set_calling_convention` | Set a function's calling convention. |
| `list_calling_conventions` | Valid calling-convention names for the program. |

### Symbols / strings / imports / exports
| Tool | Purpose |
|------|---------|
| `list_symbols` | Symbols (name, address, type, namespace). |
| `list_strings` | Defined strings (address, value). |
| `list_imports` | Imported (external) symbols and libraries. |
| `list_exports` | Exported entry-point symbols. |
| `create_label` | Create a user label at an address. |
| `rename_symbol` | Rename the primary symbol at an address. |
| `create_namespace` | Create (or get) a namespace under the global namespace. |

### Data types
| Tool | Purpose |
|------|---------|
| `list_data_types` | List known data types (name, path, length). |
| `define_struct` | Define a structure from a list of fields and add it to the program. |
| `apply_data_type` | Apply a type at an address (e.g. `int`, `char[16]`, `MyStruct`, `void *`). |
| `clear_data` | Clear code/data over a byte range back to undefined. |
| `get_data` | The defined data at an address: type, length, value, representation. |
| `define_enum` | Define an enumeration type from name/value members. |
| `set_equate` | Attach a named constant (equate) to a scalar operand. |

### Search
| Tool | Purpose |
|------|---------|
| `search_bytes` | Byte-pattern search with `??` wildcards, e.g. `8b ?? 90`. |
| `search_string` | Literal string search (`ascii`/`utf8`/`utf16le`/`utf16be`). |

### Memory / patching
| Tool | Purpose |
|------|---------|
| `read_bytes` | Read raw bytes → hex + ASCII preview. |
| `write_bytes` | Patch raw bytes at an address. |
| `assemble_instruction` | Assemble an instruction and patch it into memory. |
| `create_memory_block` | Create a new initialized memory block. |
| `set_memory_permissions` | Set a block's read/write/execute flags. |

### Emulation
| Tool | Purpose |
|------|---------|
| `emulate` | Run code from a start address for up to N instructions, with seeded registers and an optional stop address; reads back registers and memory. Runs over a copy-on-write view, so it does not modify the program. |

### Bookmarks
| Tool | Purpose |
|------|---------|
| `set_bookmark` | Mark an address (e.g. a finding). Types: Note/Info/Warning/Error/Analysis. |
| `list_bookmarks` | List bookmarks, optionally filtered by type. |

### Persistence / export
| Tool | Purpose |
|------|---------|
| `save_program` | Save the program (with patches) back into the Ghidra project. |
| `export_program` | Export the program's patched bytes to a file (`binary` format). |

### Security / RE / vulnerability analysis
| Tool | Purpose |
|------|---------|
| `find_dangerous_functions` | Call sites to unsafe APIs (strcpy, sprintf, gets, system, memcpy, …) — overflow/injection leads. |
| `analyze_imports` | Map imports to capability tags (network, process_injection, exec_memory, persistence, crypto, anti_debug, privilege, info_stealing, filesystem, dynamic_api). |
| `find_anti_debug` | Anti-debug API imports + instructions (RDTSC, CPUID, INT3, INT 2Dh). |
| `check_security_mitigations` | NX/DEP, ASLR, CFG, SEH, stack canary (PE header flags; ELF program headers/symbols). |
| `find_crypto_constants` | Scan for AES S-boxes, SHA/MD5 init, base64 alphabet, MT19937 constants. |
| `find_string_references` | Strings matching a substring + the code that references them. |
| `find_immediate` | Instructions using a given constant (magic values, syscall numbers). |
| `find_writable_executable` | W+X memory blocks (self-modifying / shellcode clue). |
| `analyze_function_security` | Per-function triage: size, branches, approx cyclomatic, stack frame, dangerous calls. |
| `get_call_tree` | Walk callees/callers from a function to a given depth. |

Edits (renames, comments, labels, patches) each run in their own Ghidra transaction, so
they are individually undoable (`Ctrl+Z`) in the GUI. Patches change the in-memory program;
save the program (or export it) to persist them.

---

## 5. Architecture

```
MCP client (Claude Code / Codex / …)
        │  HTTP POST  (JSON-RPC 2.0, MCP Streamable-HTTP)
        ▼
ghidrallm.mcp.server.McpServer        com.sun.net.httpserver, no external deps
   initialize / tools/list / tools/call
        ▼
ghidrallm.mcp.ops.ToolCatalog         tool defs + JSON schemas
        ▼
ProgramOps · ProjectOps · AnalysisOps · FunctionOps · FunctionEditOps · FunctionAttrOps
DecompilerEditOps · SymbolOps · MemoryOps · MemoryBlockOps · DataTypeOps · TypeExtraOps
SearchOps · EmulationOps · NavigationOps · DiscoveryOps · BookmarkOps · ExportOps
SecurityOps · MitigationOps
        ▼
ghidrallm.mcp.ops.GhidraBridge        program resolution, transactions, Swing marshalling
        ▼
Ghidra program API (ProgramLoader, AutoAnalysisManager, DecompInterface, Assemblers, …)
```

- Reads run on the HTTP worker thread. Writes/analysis run inside a program transaction.
  Opening imported programs is marshalled onto the Swing thread.
- `POST /mcp` handles JSON-RPC requests, notifications, and batches. `GET /mcp` returns 405
  (the server does not push SSE). `GET /health` returns a small JSON status.

## 6. Extending

Add a handler method to the relevant `*Ops` class and register it in
`ghidrallm.mcp.ops.ToolCatalog.build(...)` with a name, description, and JSON schema. Rebuild
and reinstall. No protocol code changes are needed — `tools/list` is generated from the catalog.

## 7. Security notes

- The endpoint is **unauthenticated**; anything that can reach the port can control Ghidra and
  read/patch loaded programs. Keep the bind address on `127.0.0.1`.
- `import_binary` reads files from the machine running Ghidra, and patch tools modify program
  memory. Only connect clients you trust.
- This is a standalone extension; it does not modify or depend on the separate `GhidraLLM`
  renaming extension in the parent directory.
- The build prints a deprecation warning for `EmulatorHelper` (used by `emulate`). It is present
  and functional in Ghidra 12.1.4; if a future Ghidra removes it, migrate `EmulationOps` to the
  `ghidra.pcode.emu` API.
