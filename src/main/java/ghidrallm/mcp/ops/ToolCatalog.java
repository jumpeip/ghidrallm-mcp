package ghidrallm.mcp.ops;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidrallm.mcp.server.McpTool;

/**
 * Builds the full set of MCP tools exposed to LLM clients, wiring each to its handler in the
 * ops classes. Add new capabilities here as the surface grows.
 */
public final class ToolCatalog {

	private ToolCatalog() {
	}

	public static List<McpTool> build(GhidraBridge bridge, Gson gson) {
		ProgramOps program = new ProgramOps(bridge, gson);
		AnalysisOps analysis = new AnalysisOps(bridge, gson);
		FunctionOps function = new FunctionOps(bridge, gson);
		FunctionEditOps functionEdit = new FunctionEditOps(bridge, gson);
		SymbolOps symbol = new SymbolOps(bridge, gson);
		MemoryOps memory = new MemoryOps(bridge, gson);
		DataTypeOps dataType = new DataTypeOps(bridge, gson);
		SearchOps search = new SearchOps(bridge, gson);
		EmulationOps emulation = new EmulationOps(bridge, gson);
		ExportOps export = new ExportOps(bridge, gson);
		DecompilerEditOps decompilerEdit = new DecompilerEditOps(bridge, gson);
		NavigationOps navigation = new NavigationOps(bridge, gson);
		BookmarkOps bookmark = new BookmarkOps(bridge, gson);
		TypeExtraOps typeExtra = new TypeExtraOps(bridge, gson);
		FunctionAttrOps functionAttr = new FunctionAttrOps(bridge, gson);
		MemoryBlockOps memoryBlock = new MemoryBlockOps(bridge, gson);
		ProjectOps project2 = new ProjectOps(bridge, gson);
		DiscoveryOps discovery = new DiscoveryOps(bridge, gson);
		SecurityOps security = new SecurityOps(bridge, gson);
		MitigationOps mitigation = new MitigationOps(bridge, gson);

		List<McpTool> tools = new ArrayList<>();

		// ---- program / project ------------------------------------------------
		tools.add(new McpTool("list_open_programs",
			"List the programs currently open in Ghidra, with name, project path and function count.",
			schema(new String[] {}), program::listOpenPrograms));

		tools.add(new McpTool("get_current_program",
			"Return metadata for the program currently active in the Ghidra tool, or a message if none.",
			schema(new String[] {}), program::getCurrentProgram));

		tools.add(new McpTool("program_info",
			"Return detailed metadata (format, language, compiler spec, hashes, image base, address range) for a program.",
			schema(new String[] {}, "program", programProp()), program::programInfo));

		tools.add(new McpTool("list_memory_blocks",
			"List the memory blocks (segments) of a program with address ranges, permissions and init state.",
			schema(new String[] {}, "program", programProp()), program::listMemoryBlocks));

		tools.add(new McpTool("import_binary",
			"Import a binary file from disk into the active Ghidra project, open it, and (by default) run auto-analysis. " +
				"Use the loader's best-guess language. Returns the imported program's metadata.",
			schema(new String[] { "path" },
				"path", strProp("Absolute path to the binary file on the machine running Ghidra."),
				"analyze", boolProp("Run auto-analysis after import (default true)."),
				"folder", strProp("Destination project folder path (default \"/\").")),
			program::importBinary));

		tools.add(new McpTool("list_project_files",
			"List the program files in the active Ghidra project (name, path, content type).",
			schema(new String[] {}), project2::listProjectFiles));

		tools.add(new McpTool("open_program",
			"Open an existing program from the project by its path (from list_project_files).",
			schema(new String[] { "path" },
				"path", strProp("Project path of the program, e.g. '/thing.exe'.")),
			project2::openProgram));

		tools.add(new McpTool("close_program",
			"Close an open program. Fails if it has unsaved changes unless force=true.",
			schema(new String[] {},
				"program", programProp(),
				"force", boolProp("Discard unsaved changes and close anyway (default false).")),
			project2::closeProgram));

		// ---- analysis ---------------------------------------------------------
		tools.add(new McpTool("analyze_program",
			"Run (or re-run) Ghidra auto-analysis on a program using the currently enabled analyzers.",
			schema(new String[] {}, "program", programProp()), analysis::analyzeProgram));

		tools.add(new McpTool("list_analyzers",
			"List the available auto-analyzers for a program and whether each is enabled.",
			schema(new String[] {}, "program", programProp()), analysis::listAnalyzers));

		tools.add(new McpTool("set_analyzer_enabled",
			"Enable or disable a named analyzer before running analyze_program. Names come from list_analyzers.",
			schema(new String[] { "analyzer" },
				"program", programProp(),
				"analyzer", strProp("Exact analyzer name from list_analyzers."),
				"enabled", boolProp("True to enable, false to disable (default true).")),
			analysis::setAnalyzerEnabled));

		tools.add(new McpTool("get_analysis_options",
			"List analysis options (name, type, value) for a program, optionally filtered by a substring.",
			schema(new String[] {},
				"program", programProp(),
				"filter", strProp("Only include option names containing this substring (case-insensitive).")),
			analysis::getAnalysisOptions));

		tools.add(new McpTool("set_analysis_option",
			"Set a single analysis option to a value. The value is coerced to the option's declared type.",
			schema(new String[] { "name", "value" },
				"program", programProp(),
				"name", strProp("Exact option name from get_analysis_options."),
				"value", strProp("New value as a string (boolean/int/long/double/string/enum).")),
			analysis::setAnalysisOption));

		// ---- functions --------------------------------------------------------
		tools.add(new McpTool("list_functions",
			"List functions in a program with name, entry point and signature. Supports filter and paging.",
			schema(new String[] {},
				"program", programProp(),
				"filter", strProp("Only functions whose name contains this substring (case-insensitive)."),
				"offset", intProp("Number of matches to skip (default 0)."),
				"limit", intProp("Maximum functions to return (default 200, max 2000).")),
			function::listFunctions));

		tools.add(new McpTool("decompile_function",
			"Decompile a function to C. Identify it by 'address' (any address inside it) or by 'name'.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function (hex, e.g. 0x401000)."),
				"name", strProp("Exact function name (used if address is omitted)."),
				"timeout_seconds", intProp("Decompiler timeout in seconds (default 60).")),
			function::decompileFunction));

		tools.add(new McpTool("disassemble",
			"List disassembled instructions starting at an address (or a function's entry), with bytes.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("Start address (hex). If omitted, provide 'name' for a function entry."),
				"name", strProp("Function name whose entry point is the start (if address omitted)."),
				"count", intProp("Number of instructions to return (default 20, max 2000).")),
			function::disassemble));

		tools.add(new McpTool("rename_function",
			"Rename a function (identified by 'address' inside it or by current 'name') to 'new_name'.",
			schema(new String[] { "new_name" },
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Current function name (if address omitted)."),
				"new_name", strProp("New function name.")),
			function::renameFunction));

		tools.add(new McpTool("set_comment",
			"Set (or clear) a comment at an address. Comment types: eol, pre, post, plate, repeatable.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Address to comment (hex)."),
				"type", strProp("eol | pre | post | plate | repeatable (default eol)."),
				"comment", strProp("Comment text. Empty string clears the comment.")),
			function::setComment));

		tools.add(new McpTool("get_xrefs_to",
			"List cross-references pointing TO an address (callers / data references), with source functions.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Target address (hex)."),
				"limit", intProp("Maximum references to return (default 200).")),
			function::getXrefsTo));

		tools.add(new McpTool("get_xrefs_from",
			"List cross-references originating FROM an address (calls / data accesses made there).",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Source address (hex)."),
				"limit", intProp("Maximum references to return (default 200).")),
			function::getXrefsFrom));

		tools.add(new McpTool("disassemble_at",
			"Force disassembly of bytes starting at an address (e.g. undefined code or shellcode).",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Address to start disassembling (hex)."),
				"follow_flow", boolProp("Follow control flow to disassemble reachable code (default true).")),
			discovery::disassembleAt));

		tools.add(new McpTool("create_namespace",
			"Create (or get) a namespace under the global namespace.",
			schema(new String[] { "name" },
				"program", programProp(),
				"name", strProp("Namespace name.")),
			discovery::createNamespace));

		tools.add(new McpTool("get_comments",
			"List comments across a function's body, or an address range.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("Start address of a range (hex). If omitted, provide 'name'."),
				"length", intProp("Range length in bytes when 'address' is given (default 1)."),
				"name", strProp("Function name whose body to scan (if address omitted).")),
			discovery::getComments));

		// ---- symbols / strings / imports / exports ----------------------------
		tools.add(new McpTool("list_symbols",
			"List symbols (name, address, type, namespace) in a program. Supports filter and limit.",
			schema(new String[] {},
				"program", programProp(),
				"filter", strProp("Only symbols whose name contains this substring (case-insensitive)."),
				"limit", intProp("Maximum symbols to return (default 300).")),
			symbol::listSymbols));

		tools.add(new McpTool("list_strings",
			"List defined strings (address, value, length) in a program. Supports filter and limit.",
			schema(new String[] {},
				"program", programProp(),
				"filter", strProp("Only strings containing this substring (case-sensitive)."),
				"limit", intProp("Maximum strings to return (default 300).")),
			symbol::listStrings));

		tools.add(new McpTool("list_imports",
			"List imported (external) symbols and the libraries they come from.",
			schema(new String[] {},
				"program", programProp(),
				"limit", intProp("Maximum imports to return (default 1000).")),
			symbol::listImports));

		tools.add(new McpTool("list_exports",
			"List exported entry-point symbols of a program.",
			schema(new String[] {},
				"program", programProp(),
				"limit", intProp("Maximum exports to return (default 1000).")),
			symbol::listExports));

		tools.add(new McpTool("create_label",
			"Create a user-defined label (symbol) at an address.",
			schema(new String[] { "address", "name" },
				"program", programProp(),
				"address", strProp("Address for the label (hex)."),
				"name", strProp("Label name.")),
			symbol::createLabel));

		tools.add(new McpTool("rename_symbol",
			"Rename the primary symbol at an address to 'new_name'.",
			schema(new String[] { "address", "new_name" },
				"program", programProp(),
				"address", strProp("Address of the symbol (hex)."),
				"new_name", strProp("New symbol name.")),
			symbol::renameSymbol));

		// ---- memory / patching ------------------------------------------------
		tools.add(new McpTool("read_bytes",
			"Read raw bytes at an address and return them as hex plus an ASCII preview.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Address to read (hex)."),
				"length", intProp("Number of bytes to read (default 64, max 65536).")),
			memory::readBytes));

		tools.add(new McpTool("write_bytes",
			"Patch raw bytes at an address. Overwrites program memory; the block must be initialized and writable.",
			schema(new String[] { "address", "hex" },
				"program", programProp(),
				"address", strProp("Address to patch (hex)."),
				"hex", strProp("Replacement bytes as hex (whitespace/0x tolerated, e.g. '90 90' or '9090').")),
			memory::writeBytes));

		tools.add(new McpTool("assemble_instruction",
			"Assemble an instruction and patch it directly into program memory at an address. Returns the assembled bytes.",
			schema(new String[] { "address", "instruction" },
				"program", programProp(),
				"address", strProp("Address to assemble at (hex)."),
				"instruction", strProp("Assembly text for the target architecture, e.g. 'NOP' or 'MOV EAX,0'.")),
			memory::assembleInstruction));

		tools.add(new McpTool("create_memory_block",
			"Create a new initialized memory block (e.g. to map extra data or a scratch region).",
			schema(new String[] { "name", "address", "size" },
				"program", programProp(),
				"name", strProp("Block name."),
				"address", strProp("Start address (hex)."),
				"size", intProp("Block size in bytes (number, or pass a 0x-hex string)."),
				"fill", strProp("Fill byte for the block (default 0)."),
				"overlay", boolProp("Create as an overlay block (default false).")),
			memoryBlock::createMemoryBlock));

		tools.add(new McpTool("set_memory_permissions",
			"Set read/write/execute permissions on a memory block (identified by 'block' name or 'address').",
			schema(new String[] {},
				"program", programProp(),
				"block", strProp("Block name (or omit and give 'address')."),
				"address", strProp("Any address within the target block (hex)."),
				"read", boolProp("Set the read flag."),
				"write", boolProp("Set the write flag."),
				"execute", boolProp("Set the execute flag.")),
			memoryBlock::setMemoryPermissions));

		// ---- function editing -------------------------------------------------
		tools.add(new McpTool("create_function",
			"Create a function at an address (Ghidra determines the body). Optionally name it.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Entry-point address of the new function (hex)."),
				"name", strProp("Optional name for the new function.")),
			functionEdit::createFunction));

		tools.add(new McpTool("delete_function",
			"Delete a function (identified by 'address' inside it or by 'name').",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted).")),
			functionEdit::deleteFunction));

		tools.add(new McpTool("set_function_prototype",
			"Apply a full C prototype (return type, name and parameter types) to a function, " +
				"e.g. 'int process(char *buf, int len)'.",
			schema(new String[] { "prototype" },
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted)."),
				"prototype", strProp("C function prototype to apply.")),
			functionEdit::setFunctionPrototype));

		tools.add(new McpTool("list_variables",
			"List a function's parameters and local variables with their types and storage.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted).")),
			functionAttr::listVariables));

		tools.add(new McpTool("set_function_noreturn",
			"Mark a function as non-returning (or clear the flag). Affects analysis and decompilation.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted)."),
				"no_return", boolProp("True to mark no-return (default true).")),
			functionAttr::setFunctionNoReturn));

		tools.add(new McpTool("set_calling_convention",
			"Set a function's calling convention. Use list_calling_conventions for valid names.",
			schema(new String[] { "convention" },
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted)."),
				"convention", strProp("Calling convention name, e.g. '__stdcall', '__cdecl', '__fastcall'.")),
			functionAttr::setCallingConvention));

		tools.add(new McpTool("list_calling_conventions",
			"List the calling-convention names valid for a program.",
			schema(new String[] {}, "program", programProp()),
			functionAttr::listCallingConventions));

		// ---- data types -------------------------------------------------------
		tools.add(new McpTool("list_data_types",
			"List data types known to the program (name, path, length). Supports filter and limit.",
			schema(new String[] {},
				"program", programProp(),
				"filter", strProp("Only types whose name contains this substring (case-insensitive)."),
				"limit", intProp("Maximum types to return (default 300).")),
			dataType::listDataTypes));

		tools.add(new McpTool("define_struct",
			"Define a structure data type from a list of fields and add it to the program.",
			schema(new String[] { "name", "fields" },
				"program", programProp(),
				"name", strProp("Structure name."),
				"packed", boolProp("Enable packing (default false = fixed offsets by declared size)."),
				"fields", fieldsProp()),
			dataType::defineStruct));

		tools.add(new McpTool("apply_data_type",
			"Apply a data type at an address (e.g. 'int', 'char[16]', 'MyStruct', 'void *').",
			schema(new String[] { "address", "type" },
				"program", programProp(),
				"address", strProp("Address to type (hex)."),
				"type", strProp("Data type string resolvable in the program's type manager."),
				"clear", boolProp("Clear existing code/data in the way first (default true).")),
			dataType::applyDataType));

		tools.add(new McpTool("clear_data",
			"Clear defined code/data over a byte range, returning it to undefined bytes.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Start address (hex)."),
				"length", intProp("Number of bytes to clear (default 1).")),
			dataType::clearData));

		tools.add(new McpTool("get_data",
			"Return the defined data at an address: its type, length, value and display representation.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Address of the defined data (hex).")),
			dataType::getData));

		tools.add(new McpTool("define_enum",
			"Define an enumeration data type from name/value members and add it to the program.",
			schema(new String[] { "name", "values" },
				"program", programProp(),
				"name", strProp("Enum type name."),
				"size", intProp("Enum size in bytes: 1, 2, 4 or 8 (default 4)."),
				"values", objProp("Map of member name -> integer value (decimal or 0x hex string).")),
			typeExtra::defineEnum));

		tools.add(new McpTool("set_equate",
			"Attach a named constant (equate) to a scalar operand at an address.",
			schema(new String[] { "name", "value", "address" },
				"program", programProp(),
				"name", strProp("Equate (constant) name."),
				"value", strProp("The scalar value the equate names (decimal or 0x hex)."),
				"address", strProp("Instruction address (hex)."),
				"op_index", intProp("Operand index the scalar appears in (default 0).")),
			typeExtra::setEquate));

		// ---- search -----------------------------------------------------------
		tools.add(new McpTool("search_bytes",
			"Search program memory for a byte pattern with optional '??' wildcards, e.g. '8b ?? 90'.",
			schema(new String[] { "pattern" },
				"program", programProp(),
				"pattern", strProp("Hex byte pattern; '??' matches any byte. Whitespace tolerated."),
				"start", strProp("Address to start searching from (hex). Default: program start."),
				"limit", intProp("Maximum matches to return (default 100).")),
			search::searchBytes));

		tools.add(new McpTool("search_string",
			"Search program memory for a literal string in a given encoding.",
			schema(new String[] { "text" },
				"program", programProp(),
				"text", strProp("String to find."),
				"encoding", strProp("ascii | utf8 | utf16le | utf16be (default ascii)."),
				"start", strProp("Address to start searching from (hex). Default: program start."),
				"limit", intProp("Maximum matches to return (default 100).")),
			search::searchString));

		// ---- emulation --------------------------------------------------------
		tools.add(new McpTool("emulate",
			"Emulate code from a start address for up to max_steps instructions, with optional seeded " +
				"registers and a stop address, then read back registers and memory. Does not modify the program.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Start address for emulation (hex)."),
				"stop", strProp("Optional address to stop at (breakpoint)."),
				"max_steps", intProp("Maximum instructions to execute (default 1000)."),
				"registers", objProp("Optional map of register name -> value (decimal or 0x hex string)."),
				"read_registers", arrProp("Register names to read after the run.", strItems()),
				"read_memory", arrProp("Memory ranges to read after the run.", memSpecItems())),
			emulation::emulate));

		// ---- decompiler-level variable editing --------------------------------
		tools.add(new McpTool("rename_variable",
			"Rename a local variable or parameter (by the name the decompiler shows) within a function.",
			schema(new String[] { "variable", "new_name" },
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted)."),
				"variable", strProp("Current variable name as shown by decompile_function."),
				"new_name", strProp("New variable name.")),
			decompilerEdit::renameVariable));

		tools.add(new McpTool("set_variable_type",
			"Set the data type of a local variable or parameter within a function.",
			schema(new String[] { "variable", "type" },
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted)."),
				"variable", strProp("Variable name as shown by decompile_function."),
				"type", strProp("New data type, e.g. 'int', 'char *', 'MyStruct'.")),
			decompilerEdit::setVariableType));

		// ---- call graph & pcode ----------------------------------------------
		tools.add(new McpTool("get_callers",
			"List functions that call the given function.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted).")),
			navigation::getCallers));

		tools.add(new McpTool("get_callees",
			"List functions called by the given function.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted).")),
			navigation::getCallees));

		tools.add(new McpTool("get_pcode",
			"Return raw P-code for each instruction of a function, or for a range starting at an address.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("Start address (hex). If omitted, provide 'name' for a function."),
				"name", strProp("Function name whose body to list (if address omitted)."),
				"count", intProp("Maximum instructions to include (default 100).")),
			navigation::getPcode));

		// ---- bookmarks --------------------------------------------------------
		tools.add(new McpTool("set_bookmark",
			"Add a bookmark at an address (e.g. to flag a finding). Default type 'Note'.",
			schema(new String[] { "address" },
				"program", programProp(),
				"address", strProp("Address to bookmark (hex)."),
				"type", strProp("Bookmark type: Note | Info | Warning | Error | Analysis (default Note)."),
				"category", strProp("Bookmark category (default 'GhidraMCP')."),
				"comment", strProp("Bookmark comment text.")),
			bookmark::setBookmark));

		tools.add(new McpTool("list_bookmarks",
			"List bookmarks in a program, optionally filtered by type.",
			schema(new String[] {},
				"program", programProp(),
				"type", strProp("Only this bookmark type (e.g. Note). Omit for all."),
				"limit", intProp("Maximum bookmarks to return (default 500).")),
			bookmark::listBookmarks));

		// ---- persistence / export --------------------------------------------
		tools.add(new McpTool("save_program",
			"Save the program (including patches) back into the Ghidra project.",
			schema(new String[] {}, "program", programProp()), export::saveProgram));

		tools.add(new McpTool("export_program",
			"Export the program's (patched) bytes to a file on disk. Currently supports the 'binary' format.",
			schema(new String[] { "path" },
				"program", programProp(),
				"path", strProp("Absolute output file path on the machine running Ghidra."),
				"format", strProp("Export format (only 'binary' is supported; default binary).")),
			export::exportProgram));

		// ---- security / RE / vuln analysis ------------------------------------
		tools.add(new McpTool("find_dangerous_functions",
			"Find call sites to memory-unsafe APIs (strcpy, sprintf, gets, system, memcpy, ...). " +
				"Prime leads for buffer-overflow / command-injection review.",
			schema(new String[] {},
				"program", programProp(),
				"extra", arrProp("Extra function names to treat as dangerous.", strItems()),
				"limit", intProp("Maximum call sites to return (default 500).")),
			security::findDangerousFunctions));

		tools.add(new McpTool("analyze_imports",
			"Map imported APIs to capability tags (network, process_injection, exec_memory, " +
				"persistence, crypto, anti_debug, privilege, info_stealing, filesystem, dynamic_api).",
			schema(new String[] {}, "program", programProp()),
			security::analyzeImports));

		tools.add(new McpTool("find_anti_debug",
			"Report anti-debugging indicators: anti-debug API imports plus instructions like " +
				"RDTSC, CPUID, INT3 and INT 2Dh.",
			schema(new String[] {},
				"program", programProp(),
				"max_instructions", intProp("Instruction scan cap (default 400000).")),
			security::findAntiDebug));

		tools.add(new McpTool("check_security_mitigations",
			"Report exploit mitigations: NX/DEP, ASLR, CFG, SEH and stack canary (PE via header " +
				"flags; ELF via program headers and symbols).",
			schema(new String[] {}, "program", programProp()),
			mitigation::checkSecurityMitigations));

		tools.add(new McpTool("find_crypto_constants",
			"Scan memory for well-known crypto constant tables (AES S-boxes, SHA/MD5 init, " +
				"base64 alphabet, MT19937) and report where they appear.",
			schema(new String[] {},
				"program", programProp(),
				"max_per_signature", intProp("Maximum matches per signature (default 3).")),
			mitigation::findCryptoConstants));

		tools.add(new McpTool("find_string_references",
			"Find defined strings containing a substring and the code locations that reference them.",
			schema(new String[] { "text" },
				"program", programProp(),
				"text", strProp("Substring to match within defined strings."),
				"limit", intProp("Maximum strings to return (default 100).")),
			security::findStringReferences));

		tools.add(new McpTool("find_immediate",
			"Find instructions that use a given constant/immediate value (magic numbers, syscall #s).",
			schema(new String[] { "value" },
				"program", programProp(),
				"value", strProp("The constant to find (decimal or 0x hex)."),
				"limit", intProp("Maximum matches (default 200)."),
				"max_instructions", intProp("Instruction scan cap (default 500000).")),
			security::findImmediate));

		tools.add(new McpTool("find_writable_executable",
			"List memory blocks that are both writable and executable (self-modifying / shellcode clue).",
			schema(new String[] {}, "program", programProp()),
			security::findWritableExecutable));

		tools.add(new McpTool("analyze_function_security",
			"Triage one function: size, instruction/branch counts, approx cyclomatic complexity, " +
				"stack frame size, parameter count, and any dangerous calls it makes.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted).")),
			security::analyzeFunctionSecurity));

		tools.add(new McpTool("get_call_tree",
			"Walk the call graph from a function, following callees (default) or callers to a depth.",
			schema(new String[] {},
				"program", programProp(),
				"address", strProp("An address within the function."),
				"name", strProp("Function name (if address omitted)."),
				"direction", strProp("callees (default) or callers."),
				"depth", intProp("Maximum recursion depth (default 3, max 10)."),
				"max_nodes", intProp("Node budget (default 200).")),
			security::getCallTree));

		return tools;
	}

	// ------------------------------------------------------------ schema helpers

	private static JsonObject programProp() {
		return strProp("Optional program name (from list_open_programs). Defaults to the active program.");
	}

	private static JsonObject strProp(String description) {
		return typedProp("string", description);
	}

	private static JsonObject intProp(String description) {
		return typedProp("integer", description);
	}

	private static JsonObject boolProp(String description) {
		return typedProp("boolean", description);
	}

	private static JsonObject typedProp(String type, String description) {
		JsonObject o = new JsonObject();
		o.addProperty("type", type);
		o.addProperty("description", description);
		return o;
	}

	private static JsonObject objProp(String description) {
		JsonObject o = new JsonObject();
		o.addProperty("type", "object");
		o.addProperty("description", description);
		o.addProperty("additionalProperties", true);
		return o;
	}

	private static JsonObject arrProp(String description, JsonObject items) {
		JsonObject o = new JsonObject();
		o.addProperty("type", "array");
		o.addProperty("description", description);
		o.add("items", items);
		return o;
	}

	private static JsonObject strItems() {
		JsonObject o = new JsonObject();
		o.addProperty("type", "string");
		return o;
	}

	private static JsonObject memSpecItems() {
		return schema(new String[] { "address" },
			"address", strProp("Address to read (hex)."),
			"length", intProp("Number of bytes (default 16)."));
	}

	private static JsonObject fieldsProp() {
		JsonObject items = schema(new String[] { "type" },
			"type", strProp("Field data type (e.g. 'int', 'char[8]', 'void *')."),
			"name", strProp("Field name."),
			"size", intProp("Override field size in bytes (default: the type's length)."),
			"comment", strProp("Optional field comment."));
		return arrProp("Ordered list of struct fields.", items);
	}

	/**
	 * Builds an object JSON-Schema. {@code required} is the list of required property names;
	 * {@code kv} is an alternating sequence of (name, JsonObject-propertySchema) pairs.
	 */
	private static JsonObject schema(String[] required, Object... kv) {
		JsonObject s = new JsonObject();
		s.addProperty("type", "object");
		JsonObject props = new JsonObject();
		for (int i = 0; i + 1 < kv.length; i += 2) {
			props.add((String) kv[i], (JsonObject) kv[i + 1]);
		}
		s.add("properties", props);
		JsonArray req = new JsonArray();
		for (String r : required) {
			req.add(r);
		}
		s.add("required", req);
		s.addProperty("additionalProperties", false);
		return s;
	}
}
