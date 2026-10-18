package ghidrallm.mcp.ops;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidrallm.mcp.server.ToolException;

/**
 * Security-oriented analysis built on top of the primitive tools: unsafe-API call sites,
 * import capability mapping, anti-debug indicators, W^X blocks, immediate/constant hunting,
 * string cross-references, per-function risk triage, and call-tree reachability.
 */
public class SecurityOps {

	/** Classic memory-unsafe C/Win32 string and exec functions. */
	private static final String[] DANGEROUS = {
		"strcpy", "strcpyA", "strcpyW", "lstrcpy", "lstrcpyA", "lstrcpyW",
		"strcat", "lstrcat", "lstrcatA", "lstrcatW", "wcscpy", "wcscat",
		"sprintf", "vsprintf", "swprintf", "wsprintf", "wsprintfA", "wsprintfW",
		"gets", "getws", "scanf", "sscanf", "wscanf", "swscanf", "vscanf",
		"memcpy", "memmove", "strncpy", "strncat", "stpcpy", "alloca",
		"system", "popen", "exec", "execl", "execlp", "execle", "execv", "execvp", "execve",
		"WinExec", "ShellExecuteA", "ShellExecuteW"
	};

	/** import-name substring -> capability category (lower-cased match). */
	private static final Map<String, String> CAPABILITY = buildCapabilityMap();

	/**
	 * Exact-name (lower-cased) -> category, for ambiguous short tokens like the Winsock
	 * {@code send}/{@code recv} verbs that must NOT match substrings such as SendMessage.
	 */
	private static final Map<String, String> EXACT_CAPABILITY = Map.ofEntries(
		Map.entry("send", "network"), Map.entry("recv", "network"),
		Map.entry("sendto", "network"), Map.entry("recvfrom", "network"),
		Map.entry("wsasend", "network"), Map.entry("wsarecv", "network"),
		Map.entry("connect", "network"), Map.entry("bind", "network"),
		Map.entry("listen", "network"), Map.entry("accept", "network"),
		Map.entry("acceptex", "network"));

	private final GhidraBridge bridge;
	private final Gson gson;

	public SecurityOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	// ------------------------------------------------------------ dangerous calls

	public String findDangerousFunctions(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		int limit = clamp(GhidraBridge.intArg(args, "limit", 500), 5000);
		SymbolTable st = p.getSymbolTable();
		ReferenceManager rm = p.getReferenceManager();

		Set<String> names = new LinkedHashSet<>();
		for (String n : DANGEROUS) {
			names.add(n);
		}
		if (args.has("extra") && args.get("extra").isJsonArray()) {
			args.getAsJsonArray("extra").forEach(e -> names.add(e.getAsString()));
		}

		JsonArray findings = new JsonArray();
		Set<String> seen = new LinkedHashSet<>();
		Map<String, Integer> byFunc = new TreeMap<>();
		for (String name : names) {
			SymbolIterator syms = st.getSymbols(name);
			for (Symbol sym : syms) {
				ReferenceIterator refs = rm.getReferencesTo(sym.getAddress());
				while (refs.hasNext()) {
					Reference r = refs.next();
					if (!r.getReferenceType().isCall()) {
						continue;
					}
					String key = r.getFromAddress() + "->" + name;
					if (!seen.add(key)) {
						continue;
					}
					Function caller = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
					String callerName = caller == null ? "(none)" : caller.getName();
					byFunc.merge(callerName, 1, Integer::sum);
					if (findings.size() < limit) {
						JsonObject o = new JsonObject();
						o.addProperty("api", name);
						o.addProperty("callSite", r.getFromAddress().toString());
						o.addProperty("callerFunction", callerName);
						findings.add(o);
					}
				}
			}
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", findings.size());
		o.add("findings", findings);
		JsonObject summary = new JsonObject();
		byFunc.forEach(summary::addProperty);
		o.add("callsPerFunction", summary);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ import capability mapping

	public String analyzeImports(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		SymbolTable st = p.getSymbolTable();
		Map<String, List<String>> categories = new TreeMap<>();
		SymbolIterator it = st.getExternalSymbols();
		int total = 0;
		while (it.hasNext()) {
			Symbol s = it.next();
			String apiName = s.getName();
			total++;
			String lower = apiName.toLowerCase();
			for (Map.Entry<String, String> e : CAPABILITY.entrySet()) {
				if (lower.contains(e.getKey())) {
					categories.computeIfAbsent(e.getValue(), k -> new ArrayList<>()).add(apiName);
				}
			}
			String exact = EXACT_CAPABILITY.get(lower);
			if (exact != null) {
				categories.computeIfAbsent(exact, k -> new ArrayList<>()).add(apiName);
			}
		}
		JsonObject cats = new JsonObject();
		for (Map.Entry<String, List<String>> e : categories.entrySet()) {
			JsonArray arr = new JsonArray();
			// de-dup while preserving order
			for (String n : new LinkedHashSet<>(e.getValue())) {
				arr.add(n);
			}
			cats.add(e.getKey(), arr);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("totalImports", total);
		JsonArray tags = new JsonArray();
		categories.keySet().forEach(tags::add);
		o.add("capabilityTags", tags);
		o.add("byCapability", cats);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ anti-debug

	public String findAntiDebug(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String[] antiDbgApis = {
			"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
			"OutputDebugString", "NtSetInformationThread", "GetTickCount", "QueryPerformanceCounter",
			" NtGlobalFlag", "DebugActiveProcess", "NtClose", "GetLocalTime", "GetSystemTime"
		};
		JsonArray apiHits = new JsonArray();
		SymbolTable st = p.getSymbolTable();
		for (String api : antiDbgApis) {
			String name = api.trim();
			SymbolIterator syms = st.getSymbols(name);
			for (Symbol s : syms) {
				if (s.isExternal() || p.getFunctionManager().getFunctionAt(s.getAddress()) != null) {
					JsonObject o = new JsonObject();
					o.addProperty("api", name);
					o.addProperty("address", String.valueOf(s.getAddress()));
					apiHits.add(o);
					break;
				}
			}
		}

		JsonArray instrHits = new JsonArray();
		int scanned = 0;
		int cap = GhidraBridge.intArg(args, "max_instructions", 400000);
		InstructionIterator it = p.getListing().getInstructions(true);
		while (it.hasNext() && scanned < cap && instrHits.size() < 500) {
			Instruction instr = it.next();
			scanned++;
			String m = instr.getMnemonicString().toUpperCase();
			boolean hit = m.equals("RDTSC") || m.equals("RDTSCP") || m.equals("CPUID")
				|| m.equals("INT3") || m.equals("INT1")
				|| (m.equals("INT") && operandIsValue(instr, 0x2d));
			if (hit) {
				JsonObject o = new JsonObject();
				o.addProperty("address", instr.getAddress().toString());
				o.addProperty("instruction", instr.toString());
				instrHits.add(o);
			}
		}

		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.add("antiDebugApis", apiHits);
		o.add("antiDebugInstructions", instrHits);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ W^X blocks

	public String findWritableExecutable(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		JsonArray arr = new JsonArray();
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			if (b.isWrite() && b.isExecute()) {
				JsonObject o = new JsonObject();
				o.addProperty("name", b.getName());
				o.addProperty("start", b.getStart().toString());
				o.addProperty("end", b.getEnd().toString());
				o.addProperty("size", b.getSize());
				arr.add(o);
			}
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.addProperty("note", arr.size() == 0 ? "No writable+executable blocks."
			: "Writable+executable memory can indicate self-modifying code, packers, or shellcode.");
		o.add("blocks", arr);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ immediate / constant search

	public String findImmediate(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		long value = GhidraBridge.longFromStr(GhidraBridge.reqStr(args, "value"));
		int limit = clamp(GhidraBridge.intArg(args, "limit", 200), 5000);
		int cap = GhidraBridge.intArg(args, "max_instructions", 500000);
		JsonArray hits = new JsonArray();
		int scanned = 0;
		InstructionIterator it = p.getListing().getInstructions(true);
		while (it.hasNext() && hits.size() < limit && scanned < cap) {
			Instruction instr = it.next();
			scanned++;
			if (operandIsValue(instr, value)) {
				JsonObject o = new JsonObject();
				o.addProperty("address", instr.getAddress().toString());
				o.addProperty("instruction", instr.toString());
				Function f = p.getFunctionManager().getFunctionContaining(instr.getAddress());
				if (f != null) {
					o.addProperty("function", f.getName());
				}
				hits.add(o);
			}
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("value", value);
		o.addProperty("count", hits.size());
		o.add("matches", hits);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ string xrefs

	public String findStringReferences(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String needle = GhidraBridge.reqStr(args, "text");
		int limit = clamp(GhidraBridge.intArg(args, "limit", 100), 2000);
		ReferenceManager rm = p.getReferenceManager();
		JsonArray arr = new JsonArray();
		var data = p.getListing().getDefinedData(true);
		while (data.hasNext() && arr.size() < limit) {
			var d = data.next();
			Object v = d.getValue();
			if (!(v instanceof String s) || !s.contains(needle)) {
				continue;
			}
			JsonArray refs = new JsonArray();
			ReferenceIterator it = rm.getReferencesTo(d.getAddress());
			while (it.hasNext()) {
				Reference r = it.next();
				JsonObject ro = new JsonObject();
				ro.addProperty("from", r.getFromAddress().toString());
				Function f = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
				if (f != null) {
					ro.addProperty("function", f.getName());
				}
				refs.add(ro);
			}
			JsonObject o = new JsonObject();
			o.addProperty("address", d.getAddress().toString());
			o.addProperty("string", s);
			o.addProperty("refCount", refs.size());
			o.add("references", refs);
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("query", needle);
		o.addProperty("count", arr.size());
		o.add("strings", arr);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ per-function triage

	public String analyzeFunctionSecurity(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		Set<String> dangerous = new LinkedHashSet<>();
		for (String n : DANGEROUS) {
			dangerous.add(n);
		}

		int instructions = 0;
		int branches = 0;
		int calls = 0;
		InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			instructions++;
			var ft = instr.getFlowType();
			if (ft.isConditional()) {
				branches++;
			}
			if (ft.isCall()) {
				calls++;
			}
		}

		JsonArray risky = new JsonArray();
		for (Function callee : f.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY)) {
			if (dangerous.contains(callee.getName())) {
				risky.add(callee.getName());
			}
		}

		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("function", f.getName());
		o.addProperty("entry", f.getEntryPoint().toString());
		o.addProperty("sizeBytes", f.getBody().getNumAddresses());
		o.addProperty("instructions", instructions);
		o.addProperty("conditionalBranches", branches);
		o.addProperty("approxCyclomatic", branches + 1);
		o.addProperty("callCount", calls);
		o.addProperty("parameters", f.getParameterCount());
		try {
			o.addProperty("stackFrameSize", f.getStackFrame().getFrameSize());
			o.addProperty("localSize", f.getStackFrame().getLocalSize());
		}
		catch (Exception ignore) {
			// no frame
		}
		o.add("dangerousCalls", risky);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ call tree

	public String getCallTree(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		String dir = GhidraBridge.str(args, "direction", "callees").toLowerCase();
		boolean callers = dir.equals("callers");
		int maxDepth = clamp(GhidraBridge.intArg(args, "depth", 3), 10);
		int[] budget = { clamp(GhidraBridge.intArg(args, "max_nodes", 200), 2000) };
		Set<String> visited = new LinkedHashSet<>();
		JsonObject root = node(p, f, callers, maxDepth, 0, visited, budget);
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("direction", callers ? "callers" : "callees");
		o.addProperty("maxDepth", maxDepth);
		o.add("tree", root);
		return gson.toJson(o);
	}

	private JsonObject node(Program p, Function f, boolean callers, int maxDepth, int depth,
			Set<String> visited, int[] budget) {
		JsonObject o = new JsonObject();
		o.addProperty("name", f.getName());
		o.addProperty("entry", f.getEntryPoint().toString());
		String key = f.getEntryPoint().toString();
		if (depth >= maxDepth || !visited.add(key) || budget[0] <= 0) {
			return o;
		}
		Set<Function> next = callers ? f.getCallingFunctions(ghidra.util.task.TaskMonitor.DUMMY)
			: f.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY);
		JsonArray children = new JsonArray();
		for (Function g : next) {
			if (budget[0] <= 0) {
				break;
			}
			budget[0]--;
			children.add(node(p, g, callers, maxDepth, depth + 1, visited, budget));
		}
		if (children.size() > 0) {
			o.add("children", children);
		}
		return o;
	}

	// ------------------------------------------------------------ helpers

	private boolean operandIsValue(Instruction instr, long value) {
		int n = instr.getNumOperands();
		for (int i = 0; i < n; i++) {
			for (Object obj : instr.getOpObjects(i)) {
				if (obj instanceof Scalar s) {
					if (s.getValue() == value || s.getUnsignedValue() == value) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private static int clamp(int v, int max) {
		return (v <= 0 || v > max) ? max : v;
	}

	private static Map<String, String> buildCapabilityMap() {
		Map<String, String> m = new LinkedHashMap<>();
		// networking
		// Note: bare "send"/"recv" are handled by EXACT_CAPABILITY, not here, so that
		// SendMessage / SendDlgItemMessage are not mis-tagged as network.
		for (String s : new String[] { "socket", "wsasocket", "wsastartup", "wsaconnect",
			"internetopen", "internetconnect", "httpsendrequest", "httpopenrequest",
			"urldownloadtofile", "winhttp", "getaddrinfo", "gethostbyname", "inet_addr",
			"closesocket", "dnsquery" }) {
			m.put(s, "network");
		}
		// process injection
		for (String s : new String[] { "virtualallocex", "writeprocessmemory", "createremotethread",
			"ntcreatethreadex", "queueuserapc", "setthreadcontext", "openprocess", "virtualprotectex",
			"rtlcreateuserthread", "ntmapviewofsection", "ntunmapviewofsection", "process32first",
			"process32next", "createtoolhelp32snapshot", "ntwritevirtualmemory" }) {
			m.put(s, "process_injection");
		}
		// executable memory
		for (String s : new String[] { "virtualalloc", "virtualprotect", "mprotect", "mmap",
			"ntallocatevirtualmemory", "ntprotectvirtualmemory" }) {
			m.put(s, "exec_memory");
		}
		// persistence
		for (String s : new String[] { "regsetvalue", "regcreatekey", "regopenkey", "regdeletevalue",
			"createservice", "startservice", "setwindowshookex", "schedule", "taskscheduler" }) {
			m.put(s, "persistence");
		}
		// crypto
		for (String s : new String[] { "crypt", "bcrypt", "cryptencrypt", "cryptdecrypt",
			"cryptacquirecontext", "cryptgenkey", "cryptderivekey", "cryptimportkey",
			"cngencrypt" }) {
			m.put(s, "crypto");
		}
		// anti-debug / anti-analysis
		for (String s : new String[] { "isdebuggerpresent", "checkremotedebugger",
			"ntqueryinformationprocess", "outputdebugstring", "ntsetinformationthread",
			"gettickcount", "queryperformancecounter", "ntglobalflag" }) {
			m.put(s, "anti_debug");
		}
		// privilege
		for (String s : new String[] { "adjusttokenprivileges", "openprocesstoken",
			"lookupprivilegevalue", "impersonateloggedonuser", "setsecuritydescriptor" }) {
			m.put(s, "privilege");
		}
		// info stealing / surveillance
		for (String s : new String[] { "getasynckeystate", "getkeystate", "getclipboarddata",
			"bitblt", "createcompatiblebitmap", "keybd_event", "credenumerate", "credread",
			"getforegroundwindow" }) {
			m.put(s, "info_stealing");
		}
		// filesystem
		for (String s : new String[] { "createfile", "writefile", "readfile", "deletefile",
			"findfirstfile", "findnextfile", "movefile", "copyfile", "shgetfolderpath",
			"gettemppath" }) {
			m.put(s, "filesystem");
		}
		// dynamic API resolution
		for (String s : new String[] { "loadlibrary", "getprocaddress", "ldrloaddll",
			"ldrgetprocedureaddress" }) {
			m.put(s, "dynamic_api");
		}
		return m;
	}
}
