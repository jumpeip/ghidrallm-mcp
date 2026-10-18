package ghidrallm.mcp.ops;

import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Function-centric tools: enumerate functions, decompile to C, disassemble instruction ranges,
 * rename functions, set comments, and query cross-references.
 */
public class FunctionOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public FunctionOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String listFunctions(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		String filter = GhidraBridge.str(args, "filter", null);
		int offset = Math.max(0, GhidraBridge.intArg(args, "offset", 0));
		int limit = GhidraBridge.intArg(args, "limit", 200);
		if (limit <= 0 || limit > 2000) {
			limit = 2000;
		}
		String lower = filter == null ? null : filter.toLowerCase();

		JsonArray arr = new JsonArray();
		int matched = 0;
		int skipped = 0;
		FunctionIterator it = p.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			if (lower != null && !f.getName().toLowerCase().contains(lower)) {
				continue;
			}
			if (skipped < offset) {
				skipped++;
				continue;
			}
			if (arr.size() >= limit) {
				matched++;
				continue;
			}
			JsonObject o = new JsonObject();
			o.addProperty("name", f.getName());
			o.addProperty("entry", f.getEntryPoint().toString());
			o.addProperty("signature", f.getSignature().getPrototypeString());
			o.addProperty("size", f.getBody().getNumAddresses());
			o.addProperty("thunk", f.isThunk());
			o.addProperty("external", f.isExternal());
			arr.add(o);
			matched++;
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("returned", arr.size());
		o.addProperty("offset", offset);
		o.addProperty("truncated", matched > offset + arr.size());
		o.add("functions", arr);
		return gson.toJson(o);
	}

	public String decompileFunction(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = resolveFunction(p, args);
		int timeout = GhidraBridge.intArg(args, "timeout_seconds", 60);

		DecompInterface decomp = new DecompInterface();
		try {
			if (!decomp.openProgram(p)) {
				throw new ToolException("Decompiler failed to open program: " + decomp.getLastMessage());
			}
			DecompileResults results = decomp.decompileFunction(f, timeout, TaskMonitor.DUMMY);
			if (results == null || !results.decompileCompleted()) {
				String msg = results == null ? "no result" : results.getErrorMessage();
				throw new ToolException("Decompilation did not complete for " + f.getName() + ": " + msg);
			}
			JsonObject o = new JsonObject();
			o.addProperty("program", p.getName());
			o.addProperty("function", f.getName());
			o.addProperty("entry", f.getEntryPoint().toString());
			o.addProperty("signature", f.getSignature().getPrototypeString());
			o.addProperty("c", results.getDecompiledFunction().getC());
			return gson.toJson(o);
		}
		finally {
			decomp.dispose();
		}
	}

	public String disassemble(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		int count = GhidraBridge.intArg(args, "count", 20);
		if (count <= 0 || count > 2000) {
			count = 2000;
		}
		Address start;
		String addrArg = GhidraBridge.str(args, "address", null);
		if (addrArg != null && !addrArg.isBlank()) {
			start = bridge.address(p, addrArg);
		}
		else {
			Function f = resolveFunction(p, args);
			start = f.getEntryPoint();
		}

		JsonArray arr = new JsonArray();
		Listing listing = p.getListing();
		Instruction instr = listing.getInstructionAt(start);
		if (instr == null) {
			instr = listing.getInstructionAfter(start);
		}
		while (instr != null && arr.size() < count) {
			JsonObject o = new JsonObject();
			o.addProperty("address", instr.getAddress().toString());
			o.addProperty("instruction", instr.toString());
			o.addProperty("length", instr.getLength());
			try {
				o.addProperty("bytes", toHex(instr.getBytes()));
			}
			catch (Exception ignore) {
				// bytes unavailable
			}
			arr.add(o);
			instr = instr.getNext();
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("start", start.toString());
		o.addProperty("count", arr.size());
		o.add("instructions", arr);
		return gson.toJson(o);
	}

	public String renameFunction(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = resolveFunction(p, args);
		String newName = GhidraBridge.reqStr(args, "new_name");
		String oldName = f.getName();
		bridge.inTransaction(p, "Rename function (MCP)",
			() -> {
				f.setName(newName, SourceType.USER_DEFINED);
				return null;
			});
		JsonObject o = new JsonObject();
		o.addProperty("entry", f.getEntryPoint().toString());
		o.addProperty("oldName", oldName);
		o.addProperty("newName", f.getName());
		return gson.toJson(o);
	}

	public String setComment(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String typeArg = GhidraBridge.str(args, "type", "eol").toLowerCase();
		String text = GhidraBridge.str(args, "comment", "");
		CommentType type = switch (typeArg) {
			case "eol" -> CommentType.EOL;
			case "pre" -> CommentType.PRE;
			case "post" -> CommentType.POST;
			case "plate" -> CommentType.PLATE;
			case "repeatable" -> CommentType.REPEATABLE;
			default -> throw new ToolException("Unknown comment type '" + typeArg +
				"'. Use eol, pre, post, plate or repeatable.");
		};
		Listing listing = p.getListing();
		bridge.inTransaction(p, "Set comment (MCP)", () -> {
			listing.setComment(addr, type, text.isEmpty() ? null : text);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("address", addr.toString());
		o.addProperty("type", typeArg);
		o.addProperty("comment", text);
		return gson.toJson(o);
	}

	public String getXrefsTo(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 200));
		ReferenceManager rm = p.getReferenceManager();
		JsonArray arr = new JsonArray();
		ReferenceIterator it = rm.getReferencesTo(addr);
		while (it.hasNext() && arr.size() < limit) {
			Reference r = it.next();
			JsonObject o = new JsonObject();
			o.addProperty("from", r.getFromAddress().toString());
			o.addProperty("to", r.getToAddress().toString());
			o.addProperty("type", r.getReferenceType().getName());
			Function fromFn = p.getFunctionManager().getFunctionContaining(r.getFromAddress());
			if (fromFn != null) {
				o.addProperty("fromFunction", fromFn.getName());
			}
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("address", addr.toString());
		o.addProperty("count", arr.size());
		o.add("references", arr);
		return gson.toJson(o);
	}

	public String getXrefsFrom(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 200));
		ReferenceManager rm = p.getReferenceManager();
		JsonArray arr = new JsonArray();
		for (Reference r : rm.getReferencesFrom(addr)) {
			if (arr.size() >= limit) {
				break;
			}
			JsonObject o = new JsonObject();
			o.addProperty("from", r.getFromAddress().toString());
			o.addProperty("to", r.getToAddress().toString());
			o.addProperty("type", r.getReferenceType().getName());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("address", addr.toString());
		o.addProperty("count", arr.size());
		o.add("references", arr);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ helpers

	private Function resolveFunction(Program p, JsonObject args) throws ToolException {
		String addr = GhidraBridge.str(args, "address", null);
		if (addr != null && !addr.isBlank()) {
			Address a = bridge.address(p, addr);
			Function f = p.getFunctionManager().getFunctionContaining(a);
			if (f == null) {
				f = p.getFunctionManager().getFunctionAt(a);
			}
			if (f == null) {
				throw new ToolException("No function at or containing " + addr + ".");
			}
			return f;
		}
		String name = GhidraBridge.str(args, "name", null);
		if (name != null && !name.isBlank()) {
			List<Function> fs = p.getListing().getGlobalFunctions(name);
			if (fs.isEmpty()) {
				throw new ToolException("No function named '" + name + "'.");
			}
			return fs.get(0);
		}
		throw new ToolException("Provide 'address' or 'name' to identify the function.");
	}

	private static int clampLimit(int limit) {
		return (limit <= 0 || limit > 5000) ? 5000 : limit;
	}

	private static String toHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}
}
