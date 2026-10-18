package ghidrallm.mcp.ops;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Navigation and low-level inspection: call-graph neighbours (callers/callees) and raw P-code.
 */
public class NavigationOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public NavigationOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String getCallers(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		return functionSet(p, f, f.getCallingFunctions(TaskMonitor.DUMMY), "callers");
	}

	public String getCallees(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		return functionSet(p, f, f.getCalledFunctions(TaskMonitor.DUMMY), "callees");
	}

	private String functionSet(Program p, Function f, Set<Function> set, String key) {
		JsonArray arr = new JsonArray();
		for (Function g : set) {
			JsonObject o = new JsonObject();
			o.addProperty("name", g.getName());
			o.addProperty("entry", g.getEntryPoint().toString());
			o.addProperty("external", g.isExternal());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("function", f.getName());
		o.addProperty("count", arr.size());
		o.add(key, arr);
		return gson.toJson(o);
	}

	public String getPcode(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		int limit = GhidraBridge.intArg(args, "count", 100);
		if (limit <= 0 || limit > 5000) {
			limit = 5000;
		}

		List<Instruction> instrs = new ArrayList<>();
		String addrArg = GhidraBridge.str(args, "address", null);
		if (addrArg != null && !addrArg.isBlank()) {
			Address start = bridge.address(p, addrArg);
			Instruction instr = p.getListing().getInstructionAt(start);
			if (instr == null) {
				instr = p.getListing().getInstructionAfter(start);
			}
			while (instr != null && instrs.size() < limit) {
				instrs.add(instr);
				instr = instr.getNext();
			}
		}
		else {
			Function f = bridge.resolveFunction(p, args);
			InstructionIterator it = p.getListing().getInstructions(f.getBody(), true);
			while (it.hasNext() && instrs.size() < limit) {
				instrs.add(it.next());
			}
		}

		JsonArray arr = new JsonArray();
		for (Instruction instr : instrs) {
			JsonObject io = new JsonObject();
			io.addProperty("address", instr.getAddress().toString());
			io.addProperty("instruction", instr.toString());
			JsonArray ops = new JsonArray();
			for (PcodeOp op : instr.getPcode()) {
				ops.add(op.toString());
			}
			io.add("pcode", ops);
			arr.add(io);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("instructions", arr.size());
		o.add("listing", arr);
		return gson.toJson(o);
	}
}
