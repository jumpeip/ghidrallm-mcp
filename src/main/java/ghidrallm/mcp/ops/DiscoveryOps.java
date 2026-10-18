package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidrallm.mcp.server.ToolException;

/**
 * Code discovery and organization: force disassembly, create namespaces, and read comments.
 */
public class DiscoveryOps {

	private static final CommentType[] COMMENT_TYPES = {
		CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE, CommentType.REPEATABLE
	};

	private final GhidraBridge bridge;
	private final Gson gson;

	public DiscoveryOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String disassembleAt(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		boolean followFlow = GhidraBridge.boolArg(args, "follow_flow", true);
		DisassembleCommand cmd = new DisassembleCommand(addr, null, followFlow);
		boolean ok = bridge.inTransaction(p, "Disassemble (MCP)", () -> cmd.applyTo(p));
		if (!ok) {
			throw new ToolException("Disassembly at " + addr + " failed: " + cmd.getStatusMsg());
		}
		Instruction instr = p.getListing().getInstructionAt(addr);
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("address", addr.toString());
		o.addProperty("followFlow", followFlow);
		o.addProperty("firstInstruction", instr == null ? null : instr.toString());
		return gson.toJson(o);
	}

	public String createNamespace(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "name");
		SymbolTable st = p.getSymbolTable();
		Namespace ns = bridge.inTransaction(p, "Create namespace (MCP)",
			() -> st.getOrCreateNameSpace(p.getGlobalNamespace(), name, SourceType.USER_DEFINED));
		JsonObject o = new JsonObject();
		o.addProperty("name", ns.getName());
		o.addProperty("fullName", ns.getName(true));
		return gson.toJson(o);
	}

	public String getComments(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		AddressSetView set;
		String addrArg = GhidraBridge.str(args, "address", null);
		if (addrArg != null && !addrArg.isBlank()) {
			Address start = bridge.address(p, addrArg);
			int length = GhidraBridge.intArg(args, "length", 1);
			if (length <= 0) {
				length = 1;
			}
			set = new AddressSet(start, start.add(length - 1));
		}
		else {
			Function f = bridge.resolveFunction(p, args);
			set = f.getBody();
		}

		Listing listing = p.getListing();
		JsonArray arr = new JsonArray();
		for (CommentType type : COMMENT_TYPES) {
			var it = listing.getCommentAddressIterator(type, set, true);
			while (it.hasNext()) {
				Address a = it.next();
				String text = listing.getComment(type, a);
				if (text == null) {
					continue;
				}
				JsonObject o = new JsonObject();
				o.addProperty("address", a.toString());
				o.addProperty("type", type.name().toLowerCase());
				o.addProperty("comment", text);
				arr.add(o);
			}
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.add("comments", arr);
		return gson.toJson(o);
	}
}
