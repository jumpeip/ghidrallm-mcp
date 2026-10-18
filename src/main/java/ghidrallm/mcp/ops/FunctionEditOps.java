package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrallm.mcp.server.ToolException;

/**
 * Creating, deleting and re-typing functions: create a function at an address, delete one,
 * and apply a full C prototype (return type, name, parameter types) to an existing function.
 */
public class FunctionEditOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public FunctionEditOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String createFunction(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address entry = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String name = GhidraBridge.str(args, "name", null);

		CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
		bridge.inTransaction(p, "Create function (MCP)", () -> {
			if (!cmd.applyTo(p)) {
				throw new ToolException("Could not create a function at " + entry + ": " +
					cmd.getStatusMsg());
			}
			if (name != null && !name.isBlank()) {
				Function f = p.getFunctionManager().getFunctionAt(entry);
				if (f != null) {
					f.setName(name, SourceType.USER_DEFINED);
				}
			}
			return null;
		});
		Function f = p.getFunctionManager().getFunctionAt(entry);
		JsonObject o = new JsonObject();
		o.addProperty("entry", entry.toString());
		o.addProperty("name", f == null ? null : f.getName());
		o.addProperty("signature", f == null ? null : f.getSignature().getPrototypeString());
		return gson.toJson(o);
	}

	public String deleteFunction(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		Address entry = f.getEntryPoint();
		String name = f.getName();
		DeleteFunctionCmd cmd = new DeleteFunctionCmd(entry);
		bridge.inTransaction(p, "Delete function (MCP)", () -> {
			if (!cmd.applyTo(p)) {
				throw new ToolException("Could not delete function at " + entry + ": " +
					cmd.getStatusMsg());
			}
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("deletedEntry", entry.toString());
		o.addProperty("deletedName", name);
		return gson.toJson(o);
	}

	public String setFunctionPrototype(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		String prototype = GhidraBridge.reqStr(args, "prototype");

		FunctionSignatureParser parser = new FunctionSignatureParser(p.getDataTypeManager(), null);
		FunctionDefinitionDataType sig;
		try {
			sig = parser.parse(f.getSignature(), prototype);
		}
		catch (Exception e) {
			throw new ToolException("Could not parse prototype \"" + prototype + "\": " +
				e.getMessage());
		}
		if (sig == null) {
			throw new ToolException("Prototype \"" + prototype + "\" did not parse to a signature.");
		}
		Address entry = f.getEntryPoint();
		ApplyFunctionSignatureCmd cmd =
			new ApplyFunctionSignatureCmd(entry, sig, SourceType.USER_DEFINED);
		bridge.inTransaction(p, "Set function prototype (MCP)", () -> {
			if (!cmd.applyTo(p)) {
				throw new ToolException("Could not apply prototype: " + cmd.getStatusMsg());
			}
			return null;
		});
		Function updated = p.getFunctionManager().getFunctionAt(entry);
		JsonObject o = new JsonObject();
		o.addProperty("entry", entry.toString());
		o.addProperty("name", updated.getName());
		o.addProperty("signature", updated.getSignature().getPrototypeString());
		return gson.toJson(o);
	}
}
