package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidrallm.mcp.server.ToolException;

/**
 * Function attribute tools: list a function's variables, mark no-return, and manage the
 * calling convention.
 */
public class FunctionAttrOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public FunctionAttrOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String listVariables(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		JsonArray params = new JsonArray();
		for (Parameter param : f.getParameters()) {
			params.add(variable(param, true));
		}
		JsonArray locals = new JsonArray();
		for (Variable v : f.getLocalVariables()) {
			locals.add(variable(v, false));
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("function", f.getName());
		o.addProperty("callingConvention", f.getCallingConventionName());
		o.addProperty("noReturn", f.hasNoReturn());
		o.add("parameters", params);
		o.add("localVariables", locals);
		return gson.toJson(o);
	}

	private JsonObject variable(Variable v, boolean isParam) {
		JsonObject o = new JsonObject();
		o.addProperty("name", v.getName());
		o.addProperty("dataType", v.getDataType().getName());
		o.addProperty("length", v.getLength());
		o.addProperty("storage", String.valueOf(v.getVariableStorage()));
		o.addProperty("parameter", isParam);
		return o;
	}

	public String setFunctionNoReturn(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		boolean noReturn = GhidraBridge.boolArg(args, "no_return", true);
		bridge.inTransaction(p, "Set no-return (MCP)", () -> {
			f.setNoReturn(noReturn);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("function", f.getName());
		o.addProperty("noReturn", f.hasNoReturn());
		return gson.toJson(o);
	}

	public String setCallingConvention(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		String convention = GhidraBridge.reqStr(args, "convention");
		bridge.inTransaction(p, "Set calling convention (MCP)", () -> {
			try {
				f.setCallingConvention(convention);
			}
			catch (Exception e) {
				throw new ToolException("Could not set calling convention '" + convention +
					"': " + e.getMessage() + ". Use list_calling_conventions for valid names.");
			}
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("function", f.getName());
		o.addProperty("callingConvention", f.getCallingConventionName());
		return gson.toJson(o);
	}

	public String listCallingConventions(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		JsonArray arr = new JsonArray();
		for (String name : p.getFunctionManager().getCallingConventionNames()) {
			arr.add(name);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.add("conventions", arr);
		return gson.toJson(o);
	}
}
