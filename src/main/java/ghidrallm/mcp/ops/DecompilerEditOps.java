package ghidrallm.mcp.ops;

import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * Decompiler-level editing: rename or retype local variables and parameters by the names the
 * decompiler shows. Uses {@link HighFunctionDBUtil} so changes persist to the program database
 * and reflect back into the decompiler view.
 */
public class DecompilerEditOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public DecompilerEditOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String renameVariable(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		String varName = GhidraBridge.reqStr(args, "variable");
		String newName = GhidraBridge.reqStr(args, "new_name");

		DecompInterface decomp = new DecompInterface();
		try {
			HighFunction hf = decompile(decomp, p, f);
			HighSymbol sym = lookup(hf, varName);
			bridge.inTransaction(p, "Rename variable (MCP)", () -> {
				try {
					HighFunctionDBUtil.updateDBVariable(sym, newName, null, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					throw new ToolException("Could not rename variable: " + e.getMessage());
				}
				return null;
			});
			JsonObject o = new JsonObject();
			o.addProperty("function", f.getName());
			o.addProperty("oldName", varName);
			o.addProperty("newName", newName);
			return gson.toJson(o);
		}
		finally {
			decomp.dispose();
		}
	}

	public String setVariableType(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Function f = bridge.resolveFunction(p, args);
		String varName = GhidraBridge.reqStr(args, "variable");
		String typeStr = GhidraBridge.reqStr(args, "type");
		DataType dt = bridge.parseDataType(p, typeStr);

		DecompInterface decomp = new DecompInterface();
		try {
			HighFunction hf = decompile(decomp, p, f);
			HighSymbol sym = lookup(hf, varName);
			bridge.inTransaction(p, "Set variable type (MCP)", () -> {
				try {
					HighFunctionDBUtil.updateDBVariable(sym, sym.getName(), dt,
						SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					throw new ToolException("Could not retype variable: " + e.getMessage());
				}
				return null;
			});
			JsonObject o = new JsonObject();
			o.addProperty("function", f.getName());
			o.addProperty("variable", varName);
			o.addProperty("type", dt.getName());
			return gson.toJson(o);
		}
		finally {
			decomp.dispose();
		}
	}

	// ------------------------------------------------------------ helpers

	private HighFunction decompile(DecompInterface decomp, Program p, Function f)
			throws ToolException {
		if (!decomp.openProgram(p)) {
			throw new ToolException("Decompiler failed to open program: " + decomp.getLastMessage());
		}
		DecompileResults results = decomp.decompileFunction(f, 60, TaskMonitor.DUMMY);
		if (results == null || !results.decompileCompleted()) {
			throw new ToolException("Decompilation failed for " + f.getName() + ": " +
				(results == null ? "no result" : results.getErrorMessage()));
		}
		HighFunction hf = results.getHighFunction();
		if (hf == null) {
			throw new ToolException("No high-level function produced for " + f.getName() + ".");
		}
		return hf;
	}

	private HighSymbol lookup(HighFunction hf, String varName) throws ToolException {
		Map<String, HighSymbol> map = hf.getLocalSymbolMap().getNameToSymbolMap();
		HighSymbol sym = map.get(varName);
		if (sym == null) {
			throw new ToolException("No variable named '" + varName + "' in this function. " +
				"Available: " + String.join(", ", map.keySet()));
		}
		return sym;
	}
}
