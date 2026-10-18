package ghidrallm.mcp.ops;

import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.listing.Program;
import ghidrallm.mcp.server.ToolException;

/**
 * Additional typing tools: define enumerations, and set equates (named constants) on operands.
 */
public class TypeExtraOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public TypeExtraOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String defineEnum(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "name");
		int size = GhidraBridge.intArg(args, "size", 4);
		if (size != 1 && size != 2 && size != 4 && size != 8) {
			throw new ToolException("Enum size must be 1, 2, 4 or 8 bytes.");
		}
		if (!args.has("values") || !args.get("values").isJsonObject()) {
			throw new ToolException("Provide 'values' as an object of name -> integer value.");
		}
		JsonObject values = args.getAsJsonObject("values");
		DataTypeManager dtm = p.getDataTypeManager();
		EnumDataType e = new EnumDataType(CategoryPath.ROOT, name, size, dtm);
		for (Map.Entry<String, JsonElement> entry : values.entrySet()) {
			long v = GhidraBridge.longFromStr(entry.getValue().getAsString());
			e.add(entry.getKey(), v);
		}
		DataType added = bridge.inTransaction(p, "Define enum (MCP)",
			() -> dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER));
		JsonObject o = new JsonObject();
		o.addProperty("name", added.getName());
		o.addProperty("path", added.getPathName());
		o.addProperty("size", added.getLength());
		o.addProperty("members", values.size());
		return gson.toJson(o);
	}

	public String setEquate(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "name");
		long value = GhidraBridge.longFromStr(GhidraBridge.reqStr(args, "value"));
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		int opIndex = GhidraBridge.intArg(args, "op_index", 0);
		EquateTable et = p.getEquateTable();
		bridge.inTransaction(p, "Set equate (MCP)", () -> {
			Equate eq = et.getEquate(name);
			if (eq == null) {
				eq = et.createEquate(name, value);
			}
			else if (eq.getValue() != value) {
				throw new ToolException("An equate named '" + name + "' already exists with value " +
					eq.getValue() + "; choose a different name.");
			}
			eq.addReference(addr, opIndex);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("name", name);
		o.addProperty("value", value);
		o.addProperty("address", addr.toString());
		o.addProperty("opIndex", opIndex);
		return gson.toJson(o);
	}
}
