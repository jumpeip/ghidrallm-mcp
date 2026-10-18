package ghidrallm.mcp.ops;

import java.util.Iterator;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidrallm.mcp.server.ToolException;

/**
 * Data-type tools: list types, define a structure, and apply/clear a data type at an address.
 */
public class DataTypeOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public DataTypeOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String listDataTypes(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		String filter = GhidraBridge.str(args, "filter", null);
		String lower = filter == null ? null : filter.toLowerCase();
		int limit = GhidraBridge.intArg(args, "limit", 300);
		if (limit <= 0 || limit > 5000) {
			limit = 5000;
		}
		JsonArray arr = new JsonArray();
		int matched = 0;
		Iterator<DataType> it = p.getDataTypeManager().getAllDataTypes();
		while (it.hasNext()) {
			DataType dt = it.next();
			if (lower != null && !dt.getName().toLowerCase().contains(lower)) {
				continue;
			}
			matched++;
			if (arr.size() >= limit) {
				continue;
			}
			JsonObject o = new JsonObject();
			o.addProperty("name", dt.getName());
			o.addProperty("path", dt.getPathName());
			o.addProperty("length", dt.getLength());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("returned", arr.size());
		o.addProperty("truncated", matched > arr.size());
		o.add("dataTypes", arr);
		return gson.toJson(o);
	}

	public String defineStruct(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		String name = GhidraBridge.reqStr(args, "name");
		boolean packed = GhidraBridge.boolArg(args, "packed", false);
		if (!args.has("fields") || !args.get("fields").isJsonArray()) {
			throw new ToolException("Provide 'fields' as an array of {type, name, size?, comment?}.");
		}
		JsonArray fields = args.getAsJsonArray("fields");

		DataTypeManager dtm = p.getDataTypeManager();
		StructureDataType struct = new StructureDataType(name, 0, dtm);
		if (packed) {
			struct.setPackingEnabled(true);
		}
		for (JsonElement el : fields) {
			if (!el.isJsonObject()) {
				throw new ToolException("Each field must be an object {type, name, size?, comment?}.");
			}
			JsonObject field = el.getAsJsonObject();
			String typeStr = GhidraBridge.reqStr(field, "type");
			String fieldName = GhidraBridge.str(field, "name", null);
			String comment = GhidraBridge.str(field, "comment", null);
			DataType dt = parseType(p, typeStr);
			int size = GhidraBridge.intArg(field, "size", -1);
			if (size <= 0) {
				size = dt.getLength();
			}
			if (size <= 0) {
				throw new ToolException("Field '" + fieldName + "' type '" + typeStr +
					"' has no fixed length; specify 'size'.");
			}
			struct.add(dt, size, fieldName, comment);
		}

		DataType added = bridge.inTransaction(p, "Define struct (MCP)",
			() -> dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER));

		JsonObject o = new JsonObject();
		o.addProperty("name", added.getName());
		o.addProperty("path", added.getPathName());
		o.addProperty("length", added.getLength());
		o.addProperty("fields", fields.size());
		return gson.toJson(o);
	}

	public String applyDataType(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String typeStr = GhidraBridge.reqStr(args, "type");
		boolean clearFirst = GhidraBridge.boolArg(args, "clear", true);
		DataType dt = parseType(p, typeStr);
		Listing listing = p.getListing();

		Data data = bridge.inTransaction(p, "Apply data type (MCP)", () -> {
			if (clearFirst) {
				int len = Math.max(dt.getLength(), 1);
				listing.clearCodeUnits(addr, addr.add(len - 1), false);
			}
			try {
				return listing.createData(addr, dt);
			}
			catch (Exception e) {
				throw new ToolException("Could not apply '" + typeStr + "' at " + addr +
					" (set clear=true to overwrite existing code/data): " + e.getMessage());
			}
		});

		JsonObject o = new JsonObject();
		o.addProperty("address", addr.toString());
		o.addProperty("type", data.getDataType().getName());
		o.addProperty("length", data.getLength());
		Object value = data.getValue();
		if (value != null) {
			o.addProperty("value", String.valueOf(value));
		}
		return gson.toJson(o);
	}

	public String clearData(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		int length = GhidraBridge.intArg(args, "length", 1);
		if (length <= 0) {
			length = 1;
		}
		final int len = length;
		Listing listing = p.getListing();
		bridge.inTransaction(p, "Clear data (MCP)", () -> {
			listing.clearCodeUnits(addr, addr.add(len - 1), false);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("address", addr.toString());
		o.addProperty("cleared", len);
		return gson.toJson(o);
	}

	public String getData(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		Data d = p.getListing().getDataAt(addr);
		if (d == null) {
			throw new ToolException("No defined data at " + addr +
				" (it may be code or undefined; use apply_data_type first).");
		}
		JsonObject o = new JsonObject();
		o.addProperty("address", d.getAddress().toString());
		o.addProperty("dataType", d.getDataType().getName());
		o.addProperty("length", d.getLength());
		o.addProperty("representation", d.getDefaultValueRepresentation());
		Object value = d.getValue();
		if (value != null) {
			o.addProperty("value", String.valueOf(value));
		}
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ helpers

	private DataType parseType(Program p, String typeStr) throws ToolException {
		DataTypeManager dtm = p.getDataTypeManager();
		DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
		try {
			DataType dt = parser.parse(typeStr);
			if (dt == null) {
				throw new ToolException("Unknown data type: '" + typeStr + "'.");
			}
			return dt;
		}
		catch (ToolException te) {
			throw te;
		}
		catch (Exception e) {
			throw new ToolException("Could not resolve data type '" + typeStr + "': " + e.getMessage());
		}
	}
}
