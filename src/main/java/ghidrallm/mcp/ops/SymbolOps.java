package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;
import ghidrallm.mcp.server.ToolException;

/**
 * Symbol, string, import and export tools, plus label creation and symbol renaming.
 */
public class SymbolOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public SymbolOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String listSymbols(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		String filter = lower(GhidraBridge.str(args, "filter", null));
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 300));
		JsonArray arr = new JsonArray();
		SymbolIterator it = p.getSymbolTable().getAllSymbols(true);
		int matched = 0;
		for (Symbol s : it) {
			if (filter != null && !s.getName().toLowerCase().contains(filter)) {
				continue;
			}
			matched++;
			if (arr.size() >= limit) {
				continue;
			}
			JsonObject o = new JsonObject();
			o.addProperty("name", s.getName());
			o.addProperty("address", String.valueOf(s.getAddress()));
			o.addProperty("type", s.getSymbolType().toString());
			o.addProperty("namespace", s.getParentNamespace() == null ? null
				: s.getParentNamespace().getName(true));
			o.addProperty("source", s.getSource().toString());
			o.addProperty("primary", s.isPrimary());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("returned", arr.size());
		o.addProperty("truncated", matched > arr.size());
		o.add("symbols", arr);
		return gson.toJson(o);
	}

	public String listStrings(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		String filter = GhidraBridge.str(args, "filter", null);
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 300));
		JsonArray arr = new JsonArray();
		int matched = 0;
		DataIterator it = p.getListing().getDefinedData(true);
		while (it.hasNext()) {
			Data d = it.next();
			Object value = d.getValue();
			if (!(value instanceof String str)) {
				continue;
			}
			if (filter != null && !str.contains(filter)) {
				continue;
			}
			matched++;
			if (arr.size() >= limit) {
				continue;
			}
			JsonObject o = new JsonObject();
			o.addProperty("address", d.getAddress().toString());
			o.addProperty("value", str);
			o.addProperty("length", d.getLength());
			o.addProperty("dataType", d.getDataType().getName());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("returned", arr.size());
		o.addProperty("truncated", matched > arr.size());
		o.add("strings", arr);
		return gson.toJson(o);
	}

	public String listImports(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 1000));
		JsonArray arr = new JsonArray();
		SymbolIterator it = p.getSymbolTable().getExternalSymbols();
		while (it.hasNext() && arr.size() < limit) {
			Symbol s = it.next();
			JsonObject o = new JsonObject();
			o.addProperty("name", s.getName());
			o.addProperty("library", s.getParentNamespace() == null ? null
				: s.getParentNamespace().getName());
			o.addProperty("type", s.getSymbolType().toString());
			o.addProperty("address", String.valueOf(s.getAddress()));
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.add("imports", arr);
		return gson.toJson(o);
	}

	public String listExports(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		int limit = clampLimit(GhidraBridge.intArg(args, "limit", 1000));
		SymbolTable st = p.getSymbolTable();
		JsonArray arr = new JsonArray();
		AddressIterator it = st.getExternalEntryPointIterator();
		while (it.hasNext() && arr.size() < limit) {
			Address a = it.next();
			Symbol s = st.getPrimarySymbol(a);
			JsonObject o = new JsonObject();
			o.addProperty("address", a.toString());
			o.addProperty("name", s == null ? null : s.getName());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.add("exports", arr);
		return gson.toJson(o);
	}

	public String createLabel(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String name = GhidraBridge.reqStr(args, "name");
		Symbol created = bridge.inTransaction(p, "Create label (MCP)",
			() -> p.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED));
		JsonObject o = new JsonObject();
		o.addProperty("address", addr.toString());
		o.addProperty("name", created.getName());
		return gson.toJson(o);
	}

	public String renameSymbol(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String newName = GhidraBridge.reqStr(args, "new_name");
		Symbol sym = p.getSymbolTable().getPrimarySymbol(addr);
		if (sym == null) {
			throw new ToolException("No symbol at " + addr + ". Use create_label to add one.");
		}
		String oldName = sym.getName();
		bridge.inTransaction(p, "Rename symbol (MCP)", () -> {
			sym.setName(newName, SourceType.USER_DEFINED);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("address", addr.toString());
		o.addProperty("oldName", oldName);
		o.addProperty("newName", sym.getName());
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ helpers

	private static String lower(String s) {
		return s == null ? null : s.toLowerCase();
	}

	private static int clampLimit(int limit) {
		return (limit <= 0 || limit > 5000) ? 5000 : limit;
	}
}
