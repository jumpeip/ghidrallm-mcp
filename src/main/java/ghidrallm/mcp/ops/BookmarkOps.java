package ghidrallm.mcp.ops;

import java.util.Iterator;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidrallm.mcp.server.ToolException;

/**
 * Bookmarks: mark addresses of interest (e.g. suspected vulnerabilities) and list them back.
 */
public class BookmarkOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public BookmarkOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String setBookmark(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String type = GhidraBridge.str(args, "type", BookmarkType.NOTE);
		String category = GhidraBridge.str(args, "category", "GhidraMCP");
		String comment = GhidraBridge.str(args, "comment", "");
		BookmarkManager bm = p.getBookmarkManager();
		bridge.inTransaction(p, "Set bookmark (MCP)", () -> {
			bm.setBookmark(addr, type, category, comment);
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("address", addr.toString());
		o.addProperty("type", type);
		o.addProperty("category", category);
		o.addProperty("comment", comment);
		return gson.toJson(o);
	}

	public String listBookmarks(JsonObject args) throws ToolException {
		Program p = bridge.resolve(args);
		String type = GhidraBridge.str(args, "type", null);
		int limit = GhidraBridge.intArg(args, "limit", 500);
		if (limit <= 0 || limit > 5000) {
			limit = 5000;
		}
		BookmarkManager bm = p.getBookmarkManager();
		Iterator<Bookmark> it = (type == null || type.isBlank())
			? bm.getBookmarksIterator()
			: bm.getBookmarksIterator(type);
		JsonArray arr = new JsonArray();
		while (it.hasNext() && arr.size() < limit) {
			Bookmark b = it.next();
			JsonObject o = new JsonObject();
			o.addProperty("address", b.getAddress().toString());
			o.addProperty("type", b.getTypeString());
			o.addProperty("category", b.getCategory());
			o.addProperty("comment", b.getComment());
			arr.add(o);
		}
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("count", arr.size());
		o.add("bookmarks", arr);
		return gson.toJson(o);
	}
}
