package ghidrallm.mcp.ops;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidrallm.mcp.server.ToolException;

/**
 * Raw memory and patching tools: read bytes, overwrite bytes, and assemble an instruction
 * directly into program memory. These are the primitives for binary patching.
 */
public class MemoryOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public MemoryOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String readBytes(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		int length = GhidraBridge.intArg(args, "length", 64);
		if (length <= 0 || length > 65536) {
			length = Math.min(Math.max(length, 1), 65536);
		}
		byte[] buf = new byte[length];
		int read;
		try {
			read = p.getMemory().getBytes(addr, buf);
		}
		catch (Exception e) {
			throw new ToolException("Cannot read " + length + " bytes at " + addr +
				" (uninitialized or out of range): " + e.getMessage());
		}
		byte[] actual = new byte[read];
		System.arraycopy(buf, 0, actual, 0, read);
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("address", addr.toString());
		o.addProperty("length", read);
		o.addProperty("hex", toHex(actual));
		o.addProperty("ascii", toAscii(actual));
		return gson.toJson(o);
	}

	public String writeBytes(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		byte[] bytes = parseHex(GhidraBridge.reqStr(args, "hex"));
		if (bytes.length == 0) {
			throw new ToolException("No bytes to write.");
		}
		Memory mem = p.getMemory();
		bridge.inTransaction(p, "Patch bytes (MCP)", () -> {
			try {
				mem.setBytes(addr, bytes);
			}
			catch (Exception e) {
				throw new ToolException("Cannot write " + bytes.length + " bytes at " + addr +
					" (block may be uninitialized or read-only): " + e.getMessage());
			}
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("address", addr.toString());
		o.addProperty("bytesWritten", bytes.length);
		o.addProperty("hex", toHex(bytes));
		return gson.toJson(o);
	}

	public String assembleInstruction(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address addr = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		String instruction = GhidraBridge.reqStr(args, "instruction");

		JsonArray produced = new JsonArray();
		bridge.inTransaction(p, "Assemble instruction (MCP)", () -> {
			Assembler asm = Assemblers.getAssembler(p);
			try {
				InstructionIterator it = asm.assemble(addr, instruction);
				while (it != null && it.hasNext()) {
					Instruction instr = it.next();
					JsonObject io = new JsonObject();
					io.addProperty("address", instr.getAddress().toString());
					io.addProperty("instruction", instr.toString());
					io.addProperty("length", instr.getLength());
					try {
						io.addProperty("bytes", toHex(instr.getBytes()));
					}
					catch (Exception ignore) {
						// bytes unavailable
					}
					produced.add(io);
				}
			}
			catch (Exception e) {
				throw new ToolException("Assembly of \"" + instruction + "\" at " + addr +
					" failed: " + e.getMessage());
			}
			return null;
		});
		JsonObject o = new JsonObject();
		o.addProperty("program", p.getName());
		o.addProperty("address", addr.toString());
		o.addProperty("requested", instruction);
		o.add("assembled", produced);
		return gson.toJson(o);
	}

	// ------------------------------------------------------------ helpers

	private static byte[] parseHex(String hex) throws ToolException {
		String clean = hex.replaceAll("[\\s,]", "").replaceAll("(?i)^0x", "");
		if (clean.length() % 2 != 0) {
			throw new ToolException("Hex string must have an even number of digits.");
		}
		try {
			byte[] out = new byte[clean.length() / 2];
			for (int i = 0; i < out.length; i++) {
				out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
			}
			return out;
		}
		catch (NumberFormatException e) {
			throw new ToolException("Invalid hex digits in '" + hex + "'.");
		}
	}

	private static String toHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static String toAscii(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length);
		for (byte b : bytes) {
			int c = b & 0xff;
			sb.append((c >= 0x20 && c < 0x7f) ? (char) c : '.');
		}
		return sb.toString();
	}
}
