package ghidrallm.mcp.ops;

import java.math.BigInteger;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrallm.mcp.server.ToolException;

/**
 * PCode emulation: run a program's code from a start address for up to N instructions, with
 * optional seeded registers and a stop address, then read back registers and memory.
 *
 * <p>Emulation runs over a copy-on-write view of program memory, so it does not modify the
 * program database.
 */
public class EmulationOps {

	private final GhidraBridge bridge;
	private final Gson gson;

	public EmulationOps(GhidraBridge bridge, Gson gson) {
		this.bridge = bridge;
		this.gson = gson;
	}

	public String emulate(JsonObject args) throws Exception {
		Program p = bridge.resolve(args);
		Address start = bridge.address(p, GhidraBridge.reqStr(args, "address"));
		long maxSteps = GhidraBridge.longArg(args, "max_steps", 1000);
		if (maxSteps <= 0 || maxSteps > 1_000_000) {
			maxSteps = 1_000_000;
		}
		Address stop = null;
		String stopArg = GhidraBridge.str(args, "stop", null);

		EmulatorHelper emu = new EmulatorHelper(p);
		try {
			if (stopArg != null && !stopArg.isBlank()) {
				stop = bridge.address(p, stopArg);
				emu.setBreakpoint(stop);
			}

			Register pc = emu.getPCRegister();
			emu.writeRegister(pc, start.getOffset());

			// Seed registers.
			if (args.has("registers") && args.get("registers").isJsonObject()) {
				for (Map.Entry<String, JsonElement> e : args.getAsJsonObject("registers").entrySet()) {
					String regName = e.getKey();
					long value = GhidraBridge.longFromStr(e.getValue().getAsString());
					try {
						emu.writeRegister(regName, value);
					}
					catch (Exception ex) {
						throw new ToolException("Could not set register '" + regName + "': " +
							ex.getMessage());
					}
				}
			}

			long steps = 0;
			String stopReason = "max_steps_reached";
			while (steps < maxSteps) {
				Address curPc = emu.getExecutionAddress();
				if (stop != null && curPc.equals(stop)) {
					stopReason = "reached_stop";
					break;
				}
				boolean ok;
				try {
					ok = emu.step(TaskMonitor.DUMMY);
				}
				catch (Exception ex) {
					stopReason = "exception: " + ex.getMessage();
					break;
				}
				if (!ok) {
					String err = emu.getLastError();
					stopReason = "halted" + (err == null ? "" : ": " + err);
					break;
				}
				steps++;
			}

			Address finalPc = emu.getExecutionAddress();

			JsonObject out = new JsonObject();
			out.addProperty("program", p.getName());
			out.addProperty("start", start.toString());
			out.addProperty("stepsExecuted", steps);
			out.addProperty("stopReason", stopReason);
			out.addProperty("finalPc", finalPc == null ? null : finalPc.toString());

			// Read requested registers.
			if (args.has("read_registers") && args.get("read_registers").isJsonArray()) {
				JsonObject regs = new JsonObject();
				for (JsonElement el : args.getAsJsonArray("read_registers")) {
					String regName = el.getAsString();
					try {
						BigInteger v = emu.readRegister(regName);
						regs.addProperty(regName, v == null ? null : "0x" + v.toString(16));
					}
					catch (Exception ex) {
						regs.addProperty(regName, "error: " + ex.getMessage());
					}
				}
				out.add("registers", regs);
			}

			// Read requested memory ranges.
			if (args.has("read_memory") && args.get("read_memory").isJsonArray()) {
				JsonArray mems = new JsonArray();
				for (JsonElement el : args.getAsJsonArray("read_memory")) {
					JsonObject spec = el.getAsJsonObject();
					Address addr = bridge.address(p, GhidraBridge.reqStr(spec, "address"));
					int len = GhidraBridge.intArg(spec, "length", 16);
					if (len <= 0 || len > 4096) {
						len = Math.min(Math.max(len, 1), 4096);
					}
					JsonObject m = new JsonObject();
					m.addProperty("address", addr.toString());
					m.addProperty("length", len);
					try {
						m.addProperty("hex", toHex(emu.readMemory(addr, len)));
					}
					catch (Exception ex) {
						m.addProperty("error", ex.getMessage());
					}
					mems.add(m);
				}
				out.add("memory", mems);
			}

			return gson.toJson(out);
		}
		finally {
			emu.dispose();
		}
	}

	private static String toHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}
}
