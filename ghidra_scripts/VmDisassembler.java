// Disassembles the bytecode embedded in challenge 03 (tiny VM).
//
// Finds the "TVM1" image, decodes it with the instruction set recovered from
// vm_step(), and annotates every bytecode instruction in the Listing with an
// EOL comment so the program can be read inside Ghidra.
//
// GUI:      run from Script Manager
// Headless: -postScript VmDisassembler.java [listing.txt]
//
//@category GhidraLabs
//@author TZ
//@runtime Java

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class VmDisassembler extends GhidraScript {

    /** Operand formats: rb = reg, imm8 | rr = reg, reg | a = addr16 | r = reg | "" = none. */
    private static final Map<Integer, String[]> OPS = new HashMap<>();
    static {
        OPS.put(0x10, new String[] {"LDI", "rb"});
        OPS.put(0x11, new String[] {"LDC", "rb"});
        OPS.put(0x20, new String[] {"XOR", "rr"});
        OPS.put(0x21, new String[] {"ADD", "rr"});
        OPS.put(0x22, new String[] {"ROL", "rb"});
        OPS.put(0x30, new String[] {"CMP", "rr"});
        OPS.put(0x40, new String[] {"JNE", "a"});
        OPS.put(0x41, new String[] {"JMP", "a"});
        OPS.put(0x50, new String[] {"LEN", "r"});
        OPS.put(0xF0, new String[] {"OK", ""});
        OPS.put(0xFF, new String[] {"FAIL", ""});
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        // The magic also appears as the plain "TVM1" literal that vm_load()
        // passes to memcmp, so keep searching until a hit has a sane header.
        Address image = null;
        int length = 0;
        Address hit = find(currentProgram.getMinAddress(), "TVM1".getBytes());
        while (hit != null) {
            try {
                byte[] hdr = getBytes(hit.add(4), 3);
                length = (hdr[0] & 0xFF) | ((hdr[1] & 0xFF) << 8);
                if (length > 0 && OPS.containsKey(hdr[2] & 0xFF)
                    && currentProgram.getMemory().contains(hit.add(6 + length - 1))) {
                    image = hit;
                    break;
                }
            } catch (Exception e) {
                // Ran off the end of a block; not the image.
            }
            hit = find(hit.add(1), "TVM1".getBytes());
        }
        if (image == null) {
            printerr("No TVM1 image found.");
            return;
        }
        Address codeStart = image.add(6);
        byte[] code = getBytes(codeStart, length);

        createLabel(image, "vm_image", true);
        createLabel(codeStart, "vm_code", true);
        setPlateComment(image, String.format("TVM1 bytecode image%nmagic \"TVM1\", u16 length = %d, code follows", length));

        StringBuilder listing = new StringBuilder();
        listing.append(String.format("; TVM1 image at %s, %d bytes of code%n", image, length));
        int pc = 0;
        while (pc < length && !monitor.isCancelled()) {
            int opc = code[pc] & 0xFF;
            String[] op = OPS.get(opc);
            String text;
            int size;
            if (op == null) {
                text = String.format("DB 0x%02x", opc);
                size = 1;
            } else {
                size = sizeOf(op[1]);
                text = op[0] + operands(op[1], code, pc);
            }
            String line = String.format("%04x  %s", pc, text);
            listing.append(line).append('\n');
            setEOLComment(codeStart.add(pc), "vm: " + line);
            pc += size;
        }
        println(listing.toString());

        if (args.length > 0) {
            try (PrintWriter w = new PrintWriter(args[0])) {
                w.print(listing);
            }
            println("Listing written to " + args[0]);
        }
    }

    private static int sizeOf(String fmt) {
        switch (fmt) {
            case "rb":
            case "rr":
            case "a":
                return 3;
            case "r":
                return 2;
            default:
                return 1;
        }
    }

    private static int at(byte[] code, int i) {
        return i < code.length ? code[i] & 0xFF : 0;
    }

    private static String operands(String fmt, byte[] code, int pc) {
        int a = at(code, pc + 1);
        int b = at(code, pc + 2);
        switch (fmt) {
            case "rb":
                return String.format("  r%d, 0x%02x", a, b);
            case "rr":
                return String.format("  r%d, r%d", a, b);
            case "a":
                return String.format("  0x%04x", a | (b << 8));
            case "r":
                return String.format("  r%d", a);
            default:
                return "";
        }
    }
}
