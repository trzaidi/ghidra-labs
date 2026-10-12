// Statically decrypts the XOR-obfuscated strings in challenge 02.
//
// 1. Locates the string decryption routine (or takes its address as an arg).
// 2. Applies the recovered signature:
//        void decrypt(char *dst, uchar *src, ulong len, uchar key)
// 3. Decompiles every caller and reads the constant src/len/key arguments
//    out of the decompiler's P-code at each call site.
// 4. Decrypts each blob, labels it, and comments the call site and the blob.
//
// GUI:      run with the cursor anywhere; the routine is found automatically
// Headless: -postScript DecryptStrings.java [report.txt] [decrypt address]
//
//@category GhidraLabs
//@author TZ
//@runtime Java

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class DecryptStrings extends GhidraScript {

    private static final int STEP = 0x1F;
    private final StringBuilder report = new StringBuilder();

    private void out(String fmt, Object... args) {
        String s = String.format(fmt, args);
        report.append(s).append('\n');
        println(s);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Function decrypt = args.length > 1 ? getFunctionAt(toAddr(args[1])) : findDecryptRoutine();
        if (decrypt == null) {
            printerr("Decryption routine not found. Pass its address as the second script argument.");
            return;
        }
        applySignature(decrypt);
        out("Decryption routine: %s @ %s", decrypt.getName(), decrypt.getEntryPoint());

        Set<Function> callers = new LinkedHashSet<>();
        for (Reference r : getReferencesTo(decrypt.getEntryPoint())) {
            if (r.getReferenceType().isCall()) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) {
                    callers.add(f);
                }
            }
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        int count = 0;
        try {
            for (Function caller : callers) {
                DecompileResults res = ifc.decompileFunction(caller, 60, monitor);
                HighFunction hf = res.getHighFunction();
                if (hf == null) {
                    printerr("Decompile failed for " + caller.getName());
                    continue;
                }
                Iterator<PcodeOpAST> ops = hf.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST op = ops.next();
                    if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 5) {
                        continue;
                    }
                    if (!op.getInput(0).getAddress().equals(decrypt.getEntryPoint())) {
                        continue;
                    }
                    if (handleCall(op)) {
                        count++;
                    }
                }
            }
        } finally {
            ifc.dispose();
        }
        out("Decrypted %d string(s).", count);

        if (args.length > 0) {
            try (PrintWriter w = new PrintWriter(args[0])) {
                w.print(report);
            }
            println("Report written to " + args[0]);
        }
    }

    private boolean handleCall(PcodeOp op) throws Exception {
        Address site = op.getSeqnum().getTarget();
        Long src = resolveConstant(op.getInput(2), 0);
        Long len = resolveConstant(op.getInput(3), 0);
        Long key = resolveConstant(op.getInput(4), 0);
        if (src == null || len == null || key == null) {
            out("%s: non-constant arguments, skipped", site);
            return false;
        }
        Address blob = toAddr(src);
        int n = (int) (long) len;
        int k = (int) (key & 0xFF);
        byte[] enc = getBytes(blob, n);

        StringBuilder plain = new StringBuilder();
        for (int i = 0; i < n; i++) {
            plain.append((char) ((enc[i] ^ (k + i * STEP)) & 0xFF));
        }
        String text = plain.toString();
        out("%s: src=%s len=%d key=0x%02x -> \"%s\"", site, blob, n, k, text);

        setPreComment(site, "decrypt -> \"" + text + "\"");
        setPlateComment(blob, String.format("Encrypted string (key 0x%02x, %d bytes)%n\"%s\"", k, n, text));
        String label = "enc_" + text.replaceAll("[^A-Za-z0-9]+", "_").replaceAll("^_|_$", "");
        try {
            createLabel(blob, label.length() > 40 ? label.substring(0, 40) : label, true);
        } catch (Exception e) {
            printerr("Could not label " + blob + ": " + e.getMessage());
        }
        createBookmark(site, "GhidraLabs", "decrypt: " + text);
        return true;
    }

    /**
     * Follows the decompiler's data flow back to a constant. Global addresses
     * often appear as PTRSUB(0, addr) or behind COPY/CAST once the parameter
     * is typed as a pointer, so those are unwrapped too.
     */
    private Long resolveConstant(Varnode v, int depth) {
        if (v == null || depth > 8) {
            return null;
        }
        if (v.isConstant()) {
            return v.getOffset();
        }
        PcodeOp def = v.getDef();
        if (def == null) {
            return null;
        }
        switch (def.getOpcode()) {
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_SEXT:
                return resolveConstant(def.getInput(0), depth + 1);
            case PcodeOp.PTRSUB:
            case PcodeOp.INT_ADD: {
                Long a = resolveConstant(def.getInput(0), depth + 1);
                Long b = resolveConstant(def.getInput(1), depth + 1);
                return (a == null || b == null) ? null : a + b;
            }
            default:
                return null;
        }
    }

    private void applySignature(Function f) throws Exception {
        List<Parameter> params = new ArrayList<>();
        params.add(new ParameterImpl("dst", new PointerDataType(CharDataType.dataType), currentProgram));
        params.add(new ParameterImpl("src", new PointerDataType(ByteDataType.dataType), currentProgram));
        params.add(new ParameterImpl("len", UnsignedLongDataType.dataType, currentProgram));
        params.add(new ParameterImpl("key", ByteDataType.dataType, currentProgram));
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
            SourceType.USER_DEFINED, params.toArray(new Parameter[0]));
        f.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
        if (f.getName().startsWith("FUN_")) {
            f.setName("decrypt_string", SourceType.USER_DEFINED);
        }
    }

    /**
     * Heuristic: a small function with a loop containing XOR that is called
     * from at least three places. Ranked by caller count.
     */
    private Function findDecryptRoutine() {
        Function best = null;
        int bestCallers = 2;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal() || f.getBody().getNumAddresses() > 0x80) {
                continue;
            }
            boolean hasXor = false;
            boolean hasLoop = false;
            for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                if (ins.getMnemonicString().equalsIgnoreCase("XOR") && ins.getRegister(0) != null
                    && ins.getRegister(1) == null) {
                    hasXor = true;
                }
                if (ins.getFlowType().isConditional()) {
                    for (Address target : ins.getFlows()) {
                        if (target.compareTo(ins.getAddress()) < 0) {
                            hasLoop = true;
                        }
                    }
                }
            }
            if (!hasXor || !hasLoop) {
                continue;
            }
            int callers = 0;
            for (Reference r : getReferencesTo(f.getEntryPoint())) {
                if (r.getReferenceType().isCall()) {
                    callers++;
                }
            }
            if (callers > bestCallers) {
                best = f;
                bestCallers = callers;
            }
        }
        return best;
    }
}
