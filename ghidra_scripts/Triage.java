// First-pass triage of a binary: metadata, main() recovery, imports,
// functions ranked by size, and defined strings. Writes a Markdown report.
//
// GUI:      Script Manager > GhidraLabs > Triage.java
// Headless: -postScript Triage.java <report.md>
//
//@category GhidraLabs
//@author TZ
//@runtime Java

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class Triage extends GhidraScript {

    private final StringBuilder out = new StringBuilder();

    private void line(String fmt, Object... args) {
        String s = String.format(fmt, args);
        out.append(s).append('\n');
        println(s);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        line("# Triage: %s", currentProgram.getName());
        line("");
        line("| Field | Value |");
        line("|---|---|");
        line("| Format | %s |", currentProgram.getExecutableFormat());
        line("| Language | %s |", currentProgram.getLanguageID());
        line("| Compiler | %s |", currentProgram.getCompilerSpec().getCompilerSpecID());
        line("| SHA-256 | %s |", currentProgram.getExecutableSHA256());
        line("| Image base | %s |", currentProgram.getImageBase());
        line("");

        recoverMain();

        line("## Imports");
        line("");
        FunctionIterator ext = currentProgram.getFunctionManager().getExternalFunctions();
        List<String> imports = new ArrayList<>();
        while (ext.hasNext()) {
            imports.add(ext.next().getName());
        }
        imports.sort(String::compareTo);
        for (String name : imports) {
            line("- %s", name);
        }
        line("");

        line("## Functions (largest first)");
        line("");
        line("| Entry | Name | Bytes | Callers |");
        line("|---|---|---|---|");
        List<Function> funcs = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!f.isThunk() && !f.isExternal()) {
                funcs.add(f);
            }
        }
        funcs.sort(Comparator.comparingLong((Function f) -> f.getBody().getNumAddresses()).reversed());
        for (Function f : funcs) {
            line("| %s | %s | %d | %d |", f.getEntryPoint(), f.getName(),
                f.getBody().getNumAddresses(), f.getCallingFunctions(monitor).size());
        }
        line("");

        line("## Defined strings");
        line("");
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data d = data.next();
            if (d.hasStringValue()) {
                line("- `%s` %s", d.getAddress(), d.getDefaultValueRepresentation());
            }
        }

        if (args.length > 0) {
            try (PrintWriter w = new PrintWriter(args[0])) {
                w.print(out);
            }
            println("Report written to " + args[0]);
        }
    }

    /**
     * Stripped glibc binaries lose the name "main". The ELF entry stub loads
     * main's address into RDI right before calling __libc_start_main, so we
     * read it back from there and label it.
     */
    private void recoverMain() throws Exception {
        if (!getGlobalFunctions("main").isEmpty()) {
            line("main() already named.");
            line("");
            return;
        }
        Address entry = null;
        AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (it.hasNext()) {
            Address a = it.next();
            Function f = getFunctionAt(a);
            if (f != null && (f.getName().equals("entry") || f.getName().equals("_start"))) {
                entry = a;
                break;
            }
        }
        if (entry == null) {
            line("Could not locate the ELF entry function.");
            line("");
            return;
        }

        Address candidate = null;
        Instruction ins = getInstructionAt(entry);
        for (int i = 0; ins != null && i < 32; i++, ins = ins.getNext()) {
            if (ins.getFlowType().isCall()) {
                break;
            }
            Register dst = ins.getRegister(0);
            if (dst == null || !dst.getBaseRegister().getName().equals("RDI")) {
                continue;
            }
            Scalar s = ins.getScalar(1);
            if (s != null) {
                candidate = toAddr(s.getUnsignedValue());
            }
            for (Reference r : ins.getReferencesFrom()) {
                if (r.getToAddress().isMemoryAddress()) {
                    candidate = r.getToAddress();
                }
            }
        }
        if (candidate == null) {
            line("Could not recover main() from the entry stub.");
            line("");
            return;
        }
        Function main = getFunctionAt(candidate);
        if (main == null) {
            main = createFunction(candidate, "main");
        } else {
            main.setName("main", SourceType.USER_DEFINED);
        }
        line("Recovered main() at %s from the __libc_start_main call in %s.", candidate, entry);
        line("");
    }
}
