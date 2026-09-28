# Static-analysis safety review

Review date: 2026-09-28.

The new extension has no intentional path from target-controlled data into sample execution. It contains no target CLR loader, reflection invocation, process launcher, native-library loader, shell, unsafe deserializer, HTTP client, DNS request, or URL-opening action.

| Boundary | Target-controlled data | Destination / control |
| --- | --- | --- |
| `ConstantStringAnalyzer.Reduce` | IL opcodes, signatures, operands | A bounded stack of extension-owned values. Unsupported operations remain unknown or stop reconstruction. There is no runtime invocation. |
| `ReduceCall` framework rules | Constant strings/bytes and referenced method identities | Explicit host-owned Base64/hex/encoding/concat/reverse/substring/arithmetic transformations. Framework identity and argument data are checked. No reflected function lookup or invocation is used. |
| Pure helper reduction | Same-module static method metadata and known arguments | Validated supported IL only, depth/step/allocation limits, no target delegates or objects. Arbitrary helpers are rejected. This is data reduction, not calling the sample. |
| RVA initialization rule | Field signature/size/RVA bytes | dnlib byte reads after a field-size check. `RuntimeHelpers.InitializeArray` is never called on a target field handle. |
| AES discovery | Algorithm/setter references and constants | Extension-owned marker data and observations. No actual AES object, key operation, or decryptor is created. |
| `ObfuscationProfiler` | Names, IL, static references, attributes | String/statistical comparisons and bounded reference traversal. Attributes are read as metadata; constructors are not instantiated. |
| Manual decoder | Analyst-pasted strings and numeric key/shift | Length-checked built-in transformations. No sample decryptor, expression compiler, scripts, or dynamic invocation. |
| WPF controls | Results and metadata references | Plain text, collection filters, clipboard, and decompiler navigation. UI XAML is compiled application code, never input from a sample. |
| `Navigate` | Method/type/field reference and IL offset | Existing dnSpy decompiler navigation; methods are displayed, not invoked. |
| Text export | Redacted results | User-selected plain-text file. No automatic opening, shell launch, or external requests. |

Event-delegate `Invoke` calls deliver progress or UI actions to fixed application handlers, not functions obtained from target metadata. `new string`, primitive arrays, encoding, and `Array.Reverse` operate exclusively on extension-owned data. No host debugger execution API is used.

Tests inspect a separate fixture DLL with throwing initializers/entry point and a file-writing helper without triggering them. Infinite loops and oversized arrays are stopped by budgets, malformed IL references are reported, and recognized encoded webhook secrets are redacted.

**Limits:** static parsing can still contain vulnerabilities. Timeout is cooperative, not a hard worker-process kill. Host debugger/interactive features can execute code when separately used; the existing startup plugin loader executes installed `*.x.dll` files. Suspicious samples must not be installed as plugins or placed in the application/extension directories.

Static analysis only. The sample was not executed and no discovered network endpoint was contacted. Static analysis establishes code and indicators present in the file, but cannot prove that every runtime capability successfully executes on a particular system.
