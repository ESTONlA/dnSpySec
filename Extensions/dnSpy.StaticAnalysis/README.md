# Static String Analysis extension

Open a .NET assembly as a document, select a module/member, and choose **Security > Static String Analysis**. This companion to Security Analysis adds a dockable window with reconstructed strings, a manual decoder, an obfuscation profile, AES configuration observations, and coverage information.

This extension targets the host's `net48` and `net10.0-windows` frameworks, uses existing dnlib and dnSpy APIs, and adds no packages. It does not modify the assembly or replace normal decompilation.

## Static-only reconstruction

The analyzer reduces a deliberately small subset of IL into its own integer, string, byte-array, and character-array data values. Supported calls use explicit data-transformation rules. It never invokes the referenced method, creates a target object, loads the target into the CLR, or uses dnSpy's debugger interpreter.

| Operation | Automatic support | Manual decoder |
| --- | --- | --- |
| Base64 | Constant `Convert.FromBase64String` data; separately labelled endpoint-like literal candidates | Base64 to strict UTF-8 |
| Hex | Constant `Convert.FromHexString` or two-digit `Convert.ToByte(..., 16)` | Hex to strict UTF-8 |
| UTF-8 / ASCII | Constant `Encoding.GetBytes/GetString` data | UTF-8 output for byte decoders |
| XOR | Bounded byte/character loops with known operands, including pure same-module helpers | Hex bytes plus a single-byte key |
| ROT-like arithmetic | Supported constant character loops with integer arithmetic/modulo | ASCII ROT with an explicit shift |
| Reverse | Constant `ToCharArray`, `Array.Reverse`, and `new string(char[])` | Reverse UTF-16 characters |
| Concatenation | Two to four constant string arguments to `String.Concat` | Chain operations by copying the displayed result |
| Arithmetic | Unchecked I4 arithmetic, bitwise operations, comparisons, and narrow integer conversions | Used by XOR/ROT operations |
| RVA arrays | Size-checked field bytes for `RuntimeHelpers.InitializeArray` | Not applicable |
| AES settings | API references and known key/IV/mode/padding/size settings; key bytes redacted | No AES decryption |

Each string shows **Original**, **Decoded**, **Transformation**, and **Source** (`Namespace.Type.Method IL_003A`). Double-click a row or use **Go to source** to navigate. Recognized Discord/Slack/Telegram endpoint secrets are redacted, including encoded originals when they reveal a secret. Reports export as plain text and are never opened automatically.

**Limitations:** this is not a general IL emulator. Runtime fields, unknown inputs, unsupported calls/opcodes, native-sized arithmetic, exception-handler paths, and unknown branch conditions remain unresolved. Helper bodies must contain only supported pure operations; recursion is bounded. A supported prefix may be reconstructed in a method that later uses unsupported operations. Reconstruction does not establish runtime reachability or successful behavior. Strict UTF-8 rejects invalid byte sequences. Characters outside ASCII are not rotated by the manual ROT operation.

Up to 64 fresh constant regions can also be inspected within each method's existing shared step/allocation budget. These regions start at literals or known encoding getters after unrelated unsupported code. Each starts with unknown locals and an empty stack; no runtime state is carried across regions and reachability is not asserted. Security Analysis now consumes these results automatically in its Hidden content pass.

## Obfuscation profile

The profile level describes obfuscation indicators, **not malware likelihood**. Ordinary Unicode names do not increase the level. Compiler-generated types/members and angle-bracket generated names are excluded from identifier statistics; tiny-method statistics include all readable method bodies, so ordinary accessors/wrappers can affect the ratio.

| Rule | Observation / evidence | Weight threshold |
| --- | --- | --- |
| OBF101 | Empty, control/format, invalid-surrogate, or mixed Latin/Greek/Cyrillic names; Unicode count reported separately | 2 if at least 10 unusual names and at least 10% of inspected names |
| OBF102 | Names at least 128 characters; entropy at least 4.2 bits/character for names of 24–16,384 characters | 1 if at least 10 long names, or at least 10 high-entropy names making up at least 10% |
| OBF103 | Method bodies under 8 IL instructions | 1 if at least 100 bodies and at least 80% are tiny |
| OBF104 | Short same-module forwarding chains of at least 3 methods; trace depth limited to 8 | 2 if at least 3 starting methods have such chains |
| OBF105 | Switch with at least 8 targets, locals, and a backward unconditional branch | 2 if present; possible flattening/state-machine pattern |
| OBF106 | Static byte/string-array reference and decode/XOR operations in a string-returning method | 2 if present; encoded-table candidate, encryption not proven |
| OBF107 | Invalid branch/switch/local references or metadata-reader failures | 1 if present; reader failure alone does not prove malformed metadata |

Level is **High** at a combined weight of at least 4 across at least two rules, **Medium** at weight 2–3, and **Low** below that. Failed profile analysis is **Unknown**. Each indicator explains its rationale and links up to 20 examples. Pattern and identifier counts are observations; their interpretation is heuristic. No specific obfuscator is identified.

## Bounds and coverage

- 16,384 characters/elements per value and 32 KiB maximum RVA field data.
- 10,000 IL instructions per method; 4,096 locals; 256 stack values.
- 50,000 reduction steps and 131,072 allocated array elements per root method.
- 2,000,000 string-analysis instruction/validation steps per module and helper depth 4.
- 100,000 methods, 2,000 string rows, and a 2 Mi-character raw string-output budget.
- 2,000 AES observations; up to 20 evidence examples per profile rule.
- Cancellation checks, a 60-second cooperative timeout, and per-method exception isolation.

Coverage lists unsupported/limited methods and analysis failures. No results does not establish safety. Limits supplement dnlib's parsing; they do not provide process isolation or guarantee immunity from parser vulnerabilities.

## Tests

```powershell
dotnet run --project Extensions/dnSpy.StaticAnalysis.Tests/dnSpy.StaticAnalysis.Tests.csproj -c Release
```

Harmless IL fixtures exercise decoding, arithmetic loops, pure helpers, AES observations, secret redaction, invalid references, cancellation, and resource budgets. Throwing module/static initializers and an entry point, plus a forbidden file-writing helper, are inspected without invoking them.

See [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the data-to-execution boundary review.
