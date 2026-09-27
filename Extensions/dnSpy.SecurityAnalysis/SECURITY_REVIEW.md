# Static-analysis security review

Review date: 2026-09-27. Security Analysis does not call `Assembly.Load`, `Process.Start`, `ShellExecute`, `LoadLibrary`, PowerShell, a shell, or a network request API on target data. Those names appear in rule strings only. The test fixture has a throwing module initializer, static constructor, and entry point; its inspection succeeds without invoking any of them.

## Target-controlled data boundaries

| Location | Target input | Destination | Execution risk and control |
| --- | --- | --- | --- |
| `HashAnalyzer`, `PeAnalyzer`, `PyInstallerAnalyzer` | File bytes and PE/archive offsets | BCL streams, bounded binary parsing | Data parsing only; 1 GiB file limit, offset/size checks, 8 MiB TOC limit, 10,000 entry limit, 180 s timeout, cancellation. |
| `PyInstallerAnalyzer`, `SafePythonMarshalReader` | Compressed entries and PYZ table | `DeflateStream` and narrow marshal table reader | Data parsing only. Decompression capped at 8 MiB per entry and 64 MiB total with a ratio limit. No Python import, code-object parsing, or execution. |
| `ResourceAnalyzer` | Embedded resource bytes | Hashing and header checks | Data parsing only; 64 MiB per-resource limit. |
| `ApiAnalyzer`, `BehaviorAnalyzer`, `BehaviorChainAnalyzer`, `StringIocAnalyzer`, `ConfigurationAnalyzer` | dnlib metadata, IL, attributes, and strings | In-memory comparisons, regex, `Uri.TryCreate` | `Uri.TryCreate` does not resolve DNS or make requests. `ResolveMethodDef` uses dnlib metadata resolution, not CLR loading or method invocation. Strings are capped at 16 KiB for scanning. |
| `SecurityAnalysisWindow.FollowEvidence` | Target method/IL reference | dnSpy decompiler navigation | Displays code through existing dnSpy UI; does not invoke the method. |
| `SecurityAnalysisWindow.ExtractResourceAsync` | Resource bytes and name | User-selected file | Filename is reduced to a basename and sanitized; at most 64 MiB is copied. The saved file is never opened or launched automatically. |
| `SecurityReportWriter`, IOC copy/export | Findings and strings | WPF text, clipboard, user-selected report file | Text/data output only. Recognized Discord webhook URLs are redacted in generated findings and IOCs. |

No Security Analysis path intentionally crosses from target-controlled data into code execution. The host itself discovers and executes `*.x.dll` **extensions placed in dnSpy's application or extension directories** at startup. That existing plugin-loading behavior is separate from opening a document; suspicious samples must not be placed in those directories. This review does not claim that arbitrary hostile-file parser bugs are impossible.

## Deliberate limits

The analyzer does not run samples, Python bytecode, scripts, installers, extracted resources, or discovered endpoints. It does not recursively open nested archives. PYZ parsing lists module names and offsets but does not disassemble Python bytecode. Authenticode certificate table presence is reported without online chain validation or trust judgment.
