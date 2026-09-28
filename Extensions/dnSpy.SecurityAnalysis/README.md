# Security Analysis extension

This extension adds a dockable **Security Analysis** window under **Edit**. Select a .NET module/member or a native PE document in the document tree, then choose **Security Analysis**. Analysis runs in a background task with cancellation and a timeout. Double-click a finding, evidence item, or IOC to navigate to a method and, when available, the IL location. Embedded .NET resources can be saved through a normal save dialog. Report and IOC export support Markdown, JSON, and text.

The panel opens on **Findings**, with text search, severity/category filters, sortable columns, and a resizable detail/evidence pane. Press Enter on a finding or use **Go to code** to navigate. **Overview** separates file information, hashes with copy buttons, PE information, configuration, and analysis limits. IOC copy/export actions and resource extraction are placed in their own tabs. The selected file, severity totals, progress, and static-only status remain visible. Results are cleared when the selected analyzed document changes or is removed; canceled or failed analysis does not leave an earlier file's report available for export.

The extension is loaded by dnSpy's existing `*.x.dll` discovery. It targets the same `net48` and `net10.0-windows` frameworks as the host and adds no third-party dependencies.

## Hidden payloads inside normal-looking mods

Security Analysis automatically reuses the companion **Static String Analysis** extension's bounded constant reducer. This is an internal project dependency using the same frameworks and dnlib APIs; no packages or executable sample helpers are introduced.

The **Hidden content** tab displays recovered text, transformation, source, confidence, byte size, SHA-256, and a bounded preview. It inspects literal strings, assembly/module attribute arguments, constant fields, size-checked RVA field data, and embedded resources. Candidate decoders recognize Base64 (including UTF-16 PowerShell command text), hex, decimal character-code tables, Unicode/hex escapes, and percent-encoded bytes. Bounded gzip and ZIP inspection can reveal nested configuration, scripts, or PE headers. ZIP filenames are labels only; entries are never written to disk automatically. Decoded URLs are added to IOCs without contacting them.

Batch normalization is an explicitly **heuristic display**: literal `SET` values are substituted, carets removed, and unknown long alphabetic variable names assumed empty. Ordinary environment references remain literal. This is not a cmd interpreter: it does not read the host environment, run commands, or establish runtime output. General shell semantics, arbitrary decryptors, encrypted archives, and AES payload decryption remain unsupported.

Focused `MOD001–004` rules connect download/write/launch, encoded reflected command names, and embedded script extraction through bounded same-module call references. Async/iterator metadata and delegate targets help connect compiler-generated methods to recognized mod callbacks and initializers. Direct launch chains use outgoing references; reflective chains may also follow labeled incoming caller references. Configuration override evidence is preferred over visible fallback URLs. These are static neighborhoods and reference paths, **not proven argument flow, execution order, or intent**. Each supplied example produces a focused high-priority chain even when its obfuscation profile is low; that does not make obfuscation a malware score.

Resource source navigation goes to an identified method that references the resource. It does not invoke resource deserializers. Unreferenced resources remain available as data previews and explicit save actions.

Limits: 2 MiB input resources, 64 KiB RVA fields, 4 MiB per decoded/decompressed value, 16 MiB total inspected bytes, 512 content rows, 2,048 candidate decode attempts, four transformation layers, two nested archive layers, 32 ZIP entries, and a 100:1 decompression ratio with a 64 KiB minimum allowance. Invalid/limited sources report coverage errors while other sources continue. The existing coordinator adds cancellation and a 180-second cooperative timeout. The constant reducer separately bounds IL, helper depth, and output; it can now inspect fresh constant regions after unrelated unsupported code without carrying runtime locals across regions.

## Placement

- `SecurityModel.cs`: result and evidence objects plus `ISecurityAnalyzer`.
- `SecurityCoordinator.cs`: cancellation, timeout, per-analyzer exception isolation, cache, and progress.
- `HashAnalyzer.cs`, `PeAnalyzer.cs`, `PyInstallerAnalyzer.cs`, `ResourceAnalyzer.cs`, `ConfigurationAnalyzer.cs`, `HiddenContentAnalyzer.cs`, `ApiAnalyzer.cs`, `StringIocAnalyzer.cs`, `BehaviorAnalyzer.cs`, `BehaviorChainAnalyzer.cs`, `TargetedBehaviorAnalyzer.cs`: independent static passes.
- `HiddenContentDecoder.cs`: bounded data decoders, archive reads, and candidate batch normalization.
- `SafePythonMarshalReader.cs`: bounded PYZ table parser; it does not parse or execute Python code objects.
- `SecurityAnalysisWindow.cs`: MEF window, command, and analyst actions.
- `SecurityAnalysisControl.xaml` and `.xaml.cs`: themed panel layout, filters, sorting, selection details, and action availability.
- `SecurityReportWriter.cs`: Markdown, JSON, and plain-text reports.
- `RULES.md`: rule evidence and interpretation.
- `SECURITY_REVIEW.md`: target-data boundaries and static-only audit.

## Current limits

Legacy correlation rules use same-method or same-type co-occurrence; focused mod rules additionally use bounded metadata reference neighborhoods. Neither proves data flow, call order, runtime execution, or intent. File-backed modules and native PE documents have PE/overlay information; in-memory modules may lack it. PyInstaller CArchive and PYZ tables are parsed as data, with bounded decompression of selected top-level entries. Python bytecode is not disassembled. Detailed import-table analysis, certificate subject/issuer and offline chain inspection, semantic JSON/XML settings resolution, general-purpose decryptors, full call-chain graphs, rule configuration, and search presets remain future work. See `SECURITY_REVIEW.md` for safety boundaries.

Run the harmless fixture check with:

```powershell
dotnet run --project Extensions\dnSpy.SecurityAnalysis.Tests\dnSpy.SecurityAnalysis.Tests.csproj
```

Optional read-only sample validation (byte/dnlib parsing only):

```powershell
dotnet run --project Extensions\dnSpy.SecurityAnalysis.Tests\dnSpy.SecurityAnalysis.Tests.csproj -c Release -- --inspect-samples "C:\path\to\samples"
```

This prints rule coverage and verifies sample hashes did not change. Samples are never copied into the application/plugin directories or invoked. See [SAMPLE_VALIDATION.md](SAMPLE_VALIDATION.md) for the supplied examples and limitations of that check.
