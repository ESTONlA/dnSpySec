# Security Analysis extension

This extension adds a dockable **Security Analysis** window under **Edit**. Select a .NET module/member or a native PE document in the document tree, then choose **Security Analysis**. Analysis runs in a background task with cancellation and a timeout. Double-click a finding, evidence item, or IOC to navigate to a method and, when available, the IL location. Embedded .NET resources can be saved through a normal save dialog. Report and IOC export support Markdown, JSON, and text.

The panel opens on **Findings**, with text search, severity/category filters, sortable columns, and a resizable detail/evidence pane. Press Enter on a finding or use **Go to code** to navigate. **Overview** separates file information, hashes with copy buttons, PE information, configuration, and analysis limits. IOC copy/export actions and resource extraction are placed in their own tabs. The selected file, severity totals, progress, and static-only status remain visible. Results are cleared when the selected analyzed document changes or is removed; canceled or failed analysis does not leave an earlier file's report available for export.

The extension is loaded by dnSpy's existing `*.x.dll` discovery and targets the same `net48` and `net10.0-windows` frameworks as the host. **Include MLVScan** adds an optional local MLVScan.Core scan of the saved managed assembly. The bundled worker keeps Core and Mono.Cecil outside the WPF process. See [MLVScan integration](MLVSCAN.md) for supported inputs, evidence, limits, build steps, and tests.

## Placement

- `SecurityModel.cs`: result and evidence objects plus `ISecurityAnalyzer`.
- `SecurityCoordinator.cs`: cancellation, timeout, per-analyzer exception isolation, cache, and progress.
- `HashAnalyzer.cs`, `PeAnalyzer.cs`, `PyInstallerAnalyzer.cs`, `ResourceAnalyzer.cs`, `ConfigurationAnalyzer.cs`, `ApiAnalyzer.cs`, `StringIocAnalyzer.cs`, `BehaviorAnalyzer.cs`, `BehaviorChainAnalyzer.cs`: independent static passes.
- `SafePythonMarshalReader.cs`: bounded PYZ table parser; it does not parse or execute Python code objects.
- `SecurityAnalysisWindow.cs`: MEF window, command, and analyst actions.
- `SecurityAnalysisControl.xaml` and `.xaml.cs`: themed panel layout, filters, sorting, selection details, and action availability.
- `SecurityReportWriter.cs`: Markdown, JSON, and plain-text reports.
- `RULES.md`: rule evidence and interpretation.
- `SECURITY_REVIEW.md`: target-data boundaries and static-only audit.

## Current limits

Correlation rules use same-method or same-type co-occurrence. They do not prove data flow, call order, runtime execution, or intent. File-backed modules and native PE documents have PE/overlay information; in-memory modules may lack it. PyInstaller CArchive and PYZ tables are parsed as data, with bounded decompression of selected top-level entries. Python bytecode is not disassembled. Detailed import-table analysis, certificate subject/issuer and offline chain inspection, embedded JSON/XML settings, deeper obfuscation analysis, full call-chain graphs, rule configuration, and search presets remain future work. See `SECURITY_REVIEW.md` for safety boundaries.

Run the harmless fixture check with:

```powershell
dotnet run --project Extensions\dnSpy.SecurityAnalysis.Tests\dnSpy.SecurityAnalysis.Tests.csproj
```
