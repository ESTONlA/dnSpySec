# Security Analysis extension

This extension adds a dockable **Security Analysis** window under **Edit**. Select a module or member in the document tree, then choose **Security Analysis**. Analysis runs in a background task, supports cancellation, caches results by loaded module, and invalidates the cache on dnSpy document changes. Double-click a finding or IOC to navigate to the method and, when available, the IL location. Embedded resources can be saved through a normal save dialog. Report export supports Markdown, JSON, and text.

The extension is loaded by dnSpy's existing `*.x.dll` discovery. It targets the same `net48` and `net10.0-windows` frameworks as the host and adds no third-party dependencies.

## Placement

- `SecurityModel.cs`: result and evidence objects plus `ISecurityAnalyzer`.
- `SecurityCoordinator.cs`: cancellation, per-analyzer exception isolation, cache, and progress.
- `HashAnalyzer.cs`, `PeAnalyzer.cs`, `ResourceAnalyzer.cs`, `ApiAnalyzer.cs`, `StringIocAnalyzer.cs`, `BehaviorAnalyzer.cs`: independent static passes.
- `SecurityAnalysisWindow.cs`: MEF window, command, and analyst actions.
- `SecurityReportWriter.cs`: Markdown, JSON, and plain-text reports.
- `RULES.md`: rule evidence and interpretation.

## Current limits

Correlation rules use same-method call proximity. They do not prove data flow, call order, runtime execution, or intent. PE inspection reads file-backed modules; in-memory modules may lack file hashes and PE details. The current IOC pass covers HTTP(S) URLs, IPv4 literals, and common registry paths in IL string literals. More IOC types, import-table inspection, Authenticode, detailed CLR header data, obfuscation heuristics, call-chain helpers, rule configuration, and search presets remain future work.

Run the harmless fixture check with:

```powershell
dotnet run --project Extensions\dnSpy.SecurityAnalysis.Tests\dnSpy.SecurityAnalysis.Tests.csproj
```
