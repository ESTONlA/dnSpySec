# dnSpySec v4.0.0 — Security analysis improvements

This release makes it easier to investigate suspicious mods and assemblies while keeping the evidence close to the code. Security tools now have their own menu, and new views help connect findings to the methods and files behind them.

## What's new

- **Security menu:** Security Analysis and Static String Analysis are now grouped in a top level menu beside Help.
- **Whole mod package scan:** Inspect a ZIP package as a whole, including its DLLs, scripts, configuration files, and other assets. The Mod package tab shows file hashes, findings, and links between DLL references and files in the archive. You can export a plain text package report.
- **Optional MLVScan analysis:** Select **Include MLVScan** in Security Analysis to add its findings to the built in results. Filter findings by engine, expand supporting signals, and follow available links to methods or IL. The overview shows MLVScan's assessment and scan completeness. Its results are also included in Markdown, JSON, and text reports.
- **Startup paths:** Explore recognized mod callbacks and initializers, along with reachable methods and nearby security relevant API references. Double click a method to inspect it.
- **Version comparison:** Compare the current mod with an older saved DLL or EXE. The Version changes tab highlights newly observed APIs, IOCs, resources, decoded content, and findings, with code navigation where available.
- **Context for decoded content:** Hidden content details now show API references near the IL instruction that produced a decoded value. These are nearby references, not proof that an API uses the value.
- **Cleaner analysis windows:** Security Analysis and Static String Analysis now give the selected file its own line, so actions stay readable when the window is narrow. Finding details clearly separate the explanation from supporting evidence, and the manual decoder labels its input and output.

Startup paths, nearby references, and version comparison are included in Markdown, JSON, and text exports.

## Analysis and safety

Analysis remains static. The inspected assembly and any comparison file are read as data; Security Analysis does not load them into the CLR, invoke their methods, or contact discovered URLs. Optional MLVScan runs locally in a separate worker that receives sample bytes as data. It supports cancellation and time limits, and **Deeper scan** raises its analysis limits.

Version comparison runs in the background and can be canceled. If the current file changes after analysis, analyze it again before comparing versions.

## Notes

- MLVScan supports saved, unmodified, single module managed DLLs and EXEs up to 64 MiB. It does not scan DLLs inside a ZIP package scan. A `Clean` result is not a guarantee of safety, and a blocking recommendation does not cause dnSpySec to block, delete, or quarantine a file.
- Startup paths and nearby API references are investigation aids. They do not establish a complete runtime call graph or prove how a value is used. Version comparison shows newly observed evidence, so a renamed method may appear as new.
- The MLVScan worker has resource limits, but it is not an operating system sandbox. As with the existing dnSpy host, installed application extensions are loaded at startup; keep suspicious files out of dnSpySec's application and extension directories.
