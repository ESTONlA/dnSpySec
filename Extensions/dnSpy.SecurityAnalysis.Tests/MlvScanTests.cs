using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using dnlib.DotNet;
using dnSpy.SecurityAnalysis;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

static class MlvScanTests {
	public static void Run(string[] workers) {
		var dto = new JObject {
			["schemaVersion"] = "1.4.0", ["input"] = new JObject { ["sha256Hash"] = "abc" },
			["metadata"] = new JObject { ["coreVersion"] = "1.9.0", ["scanMode"] = "standard" },
			["disposition"] = new JObject { ["classification"] = "KnownThreat", ["relatedFindingIds"] = new JArray() },
			["analysisCompleteness"] = new JObject { ["isComplete"] = true, ["status"] = "Complete" }, ["findings"] = new JArray()
		};
		string Envelope() => new JObject { ["protocolVersion"] = MlvScanProtocol.Version, ["result"] = dto }.ToString(Formatting.None);
		var result = new SecurityResult();
		MlvScanResultMapper.Apply(Envelope(), "abc", null, result);
		Require(result.MlvScan.Summary.Contains("KnownThreat") && result.Findings.Count == 0, "Hash-only verdict was lost");
		var secret = "https://discord.com/api/webhooks/123456789012345678/SECRET_MLV_TEST";
		dto["findings"] = new JArray(new JObject {
			["id"] = "f1", ["ruleId"] = "TestRule", ["severity"] = "Critical", ["visibility"] = "Advanced",
			["description"] = secret, ["codeSnippet"] = secret, ["location"] = "ambiguous.Method",
			["dataFlowChain"] = new JObject { ["nodes"] = new JArray(new JObject { ["nodeType"] = "Sink", ["dataDescription"] = secret, ["location"] = "ambiguous.Method" }) }
		});
		result = new SecurityResult();
		MlvScanResultMapper.Apply(Envelope(), "abc", null, result);
		var finding = result.Findings.Single();
		Require(finding.Severity == SecuritySeverity.Critical && finding.Confidence is null && finding.SupportingSignal, "Signal semantics changed");
		Require(finding.Reference is null && finding.EvidenceItems.Single().Reference is null, "Ambiguous navigation was enabled");
		foreach (var format in new[] { 1, 2, 3 }) {
			var report = SecurityReportWriter.Write(result, format);
			Require(!report.Contains("SECRET_MLV_TEST") && report.Contains("Critical") && report.Contains("KnownThreat"), "Export lost evidence or leaked a secret");
			if (format == 2) {
				var json = JObject.Parse(report);
				Require(json["findings"]![0]!["confidence"]!.Type == JTokenType.Null, "Absent confidence became a value");
				Require((string?)json["mlvscan"]?["result"]?["findings"]?[0]?["id"] == "f1", "Core IDs were lost");
			}
		}
		dto["analysisCompleteness"]!["isComplete"] = false;
		dto["analysisCompleteness"]!["status"] = "Partial";
		result = new SecurityResult(); MlvScanResultMapper.Apply(Envelope(), "abc", null, result);
		Require(result.MlvScan.Status == "Incomplete", "Incomplete became completed");
		ExpectInvalid(() => MlvScanResultMapper.Apply(Envelope(), "wrong-hash", null, new SecurityResult()));
		dto["schemaVersion"] = "99.0.0";
		ExpectInvalid(() => MlvScanResultMapper.Apply(Envelope(), "abc", null, new SecurityResult()));
		var options = new SecurityAnalysisOptions { IncludeMlvScan = true };
		result = new SecurityResult();
		new MlvScanAnalyzer(options).Analyze(new SecurityContext(null, "native.exe", CancellationToken.None), result);
		Require(result.MlvScan.Status == "Skipped", "Native input was treated as a managed scan");
		using var module = ModuleDefMD.Load(typeof(HarmlessFixture).Assembly.Location);
		options.MlvScanUnavailableReason = "Edited document";
		result = new SecurityResult();
		new MlvScanAnalyzer(options).Analyze(new SecurityContext(module, module.Location, CancellationToken.None), result);
		Require(result.MlvScan.Status == "Skipped", "Edited input was not rejected");
		options.MlvScanUnavailableReason = string.Empty;
		result = new SecurityResult { Sha256 = "wrong-content" };
		new MlvScanAnalyzer(options).Analyze(new SecurityContext(module, module.Location, CancellationToken.None), result);
		Require(result.MlvScan.Status == "Failed" && result.MlvScan.Result is null, "Mismatched built-in input was accepted");
		TestNavigation(dto, module);
		TestReplacedInput(options);
		foreach (var worker in workers) RunWorker(worker);
		TestWorkerLifecycle();
		Console.WriteLine("MLVScan mapping/eligibility tests passed; worker integrations: " + workers.Length);
	}

	static void RunWorker(string worker) {
		var fixture = Path.Combine(AppContext.BaseDirectory, "HostileFixture.dll");
		var bytes = File.ReadAllBytes(fixture);
		using var module = ModuleDefMD.Load(fixture);
		var client = new MlvScanWorkerClient(Path.GetFullPath(worker));
		using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
		var timer = Stopwatch.StartNew();
		var json = client.ScanAsync(bytes, false, timeout.Token).GetAwaiter().GetResult();
		var result = new SecurityResult();
		MlvScanResultMapper.Apply(json, MlvScanAnalyzer.Hash(bytes), module, result);
		Require(result.MlvScan.Result?["disposition"] is JObject && result.Findings.Count > 0, "Real Core scan did not return evidence");
		var again = client.ScanAsync(bytes, false, timeout.Token).GetAwaiter().GetResult();
		var a = JObject.Parse(json); var b = JObject.Parse(again);
		NormalizeRunMetadata(a); NormalizeRunMetadata(b);
		Require(JToken.DeepEquals(a, b), "Repeated scans changed semantic output");
		var deep = JObject.Parse(client.ScanAsync(bytes, true, timeout.Token).GetAwaiter().GetResult());
		Require((string?)deep["result"]?["metadata"]?["scanMode"] == "deep", "Deep mode was not reported");
		var malformed = JObject.Parse(client.ScanAsync(new byte[] { 1, 2, 3, 4 }, false, timeout.Token).GetAwaiter().GetResult());
		Require((bool?)malformed["result"]?["analysisCompleteness"]?["isComplete"] == false &&
			(string?)malformed["result"]?["disposition"]?["classification"] != "Clean", "Malformed input was clean");
		using var canceled = new CancellationTokenSource(); canceled.Cancel();
		try { client.ScanAsync(bytes, false, canceled.Token).GetAwaiter().GetResult(); throw new Exception("Canceled scan ran"); }
		catch (OperationCanceledException) { }
		Console.WriteLine("Worker passed: " + worker + " (" + result.Findings.Count + " findings; suite " + timer.ElapsedMilliseconds + " ms)");
	}
	static void ExpectInvalid(Action action) { try { action(); } catch (InvalidDataException) { return; } throw new Exception("Invalid Core result was accepted"); }
	static void TestWorkerLifecycle() {
		var client = new MlvScanWorkerClient(Path.Combine(AppContext.BaseDirectory, "worker-fixture", "dnSpy.MlvScanWorkerFixture.exe"));
		using (var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(700))) {
			try { client.ScanAsync(new byte[] { 1 }, true, stop.Token).GetAwaiter().GetResult(); throw new Exception("Blocking worker did not cancel"); }
			catch (Exception ex) when (stop.IsCancellationRequested && (ex is OperationCanceledException || ex is IOException)) { }
		}
		using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10))) {
			ExpectInvalid(() => client.ScanAsync(new byte[] { 1 }, false, stop.Token).GetAwaiter().GetResult());
		}
		Require(Process.GetProcessesByName("dnSpy.MlvScanWorkerFixture").Length == 0, "Worker was not reaped");
		using var module = ModuleDefMD.Load(typeof(HarmlessFixture).Assembly.Location);
		var result = new SecurityResult();
		result.Findings.Add(new SecurityFinding { RuleId = "BUILTIN" });
		new MlvScanAnalyzer(new SecurityAnalysisOptions { IncludeMlvScan = true, DeepMlvScan = true }, client, TimeSpan.FromMilliseconds(700))
			.Analyze(new SecurityContext(module, module.Location, CancellationToken.None), result);
		Require(result.MlvScan.Status == "Timed out" && result.Findings.Single().RuleId == "BUILTIN", "Core deadline discarded built-in findings");
		Require(Process.GetProcessesByName("dnSpy.MlvScanWorkerFixture").Length == 0, "Timed-out worker was not reaped");
	}
	static void TestNavigation(JObject dto, ModuleDef module) {
		dto["schemaVersion"] = "1.4.0";
		var method = module.GetTypes().SelectMany(t => t.Methods).Single(m => m.Name == "Url");
		dto["findings"] = new JArray(new JObject { ["severity"] = "Low", ["location"] = method.DeclaringType.FullName + "." + method.Name + ":0" });
		string Json() => new JObject { ["protocolVersion"] = MlvScanProtocol.Version, ["result"] = dto }.ToString();
		var result = new SecurityResult(); MlvScanResultMapper.Apply(Json(), "abc", module, result);
		Require(result.Findings.Single().Reference == method && result.Findings.Single().IlOffset == 0, "Unique location did not navigate");
		using var overloaded = new ModuleDefUser("overloads");
		var type = new TypeDefUser("Fixtures", "Overloads", overloaded.CorLibTypes.Object.TypeDefOrRef); overloaded.Types.Add(type);
		type.Methods.Add(new MethodDefUser("Run", MethodSig.CreateStatic(overloaded.CorLibTypes.Void)));
		type.Methods.Add(new MethodDefUser("Run", MethodSig.CreateStatic(overloaded.CorLibTypes.Void, overloaded.CorLibTypes.Int32)));
		dto["findings"]![0]!["location"] = "Fixtures.Overloads.Run:0";
		result = new SecurityResult(); MlvScanResultMapper.Apply(Json(), "abc", overloaded, result);
		Require(result.Findings.Single().Reference is null, "Ambiguous overload became navigable");
	}
	static void TestReplacedInput(SecurityAnalysisOptions options) {
		var path = Path.GetTempFileName();
		try {
			var bytes = File.ReadAllBytes(typeof(HarmlessFixture).Assembly.Location);
			File.WriteAllBytes(path, bytes);
			var stamp = File.GetLastWriteTimeUtc(path);
			using var loaded = ModuleDefMD.Load(bytes); loaded.Location = path;
			var replacement = (byte[])bytes.Clone(); replacement[replacement.Length - 1] ^= 1;
			File.WriteAllBytes(path, replacement); File.SetLastWriteTimeUtc(path, stamp);
			var result = new SecurityResult();
			new MlvScanAnalyzer(options).Analyze(new SecurityContext(loaded, path, CancellationToken.None), result);
			Require(result.MlvScan.Status == "Failed" && result.MlvScan.Details.Contains("differs"), "Same-size/timestamp replacement was accepted");
		} finally { File.Delete(path); }
	}
	static void NormalizeRunMetadata(JObject envelope) {
		envelope["result"]!["metadata"]!["timestamp"] = null;
		var ids = ((JArray)envelope["result"]!["findings"]!).Select((f, index) => new { Id = (string?)f["id"], Value = "finding-" + index }).Where(p => p.Id is not null).ToDictionary(p => p.Id!, p => p.Value);
		foreach (var value in envelope.Descendants().OfType<JValue>())
			if (value.Type == JTokenType.String && ids.TryGetValue((string)value!, out var stable)) value.Value = stable;
	}
	static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
