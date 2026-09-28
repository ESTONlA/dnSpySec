using System;
using System.IO;
using System.Linq;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnSpy.StaticAnalysis;

static class Program {
	static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
	static int Main() {
		var marker = Path.Combine(Path.GetTempPath(), "dnspy-static-fixture-must-not-run.txt");
		Require(!File.Exists(marker), "Fixture marker already exists; choose a clean test environment.");
		using var module = ModuleDefMD.Load(Path.Combine(AppContext.BaseDirectory, "StaticFixture.dll"));
		var result = new StaticAnalysisCoordinator().Analyze(module, CancellationToken.None);
		foreach (var pattern in new[] { ("Base64", "https://example.org/static"), ("DecodeAfterUnrelated", "https://example.org/static"), ("Bytes", "hello"), ("EncodeThenXor", "hello"), ("Hex", "https://example.org"),
			("Reverse", "example"), ("Xor", "hello"), ("Rot", "hello"), ("Concat", "https://example.org"), ("ForbiddenAfterDecode", "https://example.org/static") })
			Require(result.Strings.Any(s => s.Reference?.Name == pattern.Item1 && s.Decoded == pattern.Item2), "Missing reconstructed fixture: " + pattern.Item1);
		Require(!File.Exists(marker), "Analyzer invoked a forbidden sample helper.");
		Require(result.Strings.Any(s => s.Reference?.Name == "Webhook" && s.Decoded.Contains("[REDACTED]") && s.Original == "[ENCODED SECRET REDACTED]"), "Encoded webhook secret was not redacted.");
		Require(!StaticReportWriter.Write(result).Contains("SECRET_TOKEN", StringComparison.Ordinal), "Report leaked a webhook secret.");
		Require(result.Crypto.Any(c => c.Property == "Key" && c.Value.Contains("16 constant bytes")), "AES constant key observation missing.");
		Require(result.Crypto.Any(c => c.Property == "IV" && c.Value.Contains("303132")), "AES IV observation missing.");
		Require(result.MethodsWithUnresolvedOperations > 0, "Coverage must report unknown operations.");
		Require(ConstantTransforms.Decode("uryyb", "ROT") == "hello", "Manual ROT failed.");
		Require(ConstantTransforms.Decode("6b666f6f6c", "XOR hex / UTF-8", 3) == "hello", "Manual XOR failed.");
		bool rejected = false;
		try { ConstantTransforms.Decode(new string('A', StaticLimits.MaximumValueLength + 1), "Base64"); } catch (InvalidOperationException) { rejected = true; }
		Require(rejected, "Oversized manual input was accepted.");
		using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
		rejected = false; try { new StaticAnalysisCoordinator().Analyze(module, cancellation.Token); } catch (OperationCanceledException) { rejected = true; }
		Require(rejected, "Cancellation not honored.");
		CheckBudgets(); CheckProfile(); CheckFrameworkIdentity();
		Console.WriteLine("Static string/profile tests passed: " + result.Strings.Count + " string observations; no fixture code executed.");
		return 0;
	}
	static MethodDef Method(ModuleDef module, TypeDef type, string name, params Instruction[] instructions) {
		var method = new MethodDefUser(name, MethodSig.CreateStatic(module.CorLibTypes.String), MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
		foreach (var instruction in instructions) method.Body.Instructions.Add(instruction);
		type.Methods.Add(method); return method;
	}
	static void CheckBudgets() {
		using var module = new ModuleDefUser("Limits"); var type = new TypeDefUser("Fixtures", "Limits", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(type);
		var loop = Instruction.Create(OpCodes.Nop);
		Method(module, type, "Loop", loop, Instruction.Create(OpCodes.Br, loop));
		Method(module, type, "Huge", Instruction.CreateLdcI4(int.MaxValue), Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef), Instruction.Create(OpCodes.Ret));
		var result = new StaticAnalysisCoordinator().Analyze(module, CancellationToken.None);
		Require(result.MethodsWithUnresolvedOperations == 2, "Loop/allocation limits not reported.");
		Require(result.Strings.Count == 0, "Invalid bounded fixture produced a string.");
	}
	static void CheckProfile() {
		using var normal = new ModuleDefUser("Unicode"); normal.Types.Add(new TypeDefUser("Fixtures", "Tööriist", normal.CorLibTypes.Object.TypeDefOrRef));
		var normalResult = new StaticAnalysisResult(); new ObfuscationProfiler().Analyze(normal, normalResult, CancellationToken.None);
		Require(normalResult.ProfileLevel == "Low" && normalResult.Indicators.Single(i => i.RuleId == "OBF101").Weight == 0, "Legitimate Unicode raised profile weight.");
		using var unusual = new ModuleDefUser("Profile");
		for (int i = 0; i < 20; i++) {
			var type = new TypeDefUser("Fixtures", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP\u200D" + i, unusual.CorLibTypes.Object.TypeDefOrRef); unusual.Types.Add(type);
			for (int j = 0; j < 7; j++) Method(unusual, type, "M" + j, Instruction.Create(OpCodes.Ldstr, "benign"), Instruction.Create(OpCodes.Ret));
		}
		var result = new StaticAnalysisResult(); new ObfuscationProfiler().Analyze(unusual, result, CancellationToken.None);
		Require(result.ProfileLevel == "High", "Combined profile thresholds not applied.");
		Require(result.Indicators.Single(i => i.RuleId == "OBF103").Title.Contains("100"), "Tiny-method ratio missing.");
		var invalid = Instruction.Create(OpCodes.Nop);
		Method(unusual, unusual.Types[1], "InvalidBranch", Instruction.Create(OpCodes.Br, invalid));
		var broken = new StaticAnalysisResult(); new ObfuscationProfiler().Analyze(unusual, broken, CancellationToken.None);
		Require(broken.Indicators.Single(i => i.RuleId == "OBF107").Evidence.Any(e => e.Description.Contains("outside the method body")), "Invalid IL reference not reported.");
	}
	static void CheckFrameworkIdentity() {
		using var module = new ModuleDefUser("Identity");
		var spoof = new TypeDefUser("System", "Convert", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(spoof);
		var helper = new MethodDefUser("FromBase64String", MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.String), MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
		foreach (var i in new[] { Instruction.CreateLdcI4(1), Instruction.Create(OpCodes.Newarr, module.CorLibTypes.Byte.TypeDefOrRef), Instruction.Create(OpCodes.Dup), Instruction.CreateLdcI4(0), Instruction.CreateLdcI4(88), Instruction.Create(OpCodes.Stelem_I1), Instruction.Create(OpCodes.Ret) }) helper.Body.Instructions.Add(i);
		spoof.Methods.Add(helper);
		var importer = new Importer(module);
		var encoding = importer.Import(typeof(System.Text.Encoding).GetProperty("UTF8")!.GetMethod!);
		var getString = importer.Import(typeof(System.Text.Encoding).GetMethod("GetString", new[] { typeof(byte[]) })!);
		Method(module, spoof, "Caller", Instruction.Create(OpCodes.Call, encoding), Instruction.Create(OpCodes.Ldstr, "aGVsbG8="), Instruction.Create(OpCodes.Call, helper), Instruction.Create(OpCodes.Callvirt, getString), Instruction.Create(OpCodes.Ret));
		var result = new StaticAnalysisResult(); new ConstantStringAnalyzer().Analyze(module, result, CancellationToken.None);
		Require(result.Strings.Any(s => s.Decoded == "X") && result.Strings.All(s => !s.Transformation.Contains("Base64")), "Target-defined System.Convert was mistaken for the framework implementation.");
	}
}
