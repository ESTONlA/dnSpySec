using System;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using dnlib.DotNet;
using dnSpy.SecurityAnalysis;

// The fixture methods are inspected as IL. They are never called by the test.
static class HarmlessFixture {
	[DllImport("kernel32.dll", EntryPoint = "OpenProcess")]
	public static extern IntPtr DeclaredOpenProcess(uint access, bool inherit, uint id);

	public static Assembly DecodeAndLoad(byte[] bytes) {
		var decoded = Convert.FromBase64String("TVqQAAMAAAAEAAAA");
		return Assembly.Load(decoded.Length == 0 ? bytes : decoded);
	}

	public static string Url() => "https://example.org/static-test";
	public static string RunKey() => @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
	public static string UserAgent() => "Chrome/120.0.0.0";
	public static string Webhook() => "https://discord.com/api/webhooks/123456789012345678/SECRET_TOKEN_FIXTURE";
	public static string SlackHook() => "https://hooks.slack.com/services/T123/B456/SECRET_SLACK_FIXTURE";
	public static string TelegramHook() => "https://api.telegram.org/bot123456:SECRET_TELEGRAM_FIXTURE/sendMessage";
}

static class Program {
	static int Main(string[] args) {
		if (args.Length == 2 && args[0] == "--inspect-samples") return SampleValidation.Inspect(args[1]);
		using var module = ModuleDefMD.Load(typeof(HarmlessFixture).Assembly.Location);
		var coordinator = new SecurityCoordinator(new ISecurityAnalyzer[] { new ApiAnalyzer(), new StringIocAnalyzer(), new BehaviorAnalyzer() });
		var result = coordinator.Analyze(module, CancellationToken.None);
		var expected = new[] { "API001", "API002", "NET002", "NETW001", "PERS001" };
		foreach (var id in expected) {
			if (result.Findings.All(f => f.RuleId != id)) {
				Console.Error.WriteLine("Missing finding: " + id);
				return 1;
			}
		}
		if (result.Iocs.All(i => i.Value != "https://example.org/static-test")) return 2;
		var versionNumber = string.Join(".", new[] { 120, 0, 0, 0 });
		if (result.Iocs.Any(i => i.Kind.Contains("IPv4") && i.Value == versionNumber)) { Console.Error.WriteLine("User-Agent version became an IP IOC"); return 13; }
		if (result.Iocs.Any(i => i.Value.Contains("SECRET_TOKEN_FIXTURE", StringComparison.Ordinal))) { Console.Error.WriteLine("Webhook token leaked into IOC"); return 14; }
		if (result.Iocs.Any(i => i.Value.Contains("SECRET_SLACK_FIXTURE", StringComparison.Ordinal) || i.Value.Contains("SECRET_TELEGRAM_FIXTURE", StringComparison.Ordinal))) return 17;
		using var report = JsonDocument.Parse(SecurityReportWriter.Write(result, 2));
		if (report.RootElement.GetProperty("findings").GetArrayLength() != result.Findings.Count) return 3;
		if (SecurityReportWriter.Write(result, 2).Contains("SECRET_TOKEN_FIXTURE", StringComparison.Ordinal)) { Console.Error.WriteLine("Webhook token leaked into report"); return 15; }
		var hostilePath = Path.Combine(AppContext.BaseDirectory, "HostileFixture.dll");
		if (!File.Exists(hostilePath)) { Console.Error.WriteLine("Missing static-only fixture: " + hostilePath); return 4; }
		using var hostile = ModuleDefMD.Load(hostilePath);
		var hostileResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new HashAnalyzer(), new PeAnalyzer(), new ResourceAnalyzer(), new ConfigurationAnalyzer(),
			new HiddenContentAnalyzer(), new ApiAnalyzer(), new StringIocAnalyzer(), new BehaviorAnalyzer(), new BehaviorChainAnalyzer(), new TargetedBehaviorAnalyzer() }).Analyze(hostile, CancellationToken.None);
		if (hostileResult.Findings.All(f => f.RuleId != "INIT001")) return 5;
		if (hostileResult.Findings.Any(f => f.RuleId == "RES001")) return 6;
		if (hostileResult.Resources.Count < 4) return 7;
		if (hostileResult.Findings.All(f => f.RuleId != "CONF001")) return 11;
		var synthetic = new ModuleDefUser("SyntheticResources");
		var tinyPe = new byte[68];
		tinyPe[0] = (byte)'M'; tinyPe[1] = (byte)'Z';
		BitConverter.GetBytes(64).CopyTo(tinyPe, 0x3C);
		tinyPe[64] = (byte)'P'; tinyPe[65] = (byte)'E';
		synthetic.Resources.Add(new EmbeddedResource("valid-pe.bin", tinyPe, dnlib.DotNet.ManifestResourceAttributes.Private));
		var resourceResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new ResourceAnalyzer() }).Analyze(synthetic, CancellationToken.None);
		if (resourceResult.Findings.All(f => f.RuleId != "RES001")) return 18;
		var archivePath = Path.GetTempFileName();
		try {
			File.WriteAllBytes(archivePath, MakeTinyCArchive());
			var archiveResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new PyInstallerAnalyzer() }).Analyze(archivePath, null, CancellationToken.None);
			if (archiveResult.PyInstallerEntries.Count != 1 || archiveResult.Findings.All(f => f.RuleId != "PYI001")) return 8;
			var malformed = MakeTinyCArchive();
			// Corrupt archive length. The parser must return an analysis error, not throw to the caller.
			malformed[malformed.Length - 80] = 0x7F;
			File.WriteAllBytes(archivePath, malformed);
			var malformedResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new PyInstallerAnalyzer() }).Analyze(archivePath, null, CancellationToken.None);
			if (malformedResult.AnalysisErrors.Count == 0) return 9;
			File.WriteAllBytes(archivePath, MakeCompressedCArchive());
			var compressedResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new PyInstallerAnalyzer() }).Analyze(archivePath, null, CancellationToken.None);
			if (compressedResult.Findings.All(f => f.RuleId != "PYI002") || compressedResult.Iocs.All(i => i.Value != "https://example.org/static")) return 10;
			File.WriteAllBytes(archivePath, MakePyzCArchive());
			var pyzResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new PyInstallerAnalyzer() }).Analyze(archivePath, null, CancellationToken.None);
			if (pyzResult.PyInstallerEntries.All(e => e.Name != "PYZ-00.pyz/module")) return 12;
			var badPe = new byte[64];
			badPe[0] = (byte)'M'; badPe[1] = (byte)'Z';
			BitConverter.GetBytes(uint.MaxValue).CopyTo(badPe, 0x3C);
			File.WriteAllBytes(archivePath, badPe);
			var badPeResult = new SecurityCoordinator(new ISecurityAnalyzer[] { new PeAnalyzer() }).Analyze(archivePath, null, CancellationToken.None);
			if (badPeResult.AnalysisErrors.Count == 0) return 16;
		} finally { File.Delete(archivePath); }
		HiddenContentTests.Run();
		ExtensionCompatibilityTests.Run();
		Console.WriteLine("Security analysis fixture passed: " + result.Findings.Count + " findings; hidden-content and behavior regressions passed");
		MlvScanTests.Run(args);
		return 0;
	}

	static byte[] MakeTinyCArchive() {
		var data = new byte[16 + 4 + 32 + 88];
		data[0] = (byte)'M'; data[1] = (byte)'Z';
		data[16] = (byte)'P'; data[17] = (byte)'Y'; data[18] = (byte)'Z';
		var toc = 20;
		WriteBe32(data, toc, 32);
		WriteBe32(data, toc + 4, 0);
		WriteBe32(data, toc + 8, 4);
		WriteBe32(data, toc + 12, 4);
		data[toc + 16] = 0;
		data[toc + 17] = (byte)'z';
		System.Text.Encoding.ASCII.GetBytes("PYZ-00.pyz").CopyTo(data, toc + 18);
		var cookie = 52;
		new byte[] { (byte)'M', (byte)'E', (byte)'I', 12, 11, 10, 11, 14 }.CopyTo(data, cookie);
		WriteBe32(data, cookie + 8, 124);
		WriteBe32(data, cookie + 12, 4);
		WriteBe32(data, cookie + 16, 32);
		WriteBe32(data, cookie + 20, 311);
		System.Text.Encoding.ASCII.GetBytes("python311.dll").CopyTo(data, cookie + 24);
		return data;
	}

	static byte[] MakeCompressedCArchive() {
		var plain = System.Text.Encoding.ASCII.GetBytes("inject_discord_desktop https://example.org/static");
		byte[] compressed;
		using (var output = new MemoryStream()) {
			using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, true)) zlib.Write(plain, 0, plain.Length);
			compressed = output.ToArray();
		}
		var cookie = 16 + compressed.Length + 32;
		var data = new byte[cookie + 88];
		data[0] = (byte)'M'; data[1] = (byte)'Z';
		compressed.CopyTo(data, 16);
		var toc = 16 + compressed.Length;
		WriteBe32(data, toc, 32);
		WriteBe32(data, toc + 4, 0);
		WriteBe32(data, toc + 8, (uint)compressed.Length);
		WriteBe32(data, toc + 12, (uint)plain.Length);
		data[toc + 16] = 1;
		data[toc + 17] = (byte)'s';
		System.Text.Encoding.ASCII.GetBytes("main").CopyTo(data, toc + 18);
		new byte[] { (byte)'M', (byte)'E', (byte)'I', 12, 11, 10, 11, 14 }.CopyTo(data, cookie);
		WriteBe32(data, cookie + 8, (uint)(compressed.Length + 32 + 88));
		WriteBe32(data, cookie + 12, (uint)compressed.Length);
		WriteBe32(data, cookie + 16, 32);
		WriteBe32(data, cookie + 20, 311);
		System.Text.Encoding.ASCII.GetBytes("python311.dll").CopyTo(data, cookie + 24);
		return data;
	}

	static byte[] MakePyzCArchive() {
		using var marshalled = new MemoryStream();
		using (var writer = new BinaryWriter(marshalled, System.Text.Encoding.ASCII, true)) {
			writer.Write((byte)0xDB); writer.Write(1);
			writer.Write((byte)0xA9); writer.Write((byte)2);
			writer.Write((byte)0xFA); writer.Write((byte)6); writer.Write(System.Text.Encoding.ASCII.GetBytes("module"));
			writer.Write((byte)0xA9); writer.Write((byte)3);
			writer.Write((byte)0xE9); writer.Write(0);
			writer.Write((byte)0xE9); writer.Write(12);
			writer.Write((byte)0xE9); writer.Write(0);
		}
		var pyz = new byte[12 + marshalled.Length];
		pyz[0] = (byte)'P'; pyz[1] = (byte)'Y'; pyz[2] = (byte)'Z';
		WriteBe32(pyz, 8, 12);
		marshalled.ToArray().CopyTo(pyz, 12);
		var cookie = 16 + pyz.Length + 32;
		var data = new byte[cookie + 88];
		data[0] = (byte)'M'; data[1] = (byte)'Z';
		pyz.CopyTo(data, 16);
		var toc = 16 + pyz.Length;
		WriteBe32(data, toc, 32);
		WriteBe32(data, toc + 8, (uint)pyz.Length);
		WriteBe32(data, toc + 12, (uint)pyz.Length);
		data[toc + 17] = (byte)'z';
		System.Text.Encoding.ASCII.GetBytes("PYZ-00.pyz").CopyTo(data, toc + 18);
		new byte[] { (byte)'M', (byte)'E', (byte)'I', 12, 11, 10, 11, 14 }.CopyTo(data, cookie);
		WriteBe32(data, cookie + 8, (uint)(pyz.Length + 32 + 88));
		WriteBe32(data, cookie + 12, (uint)pyz.Length);
		WriteBe32(data, cookie + 16, 32);
		WriteBe32(data, cookie + 20, 311);
		System.Text.Encoding.ASCII.GetBytes("python311.dll").CopyTo(data, cookie + 24);
		return data;
	}

	static void WriteBe32(byte[] data, int offset, uint value) {
		data[offset] = (byte)(value >> 24);
		data[offset + 1] = (byte)(value >> 16);
		data[offset + 2] = (byte)(value >> 8);
		data[offset + 3] = (byte)value;
	}
}
