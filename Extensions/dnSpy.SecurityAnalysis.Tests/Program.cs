using System;
using System.Linq;
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
}

static class Program {
	static int Main() {
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
		using var report = JsonDocument.Parse(SecurityReportWriter.Write(result, 2));
		if (report.RootElement.GetProperty("findings").GetArrayLength() != result.Findings.Count) return 3;
		Console.WriteLine("Security analysis fixture passed: " + result.Findings.Count + " findings");
		return 0;
	}
}
