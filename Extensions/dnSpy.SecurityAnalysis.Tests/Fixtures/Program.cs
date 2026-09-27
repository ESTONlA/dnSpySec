using System;
using System.Runtime.CompilerServices;
using System.Reflection;

[assembly: AssemblyMetadata("DownloadUrl", "https://example.net/real")]

static class Program {
	[ModuleInitializer]
	public static void Initialize() => throw new InvalidOperationException("Module initializer was executed");

	static Program() => throw new InvalidOperationException("Static constructor was executed");

	static void Main() => throw new InvalidOperationException("Entry point was executed");

	public static string EmbeddedCommand() => "powershell -ExecutionPolicy Bypass -Command Unblock-File sample.exe";
	public static string ReadConfiguration() => GetMetadata("DownloadUrl", "https://example.net/fallback");
	static string GetMetadata(string key, string fallback) => fallback;
}
