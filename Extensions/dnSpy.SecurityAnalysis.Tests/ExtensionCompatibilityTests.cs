using System;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnSpy.SecurityAnalysis;
using dnSpy.StaticAnalysis;

static class ExtensionCompatibilityTests {
	public static void Run() {
		// Read the trusted build's extension metadata using dnlib, mirroring the host's
		// signed-reference version gate without invoking private host methods or UI code.
		var contractsPath = Path.Combine(AppContext.BaseDirectory, "dnSpy.Contracts.DnSpy.dll");
		using var contracts = ModuleDefMD.Load(contractsPath);
		var token = contracts.Assembly.PublicKeyToken.ToString();
		foreach (var (path, command, provider) in new[] {
			(typeof(SecurityCoordinator).Assembly.Location, "SecurityAnalysisCommand", "SecurityWindowProvider"),
			(typeof(StaticAnalysisCoordinator).Assembly.Location, "StaticAnalysisCommand", "StaticWindowProvider") }) {
			using var extension = ModuleDefMD.Load(path);
			if (extension.Assembly.Version != contracts.Assembly.Version) throw new InvalidOperationException("Extension version does not match host contracts.");
			foreach (var reference in extension.GetAssemblyRefs()) {
				if (reference.PublicKeyOrToken?.Token?.ToString() == token && reference.Version < new Version(5, 0, 0, 0))
					throw new InvalidOperationException("Host would reject signed dependency: " + reference.FullName);
			}
			var commandType = extension.GetTypes().Single(t => t.Name == command);
			if (!commandType.CustomAttributes.Any(a => a.TypeFullName == "dnSpy.Contracts.Menus.ExportMenuItemAttribute")) throw new InvalidOperationException("Analysis menu command export missing.");
			var providerType = extension.GetTypes().Single(t => t.Name == provider);
			if (!providerType.CustomAttributes.Any(a => a.TypeFullName == "System.ComponentModel.Composition.ExportAttribute")) throw new InvalidOperationException("Analysis tool-window export missing.");
		}
	}
}
