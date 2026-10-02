using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnSpy.SecurityAnalysis;

// All methods inside the ZIP are serialized IL data. None is invoked by this test.
static class PackageTests {
	public static void Run() {
		var archive = Path.Combine(Path.GetTempPath(), "dnspy-package-test-" + Guid.NewGuid().ToString("N") + ".zip");
		var marker = Path.Combine(Path.GetTempPath(), "dnspy-package-no-extract-" + Guid.NewGuid().ToString("N") + ".txt");
		try {
			byte[] dll;
			using (var module = new ModuleDefUser("SyntheticMod.dll")) {
				var assembly = new AssemblyDefUser("SyntheticMod"); assembly.Modules.Add(module);
				var type = new TypeDefUser("Mods", "Plugin", module.CorLibTypes.Object.TypeDefOrRef); module.Types.Add(type);
				var method = new MethodDefUser("ReadData", MethodSig.CreateStatic(module.CorLibTypes.Void), MethodImplAttributes.IL, MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
				var assemblyType = new TypeRefUser(module, "System.Reflection", "Assembly", module.CorLibTypes.AssemblyRef);
				var readResource = new MemberRefUser(module, "GetManifestResourceStream", MethodSig.CreateInstance(module.CorLibTypes.Object, module.CorLibTypes.String), assemblyType);
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "scripts/install.ps1"));
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldnull));
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, "payload.ps1"));
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Callvirt, readResource));
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Pop));
				method.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
				type.Methods.Add(method);
				module.Resources.Add(new EmbeddedResource("payload.ps1", Encoding.UTF8.GetBytes("Write-Output 'fixture only'"), ManifestResourceAttributes.Private));
				using var output = new MemoryStream(); module.Write(output); dll = output.ToArray();
			}
			using (var output = new FileStream(archive, FileMode.CreateNew, FileAccess.Write))
			using (var zip = new ZipArchive(output, ZipArchiveMode.Create)) {
				Add(zip, "SyntheticMod.dll", dll);
				Add(zip, "HostileFixture.dll", File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "HostileFixture.dll")));
				Add(zip, "scripts/install.ps1", Encoding.UTF8.GetBytes("Invoke-WebRequest https://discord.com/api/webhooks/123456789012345678/NO_LEAK_TEST_TOKEN"));
				Add(zip, "config.json", Encoding.UTF8.GetBytes("{\"script\":\"scripts/install.ps1\"}"));
				Add(zip, "../" + Path.GetFileName(marker), Encoding.UTF8.GetBytes("fixture"));
				Add(zip, "oversized.bin", new byte[17 * 1024 * 1024]);
			}
			var scan = new SecurityPackageScanner().Scan(archive, CancellationToken.None);
			if (scan.Entries.All(e => e.Kind != "Managed DLL/EXE")) throw new InvalidOperationException("Managed package entry not parsed.");
			if (scan.Entries.All(e => e.Name != "HostileFixture.dll" || e.Kind != "Managed DLL/EXE")) throw new InvalidOperationException("Throwing-initializer fixture was not inspected as metadata.");
			if (scan.References.All(r => r.Source == "SyntheticMod.dll" ? r.Target != "scripts/install.ps1" : true)) throw new InvalidOperationException("DLL to package-file reference missing.");
			if (scan.References.All(r => r.Target != "SyntheticMod.dll!payload.ps1" || !r.Kind.Contains("GetManifestResourceStream", StringComparison.Ordinal))) throw new InvalidOperationException("Embedded resource consumer missing.");
			if (scan.References.All(r => r.Source != "config.json" || r.Target != "scripts/install.ps1")) throw new InvalidOperationException("Configuration file relationship missing.");
			if (scan.Errors.All(e => !e.Contains("oversized.bin", StringComparison.Ordinal))) throw new InvalidOperationException("Oversized entry was not reported.");
			if (scan.Findings.All(f => f.Rule != "PKG001")) throw new InvalidOperationException("Script indicator was not reported.");
			if (File.Exists(marker)) throw new InvalidOperationException("ZIP traversal entry was extracted.");
			using var canceled = new CancellationTokenSource(); canceled.Cancel();
			try { new SecurityPackageScanner().Scan(archive, canceled.Token); throw new InvalidOperationException("Package cancellation ignored."); }
			catch (OperationCanceledException) { }
			if (!SecurityPackageReportWriter.Write(scan).Contains("STATIC RELATIONSHIPS", StringComparison.Ordinal)) throw new InvalidOperationException("Package report missing relationships.");
			if (SecurityPackageReportWriter.Write(scan).Contains("NO_LEAK_TEST_TOKEN", StringComparison.Ordinal)) throw new InvalidOperationException("Webhook token leaked into package report.");
			File.WriteAllBytes(archive, new byte[] { 1, 2, 3, 4 });
			bool malformed = false;
			try { new SecurityPackageScanner().Scan(archive, CancellationToken.None); }
			catch (InvalidDataException) { malformed = true; }
			if (!malformed) throw new InvalidOperationException("Malformed ZIP was accepted.");
		} finally { if (File.Exists(archive)) File.Delete(archive); }
	}
	static void Add(ZipArchive zip, string name, byte[] bytes) { using var stream = zip.CreateEntry(name).Open(); stream.Write(bytes, 0, bytes.Length); }
}
