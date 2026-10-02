using System.Text.Json;
using System.Text.Json.Serialization;
using dnSpy.SecurityAnalysis;
using MLVScan;
using MLVScan.Abstractions;
using MLVScan.Models;
using MLVScan.Models.Dto;
using MLVScan.Services;
using Mono.Cecil;

try {
	using var input = new BinaryReader(Console.OpenStandardInput());
	if (input.ReadInt32() != MlvScanProtocol.Version) return 2;
	var deep = input.ReadBoolean();
	var length = input.ReadInt32();
	if (length <= 0 || length > MlvScanProtocol.InputLimit(deep)) return 2;
	var bytes = input.ReadBytes(length);
	if (bytes.Length != length) return 2;
	using var stream = new MemoryStream(bytes, writable: false);
	using var resolver = new BundledResolverProvider();
	var scanner = new AssemblyScanner(RuleFactory.CreateDefaultRules(), new ScanConfig {
		DeepScanMode = deep ? DeepScanMode.Always : DeepScanMode.Disabled,
		// Embedded findings do not yet expose reliable module identities for navigation.
		EnableRecursiveResourceScanning = false
	}, resolverProvider: resolver);
	var findings = scanner.Scan(stream, "selected-assembly").ToList();
	if (resolver.MissingReference)
		findings.Add(new ScanFinding("Assembly references", "External assembly metadata was unavailable; manual review is required.", Severity.Low) { RuleId = "HostIncompleteReferences" });
	var result = ScanResultMapper.ToDto(findings, "selected-assembly", bytes, new ScanResultOptions {
		Platform = "desktop", PlatformVersion = "dnSpySec", ScanMode = scanner.LastScanUsedDeepAnalysis ? "deep" : "standard",
		IncludeCallChains = true, IncludeDataFlows = true, IncludeDeveloperGuidance = true
	});
	// Serialize fully before writing: an oversized result must not look like a valid partial DTO.
	using var output = new LimitedStream();
	JsonSerializer.Serialize(output, new { protocolVersion = MlvScanProtocol.Version, result }, new JsonSerializerOptions {
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
	});
	output.Position = 0;
	output.CopyTo(Console.OpenStandardOutput());
	return 0;
}
catch (Exception) {
	// Do not print target-derived exception messages or snippets to stderr.
	Console.Error.WriteLine("MLVScan worker could not complete the request.");
	return 1;
}

sealed class LimitedStream : MemoryStream {
	public override void Write(byte[] buffer, int offset, int count) {
		Check(count); base.Write(buffer, offset, count);
	}
	public override void Write(ReadOnlySpan<byte> buffer) {
		Check(buffer.Length); base.Write(buffer);
	}
	void Check(int count) {
		if (Position + count > MlvScanProtocol.MaximumOutputBytes) throw new InvalidDataException("Result limit reached.");
	}
}

sealed class BundledResolverProvider : IAssemblyResolverProvider, IAssemblyResolver {
	readonly Dictionary<string, string> files = Directory.EnumerateFiles(AppContext.BaseDirectory, "*.dll")
		.ToDictionary(path => Path.GetFileNameWithoutExtension(path), StringComparer.OrdinalIgnoreCase);
	readonly Dictionary<string, AssemblyDefinition> cache = new(StringComparer.Ordinal);
	public bool MissingReference { get; private set; }
	public IAssemblyResolver CreateResolver() => this;
	public AssemblyDefinition Resolve(AssemblyNameReference name) => Resolve(name, new ReaderParameters());
	public AssemblyDefinition Resolve(AssemblyNameReference name, ReaderParameters parameters) {
		if (cache.TryGetValue(name.FullName, out var cached)) return cached;
		if (files.TryGetValue(name.Name, out var path)) {
			var assembly = AssemblyDefinition.ReadAssembly(path, new ReaderParameters { ReadSymbols = false, AssemblyResolver = this });
			if (assembly.Name.FullName == name.FullName) { cache.Add(name.FullName, assembly); return assembly; }
			assembly.Dispose();
		}
		MissingReference = true;
		throw new AssemblyResolutionException(name);
	}
	public void Dispose() { foreach (var assembly in cache.Values) assembly.Dispose(); cache.Clear(); }
}
