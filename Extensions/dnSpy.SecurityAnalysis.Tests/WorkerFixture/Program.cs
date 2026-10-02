using System;
using System.IO;
using System.Threading;
using System.Security.Cryptography;
using System.Text.Json;

// Host lifecycle tests only: no target parsing. Deep requests block; standard requests overflow.
using var input = new BinaryReader(Console.OpenStandardInput());
input.ReadInt32();
var block = input.ReadBoolean();
var bytes = input.ReadBytes(input.ReadInt32());
if (bytes.Length >= 8 && System.Text.Encoding.ASCII.GetString(bytes, bytes.Length - 8, 7) == "MLVTEST") {
	var mode = bytes[bytes.Length - 1];
	var secret = "https://discord.com/api/webhooks/123456789012345678/SECRET_PACKAGE_TEST";
	object[] findings = mode == 1 ? Array.Empty<object>() : new object[] { new { id = "fixture-id", ruleId = "FixtureRule", severity = "Critical", visibility = "Advanced", description = secret,
		codeSnippet = mode == 4 ? new string('x', 3 * 1024 * 1024) : secret, location = "Fixtures.Plugin.Run:0" } };
	Console.Write(JsonSerializer.Serialize(new { protocolVersion = 2, result = new {
		schemaVersion = "1.4.0", input = new { sha256Hash = mode == 3 ? "wrong" : Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() },
		metadata = new { coreVersion = "fixture", scanMode = block ? "deep" : "standard" },
		disposition = new { classification = "KnownThreat", relatedFindingIds = Array.Empty<string>() },
		analysisCompleteness = new { isComplete = mode != 2, status = mode == 2 ? "Partial" : "Complete" }, findings
	} }));
}
else if (block) Thread.Sleep(Timeout.Infinite);
else {
	using var output = Console.OpenStandardOutput();
	var chunk = new byte[8192];
	for (int i = 0; i < 5000; i++) output.Write(chunk, 0, chunk.Length);
}
