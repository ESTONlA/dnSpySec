using System.Text;

namespace dnSpy.SecurityAnalysis {
	public static class SecurityPackageReportWriter {
		public static string Write(SecurityPackageResult result) {
			var text = new StringBuilder();
			text.AppendLine("MOD PACKAGE STATIC ANALYSIS");
			text.AppendLine(result.FileName);
			text.AppendLine("Package SHA-256: " + result.Sha256);
			text.AppendLine(SecurityReportWriter.StaticDisclaimer);
			text.AppendLine("ZIP entries were inspected in memory. No DLL, script, or extracted asset was executed or automatically opened.");
			text.AppendLine();
			text.AppendLine("ENTRIES");
			foreach (var entry in result.Entries) {
				text.AppendLine(entry.Name + " | " + entry.Kind + " | " + entry.Size + " bytes | SHA-256 " + entry.Sha256);
				text.AppendLine("  " + entry.Details);
			}
			text.AppendLine();
			text.AppendLine("DLL / SCRIPT FINDINGS");
			foreach (var finding in result.Findings)
				text.AppendLine(finding.Entry + " | " + finding.Severity + " | " + finding.Rule + " " + finding.Title + " | " + finding.Method + " | " + finding.Evidence);
			text.AppendLine();
			text.AppendLine("STATIC RELATIONSHIPS");
			foreach (var reference in result.References)
				text.AppendLine(reference.Source + " -> " + reference.Target + " | " + reference.Kind + " | " + reference.Location);
			text.AppendLine();
			text.AppendLine("LIMITS / ERRORS");
			foreach (var error in result.Errors) text.AppendLine(error);
			return SecurityText.Redact(text.ToString());
		}
	}
}
