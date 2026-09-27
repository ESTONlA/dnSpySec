using System;
using System.Linq;
using System.Text;

namespace dnSpy.SecurityAnalysis {
	public static class SecurityReportWriter {
		public const string StaticDisclaimer = "Static analysis only. The sample was not executed and no discovered network endpoint was contacted. Static analysis establishes code and indicators present in the file, but cannot prove that every runtime capability successfully executes on a particular system.";
		public static string Write(SecurityResult result, int format) => format == 2 ? Json(result) : Text(result, format == 1);
		public static string WriteIocs(SecurityResult result, int format) {
			var iocs = result.Iocs.GroupBy(i => i.Kind + "\0" + i.Value).Select(g => g.First()).ToArray();
			if (format == 2) {
				var output = new StringBuilder("[\n");
				for (int index = 0; index < iocs.Length; index++) {
					if (index != 0) output.Append(",\n");
					var i = iocs[index];
					output.Append("  {\"type\":").Append(Q(i.Kind)).Append(",\"value\":").Append(Q(i.Value));
					output.Append(",\"source\":").Append(Q(i.Source)).Append(",\"method\":").Append(Q(i.Method));
					output.Append(",\"confidence\":").Append(Q(i.Confidence.ToString())).Append(",\"findingId\":").Append(Q(i.FindingId)).Append('}');
				}
				return output.Append("\n]").ToString();
			}
			var lines = iocs.Select(i => (format == 1 ? "- " : "") + i.Kind + ": " + i.Value + " | " + i.Source + " | " + i.Method);
			return format == 1 ? "# Extracted IOCs\n\n" + string.Join("\n", lines) : string.Join(Environment.NewLine, lines);
		}

		static string Text(SecurityResult result, bool markdown) {
			var output = new StringBuilder();
			var heading = markdown ? "# " : "";
			output.AppendLine(heading + "Security Analysis");
			output.AppendLine();
			output.AppendLine(StaticDisclaimer);
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "File information");
			output.AppendLine("File: " + result.FileName);
			output.AppendLine("Path: " + result.FullPath);
			output.AppendLine("Size: " + result.FileSize);
			output.AppendLine("Assembly: " + result.AssemblyName);
			output.AppendLine("Module: " + result.ModuleName);
			output.AppendLine("CLR: " + result.RuntimeVersion);
			output.AppendLine("MD5: " + result.Md5);
			output.AppendLine("SHA-1: " + result.Sha1);
			output.AppendLine("SHA-256: " + result.Sha256);
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "PE / CLR information");
			output.AppendLine(result.PeInformation);
			output.AppendLine((markdown ? "## " : "") + "PyInstaller");
			output.AppendLine(result.PyInstallerInformation);
			foreach (var entry in result.PyInstallerEntries) output.AppendLine(entry.Name + " | " + entry.Type + " | " + entry.Size + " bytes");
			output.AppendLine((markdown ? "## " : "") + "Hidden configuration");
			output.AppendLine(result.ConfigurationInformation);
			output.AppendLine((markdown ? "## " : "") + "Summary");
			foreach (SecuritySeverity severity in Enum.GetValues(typeof(SecuritySeverity)))
				output.AppendLine(severity + ": " + result.Findings.Count(f => f.Severity == severity));
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "Confirmed observations");
			foreach (var finding in result.Findings.Where(f => f.Confidence == SecurityConfidence.Confirmed)) output.AppendLine(finding.RuleId + ": " + finding.Title);
			output.AppendLine((markdown ? "## " : "") + "Strong indicators");
			foreach (var finding in result.Findings.Where(f => f.Severity >= SecuritySeverity.Medium && f.EvidenceItems.Count >= 2)) output.AppendLine(finding.RuleId + ": " + finding.Title);
			output.AppendLine((markdown ? "## " : "") + "Inferences");
			foreach (var finding in result.Findings.Where(f => f.Confidence == SecurityConfidence.Medium || f.Confidence == SecurityConfidence.Low)) output.AppendLine(finding.RuleId + ": " + finding.Explanation);
			output.AppendLine((markdown ? "## " : "") + "Not established");
			output.AppendLine("Runtime execution, successful persistence, successful elevation, endpoint contact, and proven data flow are not established by this static analysis.");
			foreach (var item in NotEstablished(result)) output.AppendLine(item);
			foreach (var severity in new[] { SecuritySeverity.High, SecuritySeverity.Medium, SecuritySeverity.Low, SecuritySeverity.Info }) {
				output.AppendLine();
				output.AppendLine((markdown ? "## " : "") + severity + " findings");
				foreach (var finding in result.Findings.Where(f => f.Severity == severity)) {
					output.AppendLine((markdown ? "### " : "") + finding.RuleId + " " + finding.Title + " (" + finding.Confidence + ")");
					output.AppendLine("Category: " + finding.Category);
					output.AppendLine("Observation: " + finding.Explanation);
					output.AppendLine("Evidence: " + finding.Evidence);
					output.AppendLine("Location: " + finding.Method + (finding.IlOffset is null ? "" : " IL_" + finding.IlOffset.Value.ToString("X4")));
					output.AppendLine("Token: " + (finding.MetadataToken is null ? "" : "0x" + finding.MetadataToken.Value.ToString("X8")));
					foreach (var evidence in finding.EvidenceItems) output.AppendLine("  - " + evidence.Description + ": " + evidence.Value + " | " + evidence.Method + (evidence.IlOffset is null ? "" : " IL_" + evidence.IlOffset.Value.ToString("X4")));
				}
			}
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "Extracted IOCs");
			foreach (var ioc in result.Iocs.GroupBy(i => i.Kind + "\0" + i.Value).Select(g => g.First())) output.AppendLine(ioc.Kind + ": " + ioc.Value + " " + ioc.Details);
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "Embedded resources");
			foreach (var resource in result.Resources) output.AppendLine(resource.Name + " | " + resource.Kind + " | " + resource.Size + " bytes | SHA-256 " + resource.Sha256);
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "Analysis limits and errors");
			foreach (var error in result.AnalysisErrors) output.AppendLine(error);
			return SecurityText.Redact(output.ToString());
		}

		static string Json(SecurityResult result) {
			var output = new StringBuilder();
			output.Append("{\"file\":").Append(Q(result.FileName)).Append(",\"path\":").Append(Q(result.FullPath));
			output.Append(",\"size\":").Append(result.FileSize?.ToString() ?? "null");
			output.Append(",\"assembly\":").Append(Q(result.AssemblyName)).Append(",\"module\":").Append(Q(result.ModuleName));
			output.Append(",\"clr\":").Append(Q(result.RuntimeVersion)).Append(",\"md5\":").Append(Q(result.Md5));
			output.Append(",\"sha1\":").Append(Q(result.Sha1)).Append(",\"sha256\":").Append(Q(result.Sha256));
			output.Append(",\"peInformation\":").Append(Q(result.PeInformation));
			output.Append(",\"staticAnalysisDisclaimer\":").Append(Q(StaticDisclaimer));
			output.Append(",\"pyInstallerInformation\":").Append(Q(result.PyInstallerInformation));
			output.Append(",\"configurationInformation\":").Append(Q(result.ConfigurationInformation));
			output.Append(",\"overlayOffset\":").Append(result.OverlayOffset?.ToString() ?? "null");
			output.Append(",\"overlaySize\":").Append(result.OverlaySize?.ToString() ?? "null");
			output.Append(",\"overlayFormat\":").Append(Q(result.OverlayFormat));
			output.Append(",\"notEstablished\":[");
			var absent = NotEstablished(result);
			for (int index = 0; index < absent.Length; index++) { if (index != 0) output.Append(','); output.Append(Q(absent[index])); }
			output.Append(']');
			output.Append(",\"findings\":[");
			bool first = true;
			foreach (var f in result.Findings) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"ruleId\":").Append(Q(f.RuleId)).Append(",\"severity\":").Append(Q(f.Severity.ToString()));
				output.Append(",\"confidence\":").Append(Q(f.Confidence.ToString())).Append(",\"category\":").Append(Q(f.Category));
				output.Append(",\"title\":").Append(Q(f.Title)).Append(",\"explanation\":").Append(Q(f.Explanation));
				output.Append(",\"evidence\":").Append(Q(f.Evidence)).Append(",\"method\":").Append(Q(f.Method));
				output.Append(",\"classification\":").Append(Q(f.Confidence == SecurityConfidence.Confirmed ? "Confirmed observation" : f.EvidenceItems.Count >= 2 && f.Severity >= SecuritySeverity.Medium ? "Strong indicator" : "Inference"));
				output.Append(",\"token\":").Append(f.MetadataToken?.ToString() ?? "null");
				output.Append(",\"ilOffset\":").Append(f.IlOffset?.ToString() ?? "null");
				output.Append(",\"evidenceItems\":[");
				bool firstEvidence = true;
				foreach (var item in f.EvidenceItems) {
					if (!firstEvidence) output.Append(','); firstEvidence = false;
					output.Append("{\"description\":").Append(Q(item.Description)).Append(",\"value\":").Append(Q(item.Value));
					output.Append(",\"method\":").Append(Q(item.Method)).Append(",\"ilOffset\":").Append(item.IlOffset?.ToString() ?? "null").Append('}');
				}
				output.Append("]}");
			}
			output.Append("],\"iocs\":["); first = true;
			foreach (var i in result.Iocs) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"kind\":").Append(Q(i.Kind)).Append(",\"value\":").Append(Q(i.Value)).Append(",\"details\":").Append(Q(i.Details));
				output.Append(",\"source\":").Append(Q(i.Source)).Append(",\"method\":").Append(Q(i.Method)).Append(",\"findingId\":").Append(Q(i.FindingId)).Append('}');
			}
			output.Append("],\"resources\":["); first = true;
			foreach (var r in result.Resources) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"name\":").Append(Q(r.Name)).Append(",\"kind\":").Append(Q(r.Kind));
				output.Append(",\"size\":").Append(r.Size).Append(",\"sha256\":").Append(Q(r.Sha256));
				output.Append(",\"entropy\":").Append(r.Entropy.ToString("R", System.Globalization.CultureInfo.InvariantCulture)).Append('}');
			}
			output.Append("],\"pyInstallerEntries\":["); first = true;
			foreach (var entry in result.PyInstallerEntries) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"name\":").Append(Q(entry.Name)).Append(",\"type\":").Append(Q(entry.Type));
				output.Append(",\"offset\":").Append(entry.Offset).Append(",\"size\":").Append(entry.Size).Append('}');
			}
			output.Append("],\"analysisErrors\":["); first = true;
			foreach (var error in result.AnalysisErrors) { if (!first) output.Append(','); first = false; output.Append(Q(error)); }
			return output.Append("]}").ToString();
		}

		static string[] NotEstablished(SecurityResult result) {
			var items = new System.Collections.Generic.List<string>();
			if (result.ModuleName.Length == 0 || result.AnalysisErrors.Count != 0) return items.ToArray();
			if (!result.Findings.Any(f => f.RuleId == "PROC001")) items.Add("The four-API remote process manipulation pattern was not found by PROC001.");
			if (!result.Findings.Any(f => f.RuleId == "CHAIN004")) items.Add("The Chromium database + password_value + DPAPI pattern was not found by CHAIN004.");
			if (!result.Findings.Any(f => f.RuleId == "CHAIN003")) items.Add("The download + Unblock-File + launch co-occurrence was not found by CHAIN003.");
			return items.ToArray();
		}

		static string Q(string? value) {
			var output = new StringBuilder("\"");
			foreach (var ch in SecurityText.Redact(value)) {
				switch (ch) {
				case '\\': output.Append("\\\\"); break;
				case '"': output.Append("\\\""); break;
				case '\n': output.Append("\\n"); break;
				case '\r': output.Append("\\r"); break;
				case '\t': output.Append("\\t"); break;
				default: if (ch < 32 || char.IsSurrogate(ch)) output.Append("\\u").Append(((int)ch).ToString("X4")); else output.Append(ch); break;
			}
			}
			return output.Append('"').ToString();
		}
	}
}
