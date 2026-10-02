using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	// Compares metadata and structured results. Neither module is loaded by the CLR.
	public static class SecurityVersionComparer {
		static readonly string[] RelevantCalls = { "Process::Start", "CreateProcess", "ShellExecute", "Assembly::Load", "DownloadFile", "DownloadData", "HttpClient::", "WebRequest::", "WriteAllBytes", "File::Copy", "Registry", "TaskScheduler", "PowerShell", "MethodInfo::Invoke", "MethodBase::Invoke" };
		public static SecurityVersionComparison Compare(ModuleDef currentModule, SecurityResult current, ModuleDef baselineModule, SecurityResult baseline, CancellationToken token) {
			var comparison = new SecurityVersionComparison { BaselineFile = baseline.FileName, BaselineSha256 = baseline.Sha256, CurrentSha256 = current.Sha256 };
			var oldCalls = Calls(baselineModule, token);
			var currentCalls = Calls(currentModule, token);
			var oldIocs = new HashSet<string>(baseline.Iocs.Select(i => i.Kind + "\0" + i.Value), StringComparer.Ordinal);
			foreach (var ioc in current.Iocs.Where(i => i.Kind != "MD5" && i.Kind != "SHA-1" && i.Kind != "SHA-256")) {
				token.ThrowIfCancellationRequested();
				if (!oldIocs.Contains(ioc.Kind + "\0" + ioc.Value)) Add("New IOC", ioc.Kind + ": " + ioc.Value, ioc.Source, ioc.Reference);
			}
			var oldResources = new HashSet<string>(baseline.Resources.Select(r => r.Name + "\0" + r.Sha256), StringComparer.Ordinal);
			foreach (var resource in current.Resources) {
				token.ThrowIfCancellationRequested();
				if (!oldResources.Contains(resource.Name + "\0" + resource.Sha256)) Add("New or changed resource", resource.Name + " | SHA-256 " + resource.Sha256, resource.Kind, null);
			}
			var oldHidden = new HashSet<string>(baseline.HiddenContents.Select(h => h.Sha256 + "\0" + h.Kind), StringComparer.Ordinal);
			foreach (var hidden in current.HiddenContents) {
				token.ThrowIfCancellationRequested();
				if (!oldHidden.Contains(hidden.Sha256 + "\0" + hidden.Kind)) Add("New recovered content", hidden.Kind + " | SHA-256 " + hidden.Sha256, hidden.Source, hidden.NavigationReference);
			}
			var oldFindings = new HashSet<string>(baseline.Findings.Where(f => f.Engine == "dnSpy").Select(f => f.RuleId + "\0" + f.Title + "\0" + f.Method), StringComparer.Ordinal);
			foreach (var finding in current.Findings.Where(f => f.Engine == "dnSpy")) {
				token.ThrowIfCancellationRequested();
				if (!oldFindings.Contains(finding.RuleId + "\0" + finding.Title + "\0" + finding.Method)) Add("New finding", finding.RuleId + ": " + finding.Title, finding.Method, finding.Reference);
			}
			foreach (var pair in currentCalls) {
				token.ThrowIfCancellationRequested();
				if (!oldCalls.ContainsKey(pair.Key)) Add("New API reference", pair.Key, pair.Value.FullName, pair.Value);
			}
			return comparison;

			void Add(string kind, string value, string source, object? reference) {
				if (comparison.Changes.Count >= 512) return;
				comparison.Changes.Add(new SecurityVersionChange { Kind = kind, Value = Short(SecurityText.Redact(value)), Source = Short(SecurityText.Redact(source)), Reference = reference });
			}
		}

		static Dictionary<string, MethodDef> Calls(ModuleDef module, CancellationToken token) {
			var result = new Dictionary<string, MethodDef>(StringComparer.Ordinal);
			int methods = 0, instructions = 0;
			foreach (var type in module.GetTypes()) foreach (var method in type.Methods) {
				token.ThrowIfCancellationRequested();
				if (++methods > AnalysisLimits.MaximumBehaviorMethods) throw new InvalidOperationException("Version comparison method limit reached.");
				if (!method.HasBody) continue;
				foreach (var instruction in method.Body.Instructions) {
					if (++instructions > AnalysisLimits.MaximumBehaviorInstructions) throw new InvalidOperationException("Version comparison IL limit reached.");
					if (instruction.OpCode.Code != Code.Call && instruction.OpCode.Code != Code.Callvirt && instruction.OpCode.Code != Code.Newobj && instruction.OpCode.Code != Code.Ldftn) continue;
					if (instruction.Operand is not IMethod target) continue;
					var label = target.DeclaringType?.FullName + "::" + target.Name;
					if (!RelevantCalls.Any(term => label.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)) continue;
					result[Short(method.FullName + " -> " + label)] = method;
				}
			}
			return result;
		}
		static string Short(string text) => text.Length <= 1024 ? text : text.Substring(0, 1024) + " [truncated]";
	}
}
