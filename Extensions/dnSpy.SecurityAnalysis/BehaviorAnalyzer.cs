using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	public sealed class BehaviorAnalyzer : ISecurityAnalyzer {
		public string Name => "Behavior correlations";
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					context.CancellationToken.ThrowIfCancellationRequested();
					if (type.IsGlobalModuleType && method.IsStaticConstructor)
						result.Findings.Add(SecurityFindings.Create(context, "INIT001", "Module initializer", "Module initializer",
							"This method runs during module initialization. Review its body and callees.", method.FullName,
							SecuritySeverity.Info, SecurityConfidence.Confirmed, method));
					if (!method.HasBody) continue;
					var calls = method.Body.Instructions.Where(i => (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt) && i.Operand is IMethod)
						.Select(i => ((IMethod)i.Operand).DeclaringType?.FullName + "::" + ((IMethod)i.Operand).Name).ToArray();
					var nativeCalls = method.Body.Instructions.Where(i => (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt) && i.Operand is IMethod)
						.Select(i => ((IMethod)i.Operand).ResolveMethodDef())
						.Where(m => m?.IsPinvokeImpl == true && m.Module == context.Module && m.ImplMap is not null)
						.Select(m => m!.ImplMap.Name.String).ToArray();
					if (!nativeCalls.Any(n => n.StartsWith("GetCurrentProcess", StringComparison.OrdinalIgnoreCase)) &&
						nativeCalls.Any(n => n.StartsWith("OpenProcess", StringComparison.OrdinalIgnoreCase)) &&
						nativeCalls.Any(n => n.StartsWith("VirtualAllocEx", StringComparison.OrdinalIgnoreCase)) &&
						nativeCalls.Any(n => n.StartsWith("WriteProcessMemory", StringComparison.OrdinalIgnoreCase)) &&
						nativeCalls.Any(n => n.StartsWith("CreateRemoteThread", StringComparison.OrdinalIgnoreCase)))
						result.Findings.Add(SecurityFindings.Create(context, "PROC001", "Process / Thread Activity", "Remote process manipulation pattern",
							"This method calls four related native APIs. Static call proximity does not establish argument flow or runtime behavior.",
							string.Join(", ", nativeCalls.Distinct()), SecuritySeverity.High, SecurityConfidence.Medium, method));
					var base64 = calls.Contains("System.Convert::FromBase64String");
					var load = calls.Contains("System.Reflection.Assembly::Load");
					if (base64 && load)
						result.Findings.Add(SecurityFindings.Create(context, "NET002", "Dynamic Loading", "Possible Base64 assembly loader",
							"The same method calls Base64 decoding and Assembly.Load. Static proximity does not prove the decoded bytes reach the load call.",
							"Convert.FromBase64String + Assembly.Load in " + method.FullName, SecuritySeverity.Medium, SecurityConfidence.Medium, method));
					if (load && calls.Any(c => c == "System.Type::GetType") && calls.Any(c => c?.EndsWith("::Invoke", StringComparison.Ordinal) == true))
						result.Findings.Add(SecurityFindings.Create(context, "REF001", "Reflection", "Reflection-heavy load method",
							"This method combines assembly loading, type lookup, and reflection invocation. Review data flow and targets.",
							method.FullName, SecuritySeverity.Medium, SecurityConfidence.Medium, method));
				}
			}
		}
}
}
