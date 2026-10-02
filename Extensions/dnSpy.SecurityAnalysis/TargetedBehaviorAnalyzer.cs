using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	// Only metadata edges are traversed. This does not invoke methods, instantiate
	// attributes, evaluate conditions, or assert that collected arguments flow together.
	public sealed class TargetedBehaviorAnalyzer : ISecurityAnalyzer {
		sealed class Fact {
			public string Value = string.Empty;
			public string Description = string.Empty;
			public MethodDef Method = null!;
			public uint? Offset;
			public object? Reference;
			public bool Text;
			public bool ApiReference;
		}
		sealed class Edge {
			public MethodDef Target = null!;
			public string Kind = string.Empty;
			public uint? Offset;
			public bool Reverse;
		}
		sealed class Node {
			public readonly List<Fact> Facts = new List<Fact>();
			public readonly List<Edge> Edges = new List<Edge>();
		}
		public string Name => "Focused mod behavior and startup paths";
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			var nodes = new Dictionary<MethodDef, Node>();
			int methods = 0, instructions = 0;
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					context.CancellationToken.ThrowIfCancellationRequested();
					if (++methods > AnalysisLimits.MaximumBehaviorMethods) { result.AnalysisErrors.Add("Focused behavior method limit."); return; }
					if (!method.HasBody) continue;
					var node = nodes[method] = new Node();
					try {
						foreach (var instruction in method.Body.Instructions) {
							context.CancellationToken.ThrowIfCancellationRequested();
							if (++instructions > AnalysisLimits.MaximumBehaviorInstructions) { result.AnalysisErrors.Add("Focused behavior IL limit."); return; }
							if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string literal && literal.Length <= AnalysisLimits.MaximumStringLength)
								node.Facts.Add(new Fact { Value = SecurityText.Redact(literal), Description = "IL literal", Text = true, Method = method, Reference = method, Offset = instruction.Offset });
							if (instruction.Operand is not IMethod call) continue;
							if (instruction.OpCode.Code != Code.Call && instruction.OpCode.Code != Code.Callvirt && instruction.OpCode.Code != Code.Newobj && instruction.OpCode.Code != Code.Ldftn && instruction.OpCode.Code != Code.Ldvirtftn) continue;
							var target = LocalMethod(call, context.Module);
							var identity = call.DeclaringType?.FullName + "::" + call.Name;
							if (target?.IsPinvokeImpl == true && target.ImplMap is { } map) identity = "native::" + map.Name;
							node.Facts.Add(new Fact { Value = identity, Description = "Referenced API / method", ApiReference = target?.IsPinvokeImpl == true || FrameworkReference(call), Method = method, Reference = method, Offset = instruction.Offset });
							if (target is not null) node.Edges.Add(new Edge { Target = target, Offset = instruction.Offset, Kind = instruction.OpCode.Code == Code.Ldftn || instruction.OpCode.Code == Code.Ldvirtftn ? "Delegate target reference" : "Direct call reference" });
						}
						foreach (var attribute in method.CustomAttributes) {
							if (attribute.TypeFullName != "System.Runtime.CompilerServices.AsyncStateMachineAttribute" && attribute.TypeFullName != "System.Runtime.CompilerServices.IteratorStateMachineAttribute") continue;
							if (attribute.ConstructorArguments.Count != 1) continue;
							var stateType = attribute.ConstructorArguments[0].Value is TypeDefOrRefSig sig ? sig.TypeDefOrRef as TypeDef : attribute.ConstructorArguments[0].Value as TypeDef;
							if (stateType?.Module != context.Module) continue;
							var moveNext = stateType.Methods.FirstOrDefault(m => m.Name == "MoveNext" && m.HasBody);
							if (moveNext is not null) node.Edges.Add(new Edge { Target = moveNext, Kind = "State-machine metadata reference" });
						}
					} catch (OperationCanceledException) { throw; }
					catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); if (result.AnalysisErrors.Count < 256) result.AnalysisErrors.Add("Focused behavior could not inspect method token 0x" + method.MDToken.Raw.ToString("X8")); }
				}
			}
			foreach (var content in result.HiddenContents) {
				if (content.MethodReference is not MethodDef method || !nodes.TryGetValue(method, out var node)) continue;
				node.Facts.Add(new Fact { Value = content.Preview, Description = content.Transformation + " (" + content.Confidence + "; runtime use not established)", Text = true, Method = method, Reference = content.Reference, Offset = content.IlOffset });
			}
			foreach (var configured in result.Findings.Where(f => f.RuleId == "CONF001")) {
				if (configured.Reference is not MethodDef method || !nodes.TryGetValue(method, out var node)) continue;
				foreach (var evidence in configured.EvidenceItems.Where(e => e.Description == "Configured value")) node.Facts.Add(new Fact { Value = evidence.Value, Description = "Assembly metadata override", Text = true, Method = method, Reference = evidence.Reference, Offset = configured.IlOffset });
			}
			// Incoming metadata references connect a hidden configuration/decryptor to
			// its caller. They are labeled separately and never treated as invocation.
			foreach (var pair in nodes.ToArray()) foreach (var edge in pair.Value.Edges.Where(e => !e.Reverse).ToArray())
				if (nodes.TryGetValue(edge.Target, out var target)) target.Edges.Add(new Edge { Target = pair.Key, Offset = edge.Offset, Kind = "Caller reference: " + edge.Kind, Reverse = true });
			var startupPaths = StartupPaths(context, nodes);
			foreach (var pair in startupPaths) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (result.StartupPaths.Count >= 512) { result.AnalysisErrors.Add("Startup path display limit reached (512 rows)."); break; }
				var facts = nodes[pair.Key].Facts;
				var relevant = facts.Where(f => f.ApiReference && HiddenContentDecoder.Contains(f.Value,
					"Process::Start", "ShellExecute", "CreateProcess", "Download", "HttpClient", "WriteAllBytes", "Assembly::Load", "MethodInfo::Invoke", "MethodBase::Invoke"))
					.Take(3).Select(f => Short(f.Value)).ToArray();
				if (relevant.Length == 0 && !result.HiddenContents.Any(c => c.MethodReference == pair.Key) && !IsStartup(pair.Key)) continue;
				result.StartupPaths.Add(new SecurityStartupPath {
					Root = pair.Value.FirstOrDefault()?.Value ?? pair.Key.FullName,
					Method = Short(pair.Key.FullName),
					Path = Short(string.Join(" -> ", pair.Value.Skip(1).Select(e => e.Value))),
					Evidence = relevant.Length == 0 ? "Initializer or recovered content; runtime execution is not established." : Short(string.Join("; ", relevant)),
					Reference = pair.Key
				});
			}
			foreach (var content in result.HiddenContents) {
				if (content.MethodReference is not MethodDef method || !nodes.TryGetValue(method, out var node) || content.IlOffset is not uint offset) continue;
				content.NearbyReferences = string.Join("; ", node.Facts.Where(f => f.ApiReference && f.Offset is uint nearby && Math.Abs((long)nearby - offset) <= 48)
					.Take(5).Select(f => Short(f.Value)));
			}
			var emitted = new HashSet<string>(StringComparer.Ordinal);
			foreach (var pair in nodes) {
				context.CancellationToken.ThrowIfCancellationRequested();
				// Start at methods with a relevant sink; avoid joining arbitrary module-wide APIs.
				if (!pair.Value.Facts.Any(f => f.ApiReference && HiddenContentDecoder.Contains(f.Value, "Process::Start", "native::ShellExecute", "native::CreateProcess", "native::WinExec", "MethodBase::Invoke", "MethodInfo::Invoke"))) continue;
				bool directLaunch = pair.Value.Facts.Any(f => f.ApiReference && HiddenContentDecoder.Contains(f.Value, "Process::Start", "native::ShellExecute", "native::CreateProcess", "native::WinExec"));
				var reachable = Reachable(pair.Key, nodes, context, 4, 32, !directLaunch);
				var facts = reachable.Keys.SelectMany(m => nodes[m].Facts).ToList();
				Fact? Text(params string[] values) => facts.FirstOrDefault(f => f.Text && HiddenContentDecoder.Contains(f.Value, values));
				Fact? Api(params string[] values) => facts.FirstOrDefault(f => f.ApiReference && HiddenContentDecoder.Contains(f.Value, values));
				var launch = Api("Process::Start", "native::ShellExecute", "native::CreateProcess", "native::WinExec");
				var downloadFile = Api("WebClient::DownloadFile", "native::URLDownloadToFile");
				var download = downloadFile ?? Api("HttpClient::GetByteArray", "HttpClient::GetAsync", "HttpClient::GetStream", "WebClient::DownloadData", "WebClient::DownloadString", "WebRequest::GetResponse");
				var url = facts.FirstOrDefault(f => f.Description == "Assembly metadata override" && HiddenContentDecoder.Contains(f.Value, "https://", "http://")) ?? Text("https://", "http://");
				var write = downloadFile ?? Api("File::WriteAllBytes", "File::WriteAllText", "FileStream::.ctor", "native::WriteFile");
				var unblock = Text("Unblock-File", "Zone.Identifier");
				var bypass = Text("ExecutionPolicy Bypass", "-ep bypass");
				var reflectedInvoke = Api("MethodBase::Invoke", "MethodInfo::Invoke");
				bool downloaderChain = launch is not null && download is not null && write is not null && url is not null;
				if (downloaderChain) {
					var title = unblock is not null ? "Download, remove download restrictions, and launch" : bypass is not null ? "Download and launch through PowerShell policy bypass" : "Download to file followed by a launch reference";
					Emit("MOD001", title, "Downloader", new[] { download, write, url, unblock, bypass, launch }.Where(f => f is not null).Select(f => f!).ToArray());
				}
				var script = facts.FirstOrDefault(f => f.Text && HiddenContentDecoder.Contains(f.Value, "Invoke-WebRequest", "Invoke-RestMethod", "DownloadFile", "DownloadString", "iwr ") && HiddenContentDecoder.Contains(f.Value, "powershell", "Invoke-Web", "Start-Process"));
				var scriptLaunch = Text("Start-Process", "cmd.exe", "powershell.exe");
				var reflectedProcess = Text("System.Diagnostics.Process");
				if (!downloaderChain && script is not null && url is not null && scriptLaunch is not null && (launch is not null || reflectedInvoke is not null && reflectedProcess is not null)) {
					var reflective = launch is null;
					Emit(reflective ? "MOD004" : "MOD002", reflective ? "Encoded process names and downloader command used near reflection" : "Shell command contains download-and-launch logic", "Hidden downloader",
						new[] { script, url, scriptLaunch, launch, reflectedInvoke, reflectedProcess }.Where(f => f is not null).Select(f => f!).ToArray());
				}
				var resourceRead = Api("Assembly::GetManifestResourceStream");
				var copy = Api("Stream::CopyTo");
				if (resourceRead is not null && copy is not null && write is not null && launch is not null) {
					var resource = result.HiddenContents.FirstOrDefault(c => c.Reference is EmbeddedResource er && facts.Any(f => f.Text && f.Value == er.Name.String));
					if (resource is not null && resource.Kind == "Command / script text") {
						var resourceFact = new Fact { Value = resource.Source + " | " + resource.Kind + " | SHA-256 " + resource.Sha256, Description = "Referenced embedded script resource", Method = resourceRead.Method, Reference = resource.Reference };
						Emit("MOD003", "Embedded command resource copied to disk near a launch API", "Embedded payload", new[] { resourceRead, resourceFact, write, copy, launch });
					}
				}

				void Emit(string rule, string title, string category, Fact[] evidence) {
					var distinct = evidence.Distinct().ToArray();
					var anchor = launch?.Method ?? reflectedInvoke?.Method ?? pair.Key;
					if (!emitted.Add(rule + "\0" + anchor.MDToken.Raw + "\0" + anchor.FullName)) return;
					if (result.Findings.Count >= AnalysisLimits.MaximumFindings) return;
					var finding = SecurityFindings.Create(context, rule, category, title,
						"These observations occur within a bounded same-module call/reference neighborhood, including compiler state machines and delegate references when present. This is a strong review indicator, not proof of runtime execution, argument flow, or malicious intent. Decoded candidates retain their heuristic status.",
						string.Join(" -> ", distinct.Select(f => f.Description + ": " + Short(f.Value))), SecuritySeverity.High, SecurityConfidence.Medium, anchor, launch?.Offset ?? reflectedInvoke?.Offset);
					foreach (var fact in distinct.Take(12)) finding.EvidenceItems.Add(Evidence(fact));
					foreach (var method in distinct.Select(f => f.Method).Distinct()) {
						if (!reachable.TryGetValue(method, out var path)) continue;
						foreach (var step in path.Take(4)) finding.EvidenceItems.Add(step);
					}
					if (startupPaths.TryGetValue(anchor, out var startup)) {
						finding.Explanation += " A recognized startup callback/initializer references this neighborhood; actual invocation is not established.";
						finding.EvidenceItems.InsertRange(0, startup);
					}
					result.Findings.Add(finding);
				}
			}
		}
		static MethodDef? LocalMethod(IMethod call, ModuleDef module) {
			if (call is MethodSpec spec) call = spec.Method;
			return call is MethodDef method && method.Module == module ? method : null;
		}
		static bool FrameworkReference(IMethod call) {
			if (call.DeclaringType is not TypeRef || call.DeclaringType.DefinitionAssembly is not AssemblyRef assembly) return false;
			var name = assembly.Name.String;
			if (name != "mscorlib" && name != "System" && name != "System.Core" && name != "System.Runtime" && name != "System.Private.CoreLib" && name != "System.Net.Http" && name != "System.Net.WebClient" &&
				name != "System.Net.Requests" && name != "System.Diagnostics.Process" && name != "System.IO.FileSystem" && name != "System.IO" && name != "System.Reflection" && name != "System.Reflection.Extensions" && name != "System.Runtime.Extensions") return false;
			var key = assembly.PublicKeyOrToken?.Token?.ToString();
			return key == "b77a5c561934e089" || key == "b03f5f7f11d50a3a" || key == "7cec85d7bea7798e" || key == "cc7b13ffcd2ddd51";
		}
		static Dictionary<MethodDef, List<SecurityEvidence>> Reachable(MethodDef start, Dictionary<MethodDef, Node> nodes, SecurityContext context, int depth, int maximum, bool includeCallers = false) {
			var paths = new Dictionary<MethodDef, List<SecurityEvidence>> { [start] = new List<SecurityEvidence>() };
			var queue = new Queue<(MethodDef method, int depth)>(); queue.Enqueue((start, 0));
			while (queue.Count > 0 && paths.Count < maximum) {
				context.CancellationToken.ThrowIfCancellationRequested(); var item = queue.Dequeue();
				if (item.depth >= depth) continue;
				foreach (var edge in nodes[item.method].Edges.Take(128)) {
					if (edge.Reverse && !includeCallers) continue;
					if (!nodes.ContainsKey(edge.Target) || paths.ContainsKey(edge.Target)) continue;
					var source = edge.Reverse ? edge.Target : item.method;
					var destination = edge.Reverse ? item.method : edge.Target;
					var path = new List<SecurityEvidence>(paths[item.method]) { new SecurityEvidence { Description = edge.Kind, Value = Short(source.FullName + " -> " + destination.FullName), Reference = source, Method = source.FullName, IlOffset = edge.Offset } };
					paths[edge.Target] = path; queue.Enqueue((edge.Target, item.depth + 1));
					if (paths.Count >= maximum) break;
				}
			}
			return paths;
		}
		static Dictionary<MethodDef, List<SecurityEvidence>> StartupPaths(SecurityContext context, Dictionary<MethodDef, Node> nodes) {
			var result = new Dictionary<MethodDef, List<SecurityEvidence>>(); int roots = 0;
			foreach (var root in nodes.Keys.Where(IsStartup)) {
				if (++roots > 512) break;
				foreach (var pair in Reachable(root, nodes, context, 6, 128)) {
					if (result.ContainsKey(pair.Key)) continue;
					result[pair.Key] = new List<SecurityEvidence> { new SecurityEvidence { Description = "Startup callback / initializer reference", Value = Short(root.FullName), Method = root.FullName, Reference = root } };
					result[pair.Key].AddRange(pair.Value);
				}
			}
			return result;
		}
		static bool IsStartup(MethodDef method) {
			if (method.IsStaticConstructor || method.Module.EntryPoint == method) return true;
			var baseName = method.DeclaringType.BaseType?.FullName ?? string.Empty;
			if (method.Name == "OnInitializeMelon" && baseName.StartsWith("MelonLoader.", StringComparison.Ordinal)) return true;
			if (method.Name == "Entry" && baseName == "StardewModdingAPI.Mod") return true;
			return (method.Name == "Awake" || method.Name == "Start" || method.Name == "OnEnable") && (baseName.StartsWith("BepInEx.", StringComparison.Ordinal) || baseName == "UnityEngine.MonoBehaviour");
		}
		static SecurityEvidence Evidence(Fact fact) => new SecurityEvidence { Description = fact.Description, Value = Short(fact.Value), Method = fact.Method.FullName, Reference = fact.Reference ?? fact.Method, IlOffset = fact.Offset };
		static string Short(string text) { text = SecurityText.Redact(text); return text.Length > 2048 ? text.Substring(0, 2048) + "…" : text; }
	}
}
