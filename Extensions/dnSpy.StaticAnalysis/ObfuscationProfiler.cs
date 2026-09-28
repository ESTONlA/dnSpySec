using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.StaticAnalysis {
	public sealed class ObfuscationProfiler {
		public void Analyze(ModuleDef module, StaticAnalysisResult result, CancellationToken token) {
			int names = 0, unicode = 0, unusual = 0, longNames = 0, highEntropy = 0, bodies = 0, tiny = 0, unreadable = 0, invalid = 0, inspected = 0;
			var identifier = Indicator("OBF101", "Identifier profile", "Counts cover non-generated metadata names. Ordinary Unicode names are counted separately and do not increase the profile level.");
			var entropy = Indicator("OBF102", "High-entropy or very long identifiers", "Long, varied identifiers can be generated or obfuscated. This heuristic does not identify a particular obfuscator.");
			var size = Indicator("OBF103", "Tiny method ratio", "Methods under eight IL instructions can be accessors, wrappers, or generated code. A high ratio alone is not proof of obfuscation.");
			var proxy = Indicator("OBF104", "Proxy method chains", "Short argument-forwarding methods form chains of at least three methods. Ordinary wrappers can have the same structure.");
			var dispatcher = Indicator("OBF105", "Possible control-flow flattening", "A large switch, local state, and a backward branch coexist in a method. This can also describe an ordinary state machine.");
			var tables = Indicator("OBF106", "Possible encoded string table", "A static byte/string array is referenced alongside string conversion or XOR operations in a string-returning method. Encryption and runtime use are not proven.");
			var malformed = Indicator("OBF107", "Unreadable metadata or IL", "Some methods contain invalid branch/local references or could not be inspected by the metadata reader. Malformed input is one possibility; parser limitations are another.");
			var proxies = new Dictionary<MethodDef, MethodDef>();
			bool limit = false;
			bool longNameLimit = false;
			void Name(string name, object reference, bool generated) {
				name = name ?? string.Empty;
				if (generated || name.StartsWith("<", StringComparison.Ordinal)) return;
				names++;
				var inspectedName = name.Length > StaticLimits.MaximumValueLength ? name.Substring(0, StaticLimits.MaximumValueLength) : name;
				if (inspectedName.Length != name.Length) longNameLimit = true;
				if (inspectedName.Any(c => c > 127)) unicode++;
				bool latin = inspectedName.Any(c => c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z');
				bool cyrillicOrGreek = inspectedName.Any(c => c >= '\u0370' && c <= '\u052F');
				if (name.Length == 0 || InvalidSurrogates(inspectedName) || inspectedName.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format) || latin && cyrillicOrGreek) {
					unusual++; Evidence(identifier, reference, "Non-printable, format, or mixed Latin/Greek/Cyrillic identifier: " + Escape(name));
				}
				if (name.Length >= 128) { longNames++; Evidence(entropy, reference, name.Length + " character identifier: " + Escape(name)); }
				if (name.Length >= 24 && name.Length <= StaticLimits.MaximumValueLength && Entropy(name) >= 4.2) { highEntropy++; Evidence(entropy, reference, "Identifier entropy ≥ 4.2 bits/character: " + Escape(name)); }
			}
			foreach (var type in module.GetTypes()) {
				token.ThrowIfCancellationRequested();
				bool generated = Generated(type.CustomAttributes);
				if (!type.IsGlobalModuleType) Name(type.Name, type, generated);
				foreach (var field in type.Fields) { token.ThrowIfCancellationRequested(); Name(field.Name, field, generated || Generated(field.CustomAttributes)); }
				foreach (var property in type.Properties) { token.ThrowIfCancellationRequested(); Name(property.Name, property, generated || Generated(property.CustomAttributes)); }
				foreach (var method in type.Methods) {
					token.ThrowIfCancellationRequested();
					if (++inspected > StaticLimits.MaximumMethodCount) { limit = true; break; }
					Name(method.Name, method, generated || Generated(method.CustomAttributes));
					try {
						if (!method.HasBody) continue;
						bodies++;
						var body = method.Body.Instructions;
						if (body.Count > StaticLimits.MaximumMethodInstructions) { result.Limitations.Add("Profile skipped a method above the IL-size limit: " + Escape(method.Name)); continue; }
						var invalidReference = InvalidReference(method);
						if (invalidReference is not null) { invalid++; Evidence(malformed, method, invalidReference + ": " + method.FullName); }
						if (body.Count < 8) { tiny++; Evidence(size, method, body.Count + " IL instructions: " + method.FullName); }
						var forwarded = ProxyTarget(method);
						if (forwarded is not null) proxies[method] = forwarded;
						bool largeSwitch = body.Any(i => i.OpCode.Code == Code.Switch && i.Operand is IList<Instruction> targets && targets.Count >= 8);
						bool backward = body.Any(i => i.OpCode.FlowControl == FlowControl.Branch && i.Operand is Instruction target && target.Offset < i.Offset);
						if (largeSwitch && backward && method.Body.Variables.Count > 0) Evidence(dispatcher, method, "Switch with ≥ 8 targets, locals, and backward branch: " + method.FullName);
						bool returnsString = method.MethodSig?.RetType.FullName == "System.String";
						bool decode = body.Any(i => i.OpCode.Code == Code.Xor || i.Operand is IMethod call &&
							ConstantStringAnalyzer.IsFramework(call) && (call.Name == "FromBase64String" || call.Name == "GetString"));
						if (returnsString && decode) {
							var field = body.Where(i => i.OpCode.Code == Code.Ldsfld).Select(i => i.Operand as IField)
								.FirstOrDefault(f => f?.FieldSig?.Type.FullName == "System.Byte[]" || f?.FieldSig?.Type.FullName == "System.String[]");
							if (field is not null) Evidence(tables, method, "Static table " + field.FullName + " and decode/XOR references in " + method.FullName);
						}
					} catch (OperationCanceledException) { throw; }
					catch (Exception ex) { unreadable++; Evidence(malformed, method, ex.GetType().Name + " while reading token 0x" + method.MDToken.Raw.ToString("X8")); }
				}
				if (limit) break;
			}
			int chains = 0;
			foreach (var start in proxies.Keys) {
				token.ThrowIfCancellationRequested();
				var visited = new HashSet<MethodDef>(); var path = new List<string>(); var current = start;
				while (path.Count < 8 && visited.Add(current) && proxies.TryGetValue(current, out var next)) { path.Add(current.FullName); current = next; }
				if (path.Count >= 3) { chains++; Evidence(proxy, start, string.Join(" → ", path)); }
			}
			identifier.Title = unusual.ToString("N0") + " unusual identifiers; " + unicode.ToString("N0") + " Unicode identifiers; " + names.ToString("N0") + " names inspected";
			if (unusual >= 10 && names > 0 && (double)unusual / names >= 0.1) { identifier.Level = "Medium"; identifier.Weight = 2; }
			entropy.Title = highEntropy.ToString("N0") + " high-entropy identifiers; " + longNames.ToString("N0") + " identifiers ≥ 128 characters";
			if (longNames >= 10 || highEntropy >= 10 && names > 0 && (double)highEntropy / names >= 0.1) { entropy.Level = "Low"; entropy.Weight = 1; }
			var ratio = bodies == 0 ? 0 : (double)tiny / bodies;
			size.Title = ratio.ToString("P1") + " of methods under 8 IL instructions (" + tiny.ToString("N0") + "/" + bodies.ToString("N0") + ")";
			if (bodies >= 100 && ratio >= 0.8) { size.Level = "Low"; size.Weight = 1; }
			proxy.Title = chains + " proxy chains; " + proxies.Count + " forwarding methods";
			if (chains >= 3) { proxy.Level = "Medium"; proxy.Weight = 2; }
			SetPattern(dispatcher, "dispatcher-like methods", 2);
			SetPattern(tables, "encoded-table candidate methods", 2);
			malformed.Title = invalid + " methods with invalid IL references; " + unreadable + " unreadable method bodies";
			if (unreadable > 0 || invalid > 0) { malformed.Level = "Medium"; malformed.Weight = 1; }
			result.Indicators.AddRange(new[] { identifier, entropy, size, proxy, dispatcher, tables, malformed });
			int score = result.Indicators.Sum(i => i.Weight), categories = result.Indicators.Count(i => i.Weight > 0);
			result.ProfileLevel = score >= 4 && categories >= 2 ? "High" : score >= 2 ? "Medium" : "Low";
			if (limit) result.Limitations.Add("Obfuscation profile stopped at the method-count limit.");
			if (longNameLimit) result.Limitations.Add("Identifier character checks were limited to the first 16,384 characters of oversized names.");
		}
		static ObfuscationIndicator Indicator(string id, string title, string explanation) => new ObfuscationIndicator { RuleId = id, Title = title, Explanation = explanation };
		static void Evidence(ObfuscationIndicator indicator, object reference, string description) {
			indicator.ObservationCount++;
			if (indicator.Evidence.Count < 20) indicator.Evidence.Add(new ProfileEvidence { Reference = reference, Description = Escape(description) });
		}
		static void SetPattern(ObfuscationIndicator indicator, string label, int weight) {
			indicator.Title += " (" + indicator.ObservationCount + " " + label + ")";
			if (indicator.ObservationCount > 0) { indicator.Level = "Medium"; indicator.Weight = weight; }
		}
		static bool Generated(IList<CustomAttribute> attributes) => attributes.Any(a => a.TypeFullName == "System.Runtime.CompilerServices.CompilerGeneratedAttribute");
		static MethodDef? ProxyTarget(MethodDef method) {
			var body = method.Body.Instructions.Where(i => i.OpCode.Code != Code.Nop).ToArray();
			if (body.Length < 2 || body.Length > 12 || body[body.Length - 1].OpCode.Code != Code.Ret) return null;
			var calls = body.Where(i => i.OpCode.Code == Code.Call).ToArray();
			if (calls.Length != 1 || calls[0].Operand is not MethodDef target || target.Module != method.Module) return null;
			if (body.Any(i => i.OpCode.Code != Code.Call && i.OpCode.Code != Code.Ret && i.OpCode.Code != Code.Ldarg && i.OpCode.Code != Code.Ldarg_S &&
				i.OpCode.Code != Code.Ldarg_0 && i.OpCode.Code != Code.Ldarg_1 && i.OpCode.Code != Code.Ldarg_2 && i.OpCode.Code != Code.Ldarg_3)) return null;
			return target;
		}
		static string? InvalidReference(MethodDef method) {
			var instructions = new HashSet<Instruction>(method.Body.Instructions);
			var locals = new HashSet<Local>(method.Body.Variables);
			foreach (var instruction in method.Body.Instructions) {
				if (instruction.Operand is Local local && !locals.Contains(local)) return "Local operand is outside the method's local table";
				if (instruction.OpCode.Code == Code.Switch) {
					if (instruction.Operand is not IList<Instruction> targets || targets.Any(t => t is null || !instructions.Contains(t))) return "Switch target is outside the method body";
				} else if (instruction.OpCode.FlowControl == FlowControl.Branch || instruction.OpCode.FlowControl == FlowControl.Cond_Branch) {
					if (instruction.Operand is not Instruction target || !instructions.Contains(target)) return "Branch target is outside the method body";
				}
			}
			return null;
		}
		static double Entropy(string name) {
			double entropy = 0;
			foreach (var group in name.GroupBy(c => c)) { double p = (double)group.Count() / name.Length; entropy -= p * Math.Log(p, 2); }
			return entropy;
		}
		static bool InvalidSurrogates(string name) {
			for (int i = 0; i < name.Length; i++) {
				if (char.IsHighSurrogate(name[i])) { if (i + 1 >= name.Length || !char.IsLowSurrogate(name[++i])) return true; }
				else if (char.IsLowSurrogate(name[i])) return true;
			}
			return false;
		}
		static string Escape(string name) {
			if (name.Length > 512) name = name.Substring(0, 512) + "…";
			return ConstantTransforms.Display(string.Concat(name.Select(c => char.IsControl(c) || char.IsSurrogate(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format ? "\\u" + ((int)c).ToString("X4") : c.ToString())));
		}
	}
}
