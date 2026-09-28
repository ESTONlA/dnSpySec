using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.StaticAnalysis {
	// All values below are analyst-owned data. No target object, CLR assembly, delegate, or
	// runtime method is created. Calls are reduced by explicit rules or remain unknown.
	public sealed class ConstantStringAnalyzer {
		enum TextEncoding { Utf8, Ascii }
		sealed class Value {
			public object? Data;
			public string Original = string.Empty;
			public string[] Operations = Array.Empty<string>();
			public static readonly Value Unknown = new Value();
			public static Value Of(object data, string original = "", params string[] operations) => new Value { Data = data, Original = original, Operations = operations };
			public Value Changed(object data, string operation) => Of(data, Original, Operations.Concat(new[] { operation }).Distinct().Take(12).ToArray());
		}
		sealed class DataArray {
			public readonly int[] Items;
			public readonly bool Characters;
			public bool Known = true;
			public string Original = string.Empty;
			public readonly HashSet<string> Operations = new HashSet<string>();
			public DataArray(int length, bool characters) { ConstantTransforms.CheckLength(length); Items = new int[length]; Characters = characters; }
			public string Describe() => Characters ? new string(Items.Select(i => (char)i).ToArray()) : BitConverter.ToString(Items.Select(i => (byte)i).ToArray()).Replace("-", "");
			public Value Element(int index) { if (Original.Length == 0) Original = Describe(); return Value.Of(Items[index], Original, Operations.ToArray()); }
			public byte[] Bytes() => Items.Select(i => (byte)i).ToArray();
		}
		sealed class AesData { public string Name = "AES"; }
		sealed class Budget {
			public int Steps;
			public int AllocatedElements;
			public bool Unresolved;
		}
		StaticAnalysisResult result = null!;
		ModuleDef module = null!;
		CancellationToken token;
		int totalSteps;
		int resultCharacters;
		bool outputLimited;
		readonly Dictionary<MethodDef, HashSet<string>> seen = new Dictionary<MethodDef, HashSet<string>>();

		public void Analyze(ModuleDef module, StaticAnalysisResult result, CancellationToken cancellationToken) {
			this.module = module; this.result = result; token = cancellationToken;
			totalSteps = resultCharacters = 0; outputLimited = false; seen.Clear();
			int methodsVisited = 0;
			foreach (var type in module.GetTypes()) {
				token.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					token.ThrowIfCancellationRequested();
					if (++methodsVisited > StaticLimits.MaximumMethodCount || totalSteps >= StaticLimits.MaximumTotalSteps || result.Strings.Count >= StaticLimits.MaximumResults || outputLimited) {
						result.Limitations.Add("String analysis stopped at the method, instruction, or output budget."); return;
					}
					var budget = new Budget();
					try {
						if (!method.HasBody) continue;
						result.MethodsInspected++;
						var instructions = method.Body.Instructions;
						if (instructions.Count > StaticLimits.MaximumMethodInstructions) { budget.Unresolved = true; continue; }
						foreach (var instruction in instructions) {
							token.ThrowIfCancellationRequested();
							if (++totalSteps > StaticLimits.MaximumTotalSteps) { budget.Unresolved = true; break; }
							if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string literal) InspectLiteral(literal, method, instruction.Offset);
							if (instruction.Operand is IMethod call && IsFramework(call) && IsAesType(call.DeclaringType.FullName))
								AddCrypto(method, instruction.Offset, call.DeclaringType.FullName, "API reference", call.Name + " (configuration/runtime use not established)");
						}
						try { Reduce(method, Array.Empty<Value>(), 0, budget); }
						catch (OperationCanceledException) { throw; }
						catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Static IL region: " + ex.GetType().Name); budget.Unresolved = true; }
						// Start fresh, independent regions after unrelated/unsupported code. Unknown
						// locals are never carried across regions, and reachability is not inferred.
						int seeds = 0;
						for (int i = 1; i < instructions.Count && budget.Steps < StaticLimits.MaximumStepsPerMethod; i++) {
							var seed = instructions[i];
							if (seed.OpCode.Code != Code.Ldstr && !(seed.Operand is IMethod entry && IsFramework(entry) &&
								entry.DeclaringType.FullName == "System.Text.Encoding" && (entry.Name == "get_UTF8" || entry.Name == "get_ASCII"))) continue;
							if (++seeds > 64) { budget.Unresolved = true; break; }
							try { Reduce(method, Array.Empty<Value>(), 0, budget, i); }
							catch (OperationCanceledException) { throw; }
							catch (Exception) { budget.Unresolved = true; }
						}
					} catch (OperationCanceledException) { throw; }
					catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Static constant reduction / " + method.FullName + ": " + ex); budget.Unresolved = true; }
					finally { if (budget.Unresolved) result.MethodsWithUnresolvedOperations++; }
				}
			}
		}

		void InspectLiteral(string literal, MethodDef method, uint offset) {
			if (literal.Length < 24 || literal.Length > StaticLimits.MaximumValueLength) return;
			try {
				if ((literal.Length & 3) != 0 || literal.Any(c => !(char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '='))) return;
				var decoded = ConstantTransforms.StrictUtf8.GetString(Convert.FromBase64String(literal));
				if (decoded.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || decoded.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
					decoded.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) || decoded.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
					AddString(method, offset, literal, decoded, "Candidate Base64", "Heuristic decoding of a literal. No decode call or runtime use is established.");
			} catch (FormatException) { }
			catch (DecoderFallbackException) { }
		}

		Value Reduce(MethodDef method, Value[] arguments, int depth, Budget budget, int start = 0) {
			if (depth > StaticLimits.MaximumHelperDepth || !method.HasBody ||
				method.Body.Instructions.Count > StaticLimits.MaximumMethodInstructions || method.Body.Variables.Count > 4096) return Value.Unknown;
			var instructions = method.Body.Instructions;
			var positions = new Dictionary<Instruction, int>();
			for (int i = 0; i < instructions.Count; i++) positions[instructions[i]] = i;
			var locals = Enumerable.Repeat(Value.Unknown, method.Body.Variables.Count).ToArray();
			var stack = new Stack<Value>();
			Value Pop() => stack.Count == 0 ? throw new InvalidOperationException("Invalid evaluation stack.") : stack.Pop();
			int Jump(object operand) => operand is Instruction target && positions.TryGetValue(target, out var position) ? position : throw new InvalidOperationException("Invalid branch target.");
			for (int pc = start; pc < instructions.Count;) {
				token.ThrowIfCancellationRequested();
				if (outputLimited) { budget.Unresolved = true; return Value.Unknown; }
				if (++budget.Steps > StaticLimits.MaximumStepsPerMethod || ++totalSteps > StaticLimits.MaximumTotalSteps || stack.Count > 256) { budget.Unresolved = true; return Value.Unknown; }
				var instruction = instructions[pc++];
				var code = instruction.OpCode.Code;
				if (instruction.IsLdcI4()) { stack.Push(Value.Of(instruction.GetLdcI4Value())); continue; }
				switch (code) {
				case Code.Nop: break;
				case Code.Ldstr:
					var literal = (string)instruction.Operand; ConstantTransforms.CheckLength(literal.Length); stack.Push(Value.Of(literal, literal)); break;
				case Code.Ldnull: stack.Push(Value.Unknown); break;
				case Code.Dup: stack.Push(stack.Peek()); break;
				case Code.Pop: Pop(); break;
				case Code.Ldloc: case Code.Ldloc_S: case Code.Ldloc_0: case Code.Ldloc_1: case Code.Ldloc_2: case Code.Ldloc_3:
					stack.Push(locals[LocalIndex(instruction)]); break;
				case Code.Stloc: case Code.Stloc_S: case Code.Stloc_0: case Code.Stloc_1: case Code.Stloc_2: case Code.Stloc_3:
					locals[LocalIndex(instruction)] = Pop(); break;
				case Code.Ldarg: case Code.Ldarg_S: case Code.Ldarg_0: case Code.Ldarg_1: case Code.Ldarg_2: case Code.Ldarg_3:
					var arg = ArgumentIndex(instruction); stack.Push(arg < arguments.Length ? arguments[arg] : Value.Unknown); break;
				case Code.Newarr:
					var size = Pop();
					var elementType = (instruction.Operand as ITypeDefOrRef)?.FullName;
					if (size.Data is not int length || elementType != "System.Byte" && elementType != "System.Char") { budget.Unresolved = true; stack.Push(Value.Unknown); break; }
					stack.Push(Value.Of(NewArray(length, elementType == "System.Char", budget))); break;
				case Code.Ldlen:
					var arrayLength = Pop(); stack.Push(arrayLength.Data is DataArray a ? Value.Of(a.Items.Length) : Value.Unknown); break;
				case Code.Ldelem_U1: case Code.Ldelem_I1: case Code.Ldelem_U2:
					var index = Pop(); var array = Pop();
					if (array.Data is DataArray data && data.Known && (code == Code.Ldelem_U2) == data.Characters && index.Data is int itemIndex && itemIndex >= 0 && itemIndex < data.Items.Length) {
						var value = data.Element(itemIndex);
						if (code == Code.Ldelem_I1) value.Data = (int)unchecked((sbyte)data.Items[itemIndex]);
						stack.Push(value);
					} else { budget.Unresolved = true; stack.Push(Value.Unknown); }
					break;
				case Code.Stelem_I1: case Code.Stelem_I2:
					var item = Pop(); var at = Pop(); var destination = Pop();
					if (destination.Data is DataArray targetArray) {
						if (item.Data is int number && at.Data is int slot && slot >= 0 && slot < targetArray.Items.Length &&
							(code == Code.Stelem_I2) == targetArray.Characters) {
							if (item.Operations.Length > 0 && targetArray.Original.Length == 0) targetArray.Original = item.Original;
							foreach (var operation in item.Operations) targetArray.Operations.Add(operation);
							targetArray.Items[slot] = targetArray.Characters ? unchecked((ushort)number) : unchecked((byte)number);
						} else { targetArray.Known = false; budget.Unresolved = true; }
					} else budget.Unresolved = true;
					break;
				case Code.Ldtoken:
					stack.Push(instruction.Operand is FieldDef field && field.Module == module ? Value.Of(field) : Value.Unknown); break;
				case Code.Conv_I4: case Code.Conv_U4: break; // Only I4 values are represented; native-sized arithmetic stays unresolved.
				case Code.Conv_U1: case Code.Conv_I1: case Code.Conv_U2: case Code.Conv_I2:
					var convert = Pop();
					stack.Push(convert.Data is int integer ? convert.Changed(code == Code.Conv_U1 ? (int)unchecked((byte)integer) : code == Code.Conv_I1 ? (int)unchecked((sbyte)integer) :
						code == Code.Conv_U2 ? (int)unchecked((ushort)integer) : (int)unchecked((short)integer), "Constant arithmetic") : Value.Unknown); break;
				case Code.Add: case Code.Sub: case Code.Mul: case Code.Div: case Code.Div_Un: case Code.Rem: case Code.Rem_Un:
				case Code.Xor: case Code.And: case Code.Or: case Code.Shl: case Code.Shr: case Code.Shr_Un: case Code.Ceq: case Code.Cgt: case Code.Cgt_Un: case Code.Clt: case Code.Clt_Un:
					var right = Pop(); var left = Pop(); stack.Push(Binary(left, right, code)); break;
				case Code.Neg: case Code.Not:
					var unary = Pop(); stack.Push(unary.Data is int numberValue ? unary.Changed(code == Code.Neg ? unchecked(-numberValue) : ~numberValue, "Constant arithmetic") : Value.Unknown); break;
				case Code.Br: case Code.Br_S: pc = Jump(instruction.Operand); break;
				case Code.Brtrue: case Code.Brtrue_S: case Code.Brfalse: case Code.Brfalse_S:
					var condition = Pop();
					if (condition.Data is not int truth) { budget.Unresolved = true; return Value.Unknown; }
					if ((truth != 0) == (code == Code.Brtrue || code == Code.Brtrue_S)) pc = Jump(instruction.Operand); break;
				case Code.Beq: case Code.Beq_S: case Code.Bne_Un: case Code.Bne_Un_S: case Code.Blt: case Code.Blt_S: case Code.Blt_Un: case Code.Blt_Un_S:
				case Code.Ble: case Code.Ble_S: case Code.Ble_Un: case Code.Ble_Un_S: case Code.Bgt: case Code.Bgt_S: case Code.Bgt_Un: case Code.Bgt_Un_S:
				case Code.Bge: case Code.Bge_S: case Code.Bge_Un: case Code.Bge_Un_S:
					var compareRight = Pop(); var compareLeft = Pop();
					if (compareLeft.Data is not int l || compareRight.Data is not int r) { budget.Unresolved = true; return Value.Unknown; }
					if (Branch(l, r, code)) pc = Jump(instruction.Operand); break;
				case Code.Call: case Code.Callvirt: case Code.Newobj:
					if (instruction.Operand is not IMethod called || called.MethodSig is not MethodSig signature || signature.Params.Count > 32) { budget.Unresolved = true; return Value.Unknown; }
					var count = signature.Params.Count + (signature.HasThis && code != Code.Newobj ? 1 : 0);
					var values = new Value[count];
					for (int i = count - 1; i >= 0; i--) values[i] = Pop();
					var reduced = ReduceCall(called, values, code, method, instruction.Offset, depth, budget);
					if (signature.RetType.ElementType != ElementType.Void || code == Code.Newobj) stack.Push(reduced);
					break;
				case Code.Ret:
					var returned = method.MethodSig.RetType.ElementType == ElementType.Void ? Value.Unknown : Pop();
					Record(returned, method, instruction.Offset); return returned;
				default: budget.Unresolved = true; return Value.Unknown;
				}
			}
			return Value.Unknown;
		}

		DataArray NewArray(int length, bool characters, Budget budget) {
			ConstantTransforms.CheckLength(length);
			if ((long)budget.AllocatedElements + length > StaticLimits.MaximumArrayElementsPerMethod) throw new InvalidOperationException("Array allocation budget reached.");
			budget.AllocatedElements += length; return new DataArray(length, characters);
		}

		Value ReduceCall(IMethod called, Value[] values, Code opcode, MethodDef source, uint offset, int depth, Budget budget) {
			try {
				var key = called.DeclaringType?.FullName + "::" + called.Name;
				if (IsFramework(called)) {
					Value? value = null;
					if (key == "System.Convert::FromBase64String" && values.Length == 1 && values[0].Data is string base64) {
						var bytes = Convert.FromBase64String(base64); var array = NewArray(bytes.Length, false, budget);
						for (int i = 0; i < bytes.Length; i++) array.Items[i] = bytes[i];
						array.Original = values[0].Original; array.Operations.UnionWith(values[0].Operations); array.Operations.Add("Base64"); value = Value.Of(array);
					} else if (key == "System.Convert::FromHexString" && values.Length == 1 && values[0].Data is string hex) {
						var bytes = ConstantTransforms.HexBytes(hex); var array = NewArray(bytes.Length, false, budget);
						for (int i = 0; i < bytes.Length; i++) array.Items[i] = bytes[i];
						array.Original = values[0].Original; array.Operations.UnionWith(values[0].Operations); array.Operations.Add("Hex"); value = Value.Of(array);
					} else if (key == "System.Text.Encoding::get_UTF8" && values.Length == 0) value = Value.Of(TextEncoding.Utf8);
					else if (key == "System.Text.Encoding::get_ASCII" && values.Length == 0) value = Value.Of(TextEncoding.Ascii);
					else if (key == "System.Text.Encoding::GetString" && values.Length == 2 && values[0].Data is TextEncoding encoding &&
						values[1].Data is DataArray input && input.Known && !input.Characters) {
						var text = encoding == TextEncoding.Utf8 ? ConstantTransforms.StrictUtf8.GetString(input.Bytes()) : Encoding.ASCII.GetString(input.Bytes());
						value = Value.Of(text, input.Original.Length > 0 ? input.Original : input.Describe(), input.Operations.Concat(new[] { encoding == TextEncoding.Utf8 ? "UTF-8" : "ASCII" }).ToArray());
					} else if (key == "System.String::Concat" && values.Length >= 2 && values.Length <= 4 && values.All(v => v.Data is string)) {
						var length = values.Sum(v => ((string)v.Data!).Length); ConstantTransforms.CheckLength(length);
						value = Value.Of(string.Concat(values.Select(v => (string)v.Data!)), Short(string.Join(" + ", values.Select(v => v.Original))), values.SelectMany(v => v.Operations).Concat(new[] { "Concatenation" }).Distinct().ToArray());
					} else if (key == "System.Text.Encoding::GetBytes" && values.Length == 2 && values[0].Data is TextEncoding byteEncoding && values[1].Data is string byteText) {
						var encoder = byteEncoding == TextEncoding.Utf8 ? ConstantTransforms.StrictUtf8 : Encoding.ASCII;
						var count = encoder.GetByteCount(byteText); var array = NewArray(count, false, budget); var bytes = encoder.GetBytes(byteText);
						for (int i = 0; i < bytes.Length; i++) array.Items[i] = bytes[i];
						array.Original = values[1].Original; array.Operations.UnionWith(values[1].Operations); array.Operations.Add("Constant byte encoding"); value = Value.Of(array);
					} else if (key == "System.String::ToCharArray" && values.Length == 1 && values[0].Data is string text) {
						var array = NewArray(text.Length, true, budget); for (int i = 0; i < text.Length; i++) array.Items[i] = text[i];
						array.Original = values[0].Original; array.Operations.UnionWith(values[0].Operations); value = Value.Of(array);
					} else if (key == "System.String::.ctor" && opcode == Code.Newobj && values.Length == 1 && values[0].Data is DataArray chars && chars.Known && chars.Characters)
						value = Value.Of(new string(chars.Items.Select(i => (char)i).ToArray()), chars.Original, chars.Operations.Concat(new[] { "Character array" }).ToArray());
					else if (key == "System.String::get_Length" && values.Length == 1 && values[0].Data is string stringLength) value = Value.Of(stringLength.Length);
					else if (key == "System.String::get_Chars" && values.Length == 2 && values[0].Data is string stringValue && values[1].Data is int index && index >= 0 && index < stringValue.Length)
						value = Value.Of((int)stringValue[index], values[0].Original, values[0].Operations);
					else if (key == "System.Array::Reverse" && values.Length == 1 && values[0].Data is DataArray reversed && reversed.Known) {
						if (reversed.Original.Length == 0) reversed.Original = reversed.Describe();
						Array.Reverse(reversed.Items); reversed.Operations.Add("Reverse"); return Value.Unknown;
					} else if (key == "System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray" && values.Length == 2 &&
						values[0].Data is DataArray initialized && values[1].Data is FieldDef field && field.HasFieldRVA) {
						var required = (long)initialized.Items.Length * (initialized.Characters ? 2 : 1);
						if (!field.GetFieldSize(out uint fieldSize) || fieldSize < required || fieldSize > StaticLimits.MaximumValueLength * 2) throw new InvalidOperationException("RVA field size limit reached.");
						var raw = field.InitialValue ?? throw new InvalidOperationException("RVA bytes unavailable.");
						if (raw.Length < required || raw.Length > StaticLimits.MaximumValueLength * 2) throw new InvalidOperationException("Invalid RVA data size.");
						for (int i = 0; i < initialized.Items.Length; i++) initialized.Items[i] = initialized.Characters ? raw[i * 2] | raw[i * 2 + 1] << 8 : raw[i];
						initialized.Original = initialized.Describe(); return Value.Unknown;
					} else if (key == "System.Convert::ToByte" && values.Length == 2 && values[0].Data is string digits && values[1].Data is int radix && radix == 16)
						value = values[0].Changed((int)Convert.ToByte(digits, 16), "Hex");
					else if (key == "System.String::Substring" && (values.Length == 2 || values.Length == 3) && values[0].Data is string original && values[1].Data is int start &&
						start >= 0 && start <= original.Length && (values.Length == 2 || values[2].Data is int)) {
						var count = values.Length == 3 ? (int)values[2].Data! : original.Length - start;
						if (count < 0 || count > original.Length - start) throw new ArgumentOutOfRangeException();
						value = values[0].Changed(original.Substring(start, count), "Substring");
					} else if (IsAesType(called.DeclaringType!.FullName) || called.DeclaringType.FullName == "System.Security.Cryptography.SymmetricAlgorithm" && values.Length > 0 && values[0].Data is AesData) {
						if ((called.Name == "Create" || opcode == Code.Newobj) && values.Length == 0) return Value.Of(new AesData { Name = called.DeclaringType.FullName });
						if (values.Length == 2 && values[0].Data is AesData aes && called.Name.ToString().StartsWith("set_", StringComparison.Ordinal)) {
							var property = called.Name.ToString().Substring(4);
							if (property != "Key" && property != "IV" && property != "Mode" && property != "Padding" && property != "KeySize" && property != "BlockSize") return Value.Unknown;
							var setting = values[1].Data is DataArray bytes && bytes.Known ? property == "Key" ? bytes.Items.Length + " constant bytes [KEY REDACTED]" : bytes.Describe() :
								values[1].Data is int n ? n.ToString(CultureInfo.InvariantCulture) : "Unresolved";
							AddCrypto(source, offset, aes.Name, property, setting + " (static constant; runtime assignment not proven)"); return Value.Unknown;
						}
					}
					if (value is not null) { Record(value, source, offset); return value; }
				}
				if (opcode == Code.Call && called is MethodDef helper && helper.Module == module && helper.IsStatic && !helper.IsPinvokeImpl && depth < StaticLimits.MaximumHelperDepth &&
					values.All(v => v.Data is not null) && IsPureHelper(helper, new HashSet<MethodDef>(), depth)) return Reduce(helper, values, depth + 1, budget);
			} catch (OperationCanceledException) { throw; }
			catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Static transformation: " + ex.GetType().Name); }
			// An unknown call may mutate arrays passed to it. Never reuse those as known constants.
			foreach (var value in values) if (value.Data is DataArray array) array.Known = false;
			budget.Unresolved = true; return Value.Unknown;
		}

		bool IsPureHelper(MethodDef method, HashSet<MethodDef> visited, int depth) {
			if (depth >= StaticLimits.MaximumHelperDepth || !visited.Add(method) || !method.HasBody || method.Body.ExceptionHandlers.Count != 0 || method.Body.Instructions.Count > StaticLimits.MaximumMethodInstructions) return false;
			foreach (var instruction in method.Body.Instructions) {
				token.ThrowIfCancellationRequested();
				if (++totalSteps > StaticLimits.MaximumTotalSteps) return false;
				if (instruction.IsLdcI4()) continue;
				if (instruction.Operand is IMethod call && (instruction.OpCode.Code == Code.Call || instruction.OpCode.Code == Code.Callvirt || instruction.OpCode.Code == Code.Newobj)) {
					if (IsFramework(call) && IsPureFrameworkCall(call)) continue;
					if (call is MethodDef helper && helper.Module == module && helper.IsStatic && !helper.IsPinvokeImpl && IsPureHelper(helper, visited, depth + 1)) continue;
					return false;
				}
				if (!PureCodes.Contains(instruction.OpCode.Code)) return false;
			}
			visited.Remove(method); return true;
		}
		static readonly HashSet<Code> PureCodes = new HashSet<Code> {
			Code.Nop, Code.Ldstr, Code.Dup, Code.Pop, Code.Ldloc, Code.Ldloc_S, Code.Ldloc_0, Code.Ldloc_1, Code.Ldloc_2, Code.Ldloc_3,
			Code.Stloc, Code.Stloc_S, Code.Stloc_0, Code.Stloc_1, Code.Stloc_2, Code.Stloc_3, Code.Ldarg, Code.Ldarg_S, Code.Ldarg_0, Code.Ldarg_1, Code.Ldarg_2, Code.Ldarg_3,
			Code.Newarr, Code.Ldlen, Code.Ldelem_U1, Code.Ldelem_I1, Code.Ldelem_U2, Code.Stelem_I1, Code.Stelem_I2, Code.Ldtoken,
			Code.Conv_I4, Code.Conv_U4, Code.Conv_U1, Code.Conv_I1, Code.Conv_U2, Code.Conv_I2,
			Code.Add, Code.Sub, Code.Mul, Code.Div, Code.Div_Un, Code.Rem, Code.Rem_Un, Code.Xor, Code.And, Code.Or, Code.Shl, Code.Shr, Code.Shr_Un, Code.Neg, Code.Not,
			Code.Ceq, Code.Cgt, Code.Cgt_Un, Code.Clt, Code.Clt_Un, Code.Br, Code.Br_S, Code.Brtrue, Code.Brtrue_S, Code.Brfalse, Code.Brfalse_S,
			Code.Beq, Code.Beq_S, Code.Bne_Un, Code.Bne_Un_S, Code.Blt, Code.Blt_S, Code.Blt_Un, Code.Blt_Un_S, Code.Ble, Code.Ble_S, Code.Ble_Un, Code.Ble_Un_S,
			Code.Bgt, Code.Bgt_S, Code.Bgt_Un, Code.Bgt_Un_S, Code.Bge, Code.Bge_S, Code.Bge_Un, Code.Bge_Un_S, Code.Ret
		};
		static readonly HashSet<string> PureCalls = new HashSet<string>(StringComparer.Ordinal) {
			"System.Convert::FromBase64String", "System.Convert::FromHexString", "System.Convert::ToByte", "System.String::Concat", "System.String::ToCharArray",
			"System.String::.ctor", "System.String::get_Length", "System.String::get_Chars", "System.String::Substring", "System.Array::Reverse",
			"System.Text.Encoding::get_UTF8", "System.Text.Encoding::get_ASCII", "System.Text.Encoding::GetString", "System.Text.Encoding::GetBytes", "System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray"
		};
		static bool IsPureFrameworkCall(IMethod method) => PureCalls.Contains(method.DeclaringType.FullName + "::" + method.Name);
		internal static bool IsFramework(IMethod method) {
			var declaring = method.DeclaringType;
			if (declaring is not TypeRef) return false;
			var assembly = declaring.DefinitionAssembly;
			if (assembly is not AssemblyRef) return false;
			var name = assembly.Name.String;
			if (name != "mscorlib" && name != "System" && name != "System.Core" && name != "System.Security" && name != "System.Private.CoreLib" && name != "System.Runtime" && name != "System.Text.Encoding" &&
				name != "System.Text.Encoding.Extensions" && name != "System.Security.Cryptography" && name != "System.Security.Cryptography.Algorithms" && name != "System.Security.Cryptography.Primitives") return false;
			var publicKey = assembly.PublicKeyOrToken?.Token?.ToString();
			return publicKey == "b77a5c561934e089" || publicKey == "b03f5f7f11d50a3a" || publicKey == "7cec85d7bea7798e" || publicKey == "cc7b13ffcd2ddd51";
		}
		static bool IsAesType(string name) => name == "System.Security.Cryptography.Aes" || name == "System.Security.Cryptography.AesManaged" || name == "System.Security.Cryptography.AesCryptoServiceProvider";

		static Value Binary(Value left, Value right, Code code) {
			if (left.Data is not int l || right.Data is not int r) return Value.Unknown;
			int value;
			switch (code) {
			case Code.Add: value = unchecked(l + r); break; case Code.Sub: value = unchecked(l - r); break; case Code.Mul: value = unchecked(l * r); break;
			case Code.Div: value = l / r; break; case Code.Div_Un: value = unchecked((int)((uint)l / (uint)r)); break;
			case Code.Rem: value = l % r; break; case Code.Rem_Un: value = unchecked((int)((uint)l % (uint)r)); break;
			case Code.Xor: value = l ^ r; break; case Code.And: value = l & r; break; case Code.Or: value = l | r; break;
			case Code.Shl: value = l << (r & 31); break; case Code.Shr: value = l >> (r & 31); break; case Code.Shr_Un: value = unchecked((int)((uint)l >> (r & 31))); break;
			case Code.Ceq: value = l == r ? 1 : 0; break; case Code.Cgt: value = l > r ? 1 : 0; break; case Code.Cgt_Un: value = (uint)l > (uint)r ? 1 : 0; break;
			case Code.Clt: value = l < r ? 1 : 0; break; case Code.Clt_Un: value = (uint)l < (uint)r ? 1 : 0; break; default: return Value.Unknown;
			}
			return Value.Of(value, left.Original.Length > 0 ? left.Original : right.Original, left.Operations.Concat(right.Operations)
				.Concat(new[] { code == Code.Xor ? "XOR" : code == Code.Rem || code == Code.Rem_Un ? "Modulo / ROT-like arithmetic" : "Constant arithmetic" }).Distinct().Take(12).ToArray());
		}
		static bool Branch(int l, int r, Code code) {
			switch (code) {
			case Code.Beq: case Code.Beq_S: return l == r; case Code.Bne_Un: case Code.Bne_Un_S: return l != r;
			case Code.Blt: case Code.Blt_S: return l < r; case Code.Blt_Un: case Code.Blt_Un_S: return (uint)l < (uint)r;
			case Code.Ble: case Code.Ble_S: return l <= r; case Code.Ble_Un: case Code.Ble_Un_S: return (uint)l <= (uint)r;
			case Code.Bgt: case Code.Bgt_S: return l > r; case Code.Bgt_Un: case Code.Bgt_Un_S: return (uint)l > (uint)r;
			case Code.Bge: case Code.Bge_S: return l >= r; default: return (uint)l >= (uint)r;
			}
		}
		static int LocalIndex(Instruction instruction) {
			if (instruction.Operand is Local local) return local.Index;
			switch (instruction.OpCode.Code) {
			case Code.Ldloc_0: case Code.Stloc_0: return 0; case Code.Ldloc_1: case Code.Stloc_1: return 1;
			case Code.Ldloc_2: case Code.Stloc_2: return 2; default: return 3;
			}
		}
		static int ArgumentIndex(Instruction instruction) {
			if (instruction.Operand is Parameter parameter) return parameter.Index;
			switch (instruction.OpCode.Code) { case Code.Ldarg_0: return 0; case Code.Ldarg_1: return 1; case Code.Ldarg_2: return 2; default: return 3; }
		}
		void Record(Value value, MethodDef method, uint offset) {
			if (value.Data is string text && value.Operations.Length > 0) AddString(method, offset, value.Original, text, string.Join(" → ", value.Operations), string.Empty);
		}
		void AddString(MethodDef method, uint offset, string original, string decoded, string transformation, string interpretation) {
			original = Short(original);
			if (decoded.Length == 0 || decoded.Length > StaticLimits.MaximumValueLength) return;
			if (!FirstObservation(method, "string:" + transformation + ":" + decoded)) return;
			if (result.Strings.Count >= StaticLimits.MaximumResults || (long)resultCharacters + original.Length + decoded.Length > 2 * 1024 * 1024) { outputLimited = true; return; }
			resultCharacters += original.Length + decoded.Length;
			var displayed = ConstantTransforms.Display(decoded);
			var item = new DecodedString { Original = displayed != decoded && displayed.Contains("[REDACTED]") ? "[ENCODED SECRET REDACTED]" : ConstantTransforms.Display(original), Decoded = displayed, Transformation = transformation,
				Method = ConstantTransforms.Display(Short(method.FullName)), IlOffset = offset, Reference = method };
			if (interpretation.Length > 0) item.Interpretation = interpretation;
			result.Strings.Add(item);
		}
		void AddCrypto(MethodDef method, uint offset, string algorithm, string property, string value) {
			if (result.Crypto.Count >= StaticLimits.MaximumResults || !FirstObservation(method, "crypto:" + offset + ":" + property)) return;
			result.Crypto.Add(new CryptoObservation { Algorithm = algorithm, Property = property, Value = ConstantTransforms.Display(Short(value)), Method = ConstantTransforms.Display(Short(method.FullName)), IlOffset = offset, Reference = method });
		}
		bool FirstObservation(MethodDef method, string key) {
			if (!seen.TryGetValue(method, out var values)) seen[method] = values = new HashSet<string>(StringComparer.Ordinal);
			return values.Add(key);
		}
		static string Short(string text) => text.Length <= StaticLimits.MaximumValueLength ? text : text.Substring(0, StaticLimits.MaximumValueLength - 30) + " [provenance shortened]";
	}
}
