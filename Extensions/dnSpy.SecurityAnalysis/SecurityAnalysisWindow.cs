using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using dnlib.DotNet;
using dnSpy.Contracts.Controls;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.Documents;
using dnSpy.Contracts.Documents.Tabs;
using dnSpy.Contracts.Documents.TreeView;
using dnSpy.Contracts.Extension;
using dnSpy.Contracts.Menus;
using dnSpy.Contracts.ToolWindows;
using dnSpy.Contracts.ToolWindows.App;
using Microsoft.Win32;

namespace dnSpy.SecurityAnalysis {
	[ExportExtension]
	sealed class SecurityAnalysisExtension : IExtension {
		public IEnumerable<string> MergedResourceDictionaries { get { yield break; } }
		public ExtensionInfo ExtensionInfo => new ExtensionInfo { ShortDescription = "Static security analysis of loaded .NET modules" };
		public void OnEvent(ExtensionEvent @event, object? obj) { }
	}

	[Export(typeof(IToolWindowContentProvider))]
	sealed class SecurityWindowProvider : IToolWindowContentProvider {
		readonly Lazy<SecurityAnalysisService> service;
		SecurityWindow? content;
		[ImportingConstructor]
		SecurityWindowProvider(Lazy<SecurityAnalysisService> service) => this.service = service;
		public IEnumerable<ToolWindowContentInfo> ContentInfos {
			get { yield return new ToolWindowContentInfo(SecurityWindow.Id, AppToolWindowLocation.DefaultHorizontal, AppToolWindowConstants.DEFAULT_CONTENT_ORDER_BOTTOM_ANALYZER); }
		}
		public ToolWindowContent? GetOrCreate(Guid guid) => guid == SecurityWindow.Id ? content ??= new SecurityWindow(service) : null;
	}

	sealed class SecurityWindow : ToolWindowContent, IFocusable {
		public static readonly Guid Id = new Guid("75B64EA0-394D-4EAD-A235-856D554A3114");
		readonly Lazy<SecurityAnalysisService> service;
		public SecurityWindow(Lazy<SecurityAnalysisService> service) => this.service = service;
		public override Guid Guid => Id;
		public override string Title => "Security Analysis";
		public override object? UIObject => service.Value.Control;
		public override IInputElement? FocusedElement => service.Value.Control;
		public override FrameworkElement? ZoomElement => service.Value.Control;
		public bool CanFocus => true;
		public void Focus() => service.Value.Control.Focus();
	}

	[Export]
	sealed class SecurityAnalysisService {
		readonly IDocumentTabService tabs;
		readonly SecurityCoordinator coordinator = new SecurityCoordinator(new ISecurityAnalyzer[] { new HashAnalyzer(), new PeAnalyzer(), new PyInstallerAnalyzer(), new ResourceAnalyzer(), new ConfigurationAnalyzer(), new ApiAnalyzer(), new StringIocAnalyzer(), new BehaviorAnalyzer(), new BehaviorChainAnalyzer() });
		readonly TextBlock status = new TextBlock { Margin = new Thickness(4) };
		readonly TextBox overview = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
		readonly ListView findings = new ListView();
		readonly ListView iocs = new ListView();
		readonly ListView resources = new ListView();
		readonly ListView evidence = new ListView();
		readonly ListView pyInstallerEntries = new ListView();
		readonly TextBox details = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MinHeight = 65, MaxHeight = 140, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
		CancellationTokenSource? cancellation;
		ModuleDef? selectedModule;
		string selectedPath = string.Empty;
		SecurityResult? current;
		public FrameworkElement Control { get; }

		[ImportingConstructor]
		SecurityAnalysisService(IDocumentTabService tabs) {
			this.tabs = tabs;
			var root = new DockPanel();
			var toolbar = new WrapPanel { Orientation = Orientation.Horizontal };
			var refresh = new Button { Content = "Analyze selected module", Margin = new Thickness(3) };
			refresh.Click += (_, _) => AnalyzeSelection();
			toolbar.Children.Add(refresh);
			var cancel = new Button { Content = "Cancel", Margin = new Thickness(3) };
			cancel.Click += (_, _) => cancellation?.Cancel();
			toolbar.Children.Add(cancel);
			var copyMd5 = new Button { Content = "Copy MD5", Margin = new Thickness(3) };
			copyMd5.Click += (_, _) => { var hash = current?.Md5; if (!string.IsNullOrEmpty(hash)) Clipboard.SetText(hash); };
			toolbar.Children.Add(copyMd5);
			var copySha1 = new Button { Content = "Copy SHA-1", Margin = new Thickness(3) };
			copySha1.Click += (_, _) => { var hash = current?.Sha1; if (!string.IsNullOrEmpty(hash)) Clipboard.SetText(hash); };
			toolbar.Children.Add(copySha1);
			var copyHash = new Button { Content = "Copy SHA-256", Margin = new Thickness(3) };
			copyHash.Click += (_, _) => { var hash = current?.Sha256; if (!string.IsNullOrEmpty(hash)) Clipboard.SetText(hash); };
			toolbar.Children.Add(copyHash);
			var copyIoc = new Button { Content = "Copy IOCs", Margin = new Thickness(3) };
			copyIoc.Click += (_, _) => { if (current is not null) Clipboard.SetText(string.Join(Environment.NewLine, current.Iocs.Select(i => i.Value).Distinct())); };
			toolbar.Children.Add(copyIoc);
			var copySelectedIoc = new Button { Content = "Copy selected IOC", Margin = new Thickness(3) };
			copySelectedIoc.Click += (_, _) => { if (iocs.SelectedItem is SecurityIoc ioc) Clipboard.SetText(ioc.Value); };
			toolbar.Children.Add(copySelectedIoc);
			var exportIocs = new Button { Content = "Export IOCs", Margin = new Thickness(3) };
			exportIocs.Click += (_, _) => ExportIocs();
			toolbar.Children.Add(exportIocs);
			var export = new Button { Content = "Export report", Margin = new Thickness(3) };
			export.Click += (_, _) => ExportReport();
			toolbar.Children.Add(export);
			DockPanel.SetDock(toolbar, Dock.Top);
			root.Children.Add(toolbar);
			DockPanel.SetDock(status, Dock.Top);
			root.Children.Add(status);
			DockPanel.SetDock(details, Dock.Bottom);
			root.Children.Add(details);
			var tabsControl = new TabControl();
			tabsControl.Items.Add(new TabItem { Header = "Overview / Hashes", Content = overview });
			findings.View = MakeColumns(("Severity", "Severity", 75), ("Confidence", "Confidence", 85), ("Category", "Category", 125), ("Finding", "Title", 220), ("Evidence", "Evidence", 390));
			findings.SelectionChanged += (_, _) => ShowDetails();
			findings.MouseDoubleClick += (_, _) => FollowFinding();
			tabsControl.Items.Add(new TabItem { Header = "Findings", Content = findings });
			evidence.View = MakeColumns(("Evidence", "Description", 190), ("Value", "Value", 400), ("Method", "Method", 300));
			evidence.MouseDoubleClick += (_, _) => { if (evidence.SelectedItem is SecurityEvidence item && item.Reference is not null) FollowEvidence(item.Reference, item.IlOffset); };
			tabsControl.Items.Add(new TabItem { Header = "Finding evidence", Content = evidence });
			iocs.View = MakeColumns(("Type", "Kind", 120), ("IOC", "Value", 450), ("Details", "Details", 250));
			iocs.MouseDoubleClick += (_, _) => {
				if (iocs.SelectedItem is SecurityIoc ioc && ioc.Reference is not null) FollowEvidence(ioc.Reference, ioc.IlOffset);
			};
			tabsControl.Items.Add(new TabItem { Header = "IOCs", Content = iocs });
			resources.View = MakeColumns(("Resource", "Name", 320), ("Type", "Kind", 130), ("Size", "Size", 110), ("SHA-256", "Sha256", 440), ("Entropy", "Entropy", 90));
			tabsControl.Items.Add(new TabItem { Header = "Resources", Content = resources });
			pyInstallerEntries.View = MakeColumns(("Entry", "Name", 400), ("Type", "Type", 65), ("Offset", "Offset", 120), ("Size", "Size", 110), ("Uncompressed", "UncompressedSize", 115));
			tabsControl.Items.Add(new TabItem { Header = "PyInstaller", Content = pyInstallerEntries });
			var extract = new Button { Content = "Extract selected resource...", Margin = new Thickness(3) };
			extract.Click += async (_, _) => await ExtractResourceAsync();
			toolbar.Children.Add(extract);
			root.Children.Add(tabsControl);
			Control = root;
			status.Text = "Select a module and choose Analyze selected module. API references are indicators, not a malware verdict.";
			tabs.DocumentModified += (_, e) => {
				coordinator.Invalidate();
				if (!AffectsSelectedModule(e.Documents)) return;
				CancelCurrentAnalysis();
				status.Text = "Selected module changed. Run analysis again.";
			};
			tabs.DocumentTreeView.DocumentService.CollectionChanged += (_, e) => {
				if (e.Type == NotifyDocumentCollectionType.Add) return;
				coordinator.Invalidate();
				if (!AffectsSelectedModule(e.Documents)) return;
				CancelCurrentAnalysis();
				status.Text = "Selected module was removed. Select a module and run analysis again.";
			};
		}

		bool AffectsSelectedModule(IDsDocument[] documents) => documents.Any(document =>
			selectedModule is not null && (document.ModuleDef == selectedModule || document.AssemblyDef?.Modules.Contains(selectedModule) == true) ||
			selectedPath.Length > 0 && string.Equals(document.Filename, selectedPath, StringComparison.OrdinalIgnoreCase));

		void CancelCurrentAnalysis() {
			var source = cancellation;
			cancellation = null;
			source?.Cancel();
		}

		static GridView MakeColumns(params (string header, string binding, double width)[] columns) {
			var view = new GridView();
			foreach (var column in columns)
				view.Columns.Add(new GridViewColumn { Header = column.header, DisplayMemberBinding = new System.Windows.Data.Binding(column.binding), Width = column.width });
			return view;
		}

		void ShowDetails() {
			if (findings.SelectedItem is SecurityFinding finding) {
				details.Text = finding.RuleId + " | " + finding.Explanation + Environment.NewLine + finding.Evidence + Environment.NewLine + finding.Method;
				evidence.ItemsSource = finding.EvidenceItems.ToArray();
			}
			else evidence.ItemsSource = null;
		}

		void ExportReport() {
			if (current is null) return;
			var dialog = new SaveFileDialog { Filter = "Markdown|*.md|JSON|*.json|Plain text|*.txt", FileName = "security-analysis" };
			if (dialog.ShowDialog() != true) return;
			try { File.WriteAllText(dialog.FileName, SecurityReportWriter.Write(current, dialog.FilterIndex)); status.Text = "Report exported: " + dialog.FileName; }
			catch (Exception ex) { Debug.WriteLine("Security report export: " + ex); status.Text = "Report export failed: " + ex.Message; }
		}

		void ExportIocs() {
			if (current is null) return;
			var dialog = new SaveFileDialog { Filter = "Markdown|*.md|JSON|*.json|Plain text|*.txt", FileName = "security-iocs" };
			if (dialog.ShowDialog() != true) return;
			try {
				File.WriteAllText(dialog.FileName, SecurityReportWriter.WriteIocs(current, dialog.FilterIndex));
				status.Text = "IOCs exported: " + dialog.FileName;
			} catch (Exception ex) { Debug.WriteLine("Security IOC export: " + ex); status.Text = "IOC export failed: " + ex.Message; }
		}

		async Task ExtractResourceAsync() {
			if (resources.SelectedItem is not SecurityResource resource || resource.Source is null) { status.Text = "Select a resource first."; return; }
			if (resource.Size > AnalysisLimits.MaximumResourceBytes) { status.Text = "Resource exceeds the 64 MiB extraction limit."; return; }
			var safeName = Path.GetFileName(resource.Name.Replace('/', '\\'));
			foreach (var invalid in Path.GetInvalidFileNameChars()) safeName = safeName.Replace(invalid, '_');
			if (string.IsNullOrWhiteSpace(safeName) || safeName == "." || safeName == "..") safeName = "resource.bin";
			var dialog = new SaveFileDialog { FileName = safeName };
			if (dialog.ShowDialog() != true) return;
			try {
				var destination = dialog.FileName;
				await Task.Run(() => {
					using var input = resource.Source.CreateReader().AsStream();
					if (input.Length > AnalysisLimits.MaximumResourceBytes) throw new InvalidDataException("Resource size limit exceeded.");
					using var output = new FileStream(destination, FileMode.Create, FileAccess.Write);
					var buffer = new byte[65536];
					long total = 0;
					int read;
					while ((read = input.Read(buffer, 0, buffer.Length)) > 0) {
						total += read;
						if (total > AnalysisLimits.MaximumResourceBytes) throw new InvalidDataException("Resource size limit exceeded.");
						output.Write(buffer, 0, read);
					}
				});
				status.Text = "Resource saved: " + dialog.FileName;
			} catch (Exception ex) { Debug.WriteLine("Security resource extract: " + ex); status.Text = "Extraction failed: " + ex.Message; }
		}

		void FollowFinding() {
			if (findings.SelectedItem is not SecurityFinding finding || finding.Reference is null) return;
			FollowEvidence(finding.Reference, finding.IlOffset);
		}

		void FollowEvidence(object reference, uint? ilOffset) {
			tabs.FollowReference(reference, false, true, args => {
				if (args.HasMovedCaret || !args.Success || ilOffset is null || reference is not MethodDef method) return;
				if (args.Tab.TryGetDocumentViewer() is { } viewer && viewer.GetMethodDebugService().FindByCodeOffset(method, ilOffset.Value) is { } statement)
					viewer.MoveCaretToPosition(statement.Statement.TextSpan.Start);
			});
		}

		public void AnalyzeSelection() {
			var nodes = tabs.DocumentTreeView.TreeView.SelectedItems.OfType<DocumentTreeNodeData>().ToArray();
			var module = nodes.Select(n => n.GetModule()).FirstOrDefault(m => m is not null);
			var path = module?.Location ?? nodes.OfType<DsDocumentNode>().Select(n => n.Document.Filename).FirstOrDefault() ?? string.Empty;
			if (string.IsNullOrEmpty(path) && module is null) { status.Text = "Select a module or PE document in the document tree."; return; }
			CancelCurrentAnalysis();
			selectedModule = module;
			selectedPath = path;
			var source = cancellation = new CancellationTokenSource();
			source.CancelAfter(TimeSpan.FromSeconds(AnalysisLimits.AnalysisTimeoutSeconds));
			status.Text = "Analyzing " + (module?.Name ?? Path.GetFileName(path)) + "...";
			_ = RunAnalysis(module, path, source);
		}

		async Task RunAnalysis(ModuleDef? module, string path, CancellationTokenSource source) {
			try {
				var progress = new Progress<string>(name => { if (source == cancellation) status.Text = "Analyzing: " + name; });
				var result = await Task.Run(() => coordinator.Analyze(path, module, source.Token, name => ((IProgress<string>)progress).Report(name)), source.Token);
				if (source != cancellation) return;
				current = result;
				findings.ItemsSource = result.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category).ToArray();
				iocs.ItemsSource = result.Iocs.GroupBy(i => i.Kind + "\0" + i.Value).Select(g => g.First()).ToArray();
				resources.ItemsSource = result.Resources.ToArray();
				pyInstallerEntries.ItemsSource = result.PyInstallerEntries.ToArray();
				overview.Text = "File: " + result.FileName + "\r\nPath: " + result.FullPath + "\r\nSize: " + result.FileSize +
					"\r\nAssembly: " + result.AssemblyName + "\r\nModule: " + result.ModuleName + "\r\nCLR: " + result.RuntimeVersion +
					"\r\nMD5: " + result.Md5 + "\r\nSHA-1: " + result.Sha1 + "\r\nSHA-256: " + result.Sha256 + "\r\n\r\n" + result.PeInformation +
					"\r\n" + result.PyInstallerInformation + "\r\n" + result.ConfigurationInformation +
					(result.AnalysisErrors.Count == 0 ? "" : "\r\nAnalysis limits/errors:\r\n" + string.Join("\r\n", result.AnalysisErrors));
				status.Text = (result.AnalysisErrors.Count == 0 ? "Findings: " : "Partial analysis (" + result.AnalysisErrors.Count + " errors/limits). Findings: ") +
					string.Join("  ", Enum.GetValues(typeof(SecuritySeverity)).Cast<SecuritySeverity>().Reverse().Select(s => result.Findings.Count(f => f.Severity == s) + " " + s));
			} catch (OperationCanceledException) { if (source == cancellation) status.Text = "Analysis canceled or timed out."; }
			catch (Exception ex) { Debug.WriteLine("Security Analysis: " + ex); if (source == cancellation) status.Text = "Analysis failed; see debug output."; }
			finally {
				if (source == cancellation)
					cancellation = null;
				source.Dispose();
			}
		}
	}

	[ExportMenuItem(OwnerGuid = MenuConstants.APP_MENU_EDIT_GUID, Header = "Security Analysis", Group = MenuConstants.GROUP_APP_MENU_EDIT_FIND, Order = 21)]
	sealed class SecurityAnalysisCommand : MenuItemBase {
		readonly IDsToolWindowService windows;
		readonly SecurityAnalysisService service;
		[ImportingConstructor]
		SecurityAnalysisCommand(IDsToolWindowService windows, SecurityAnalysisService service) { this.windows = windows; this.service = service; }
		public override void Execute(IMenuItemContext context) { windows.Show(SecurityWindow.Id); service.AnalyzeSelection(); }
	}
}
