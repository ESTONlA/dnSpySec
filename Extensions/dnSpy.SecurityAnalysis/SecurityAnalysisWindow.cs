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
		readonly SecurityCoordinator coordinator = new SecurityCoordinator(new ISecurityAnalyzer[] { new HashAnalyzer(), new PeAnalyzer(), new ResourceAnalyzer(), new ApiAnalyzer(), new StringIocAnalyzer(), new BehaviorAnalyzer() });
		readonly TextBlock status = new TextBlock { Margin = new Thickness(4) };
		readonly TextBox overview = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
		readonly ListView findings = new ListView();
		readonly ListView iocs = new ListView();
		readonly ListView resources = new ListView();
		readonly TextBox details = new TextBox { IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MinHeight = 65, MaxHeight = 140, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
		CancellationTokenSource? cancellation;
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
			iocs.View = MakeColumns(("Type", "Kind", 120), ("IOC", "Value", 450), ("Details", "Details", 250));
			iocs.MouseDoubleClick += (_, _) => {
				if (iocs.SelectedItem is SecurityIoc ioc && ioc.Reference is not null) FollowEvidence(ioc.Reference, ioc.IlOffset);
			};
			tabsControl.Items.Add(new TabItem { Header = "IOCs", Content = iocs });
			resources.View = MakeColumns(("Resource", "Name", 320), ("Type", "Kind", 130), ("Size", "Size", 110), ("SHA-256", "Sha256", 440), ("Entropy", "Entropy", 90));
			tabsControl.Items.Add(new TabItem { Header = "Resources", Content = resources });
			var extract = new Button { Content = "Extract selected resource...", Margin = new Thickness(3) };
			extract.Click += (_, _) => ExtractResource();
			toolbar.Children.Add(extract);
			root.Children.Add(tabsControl);
			Control = root;
			status.Text = "Select a module and choose Analyze selected module. API references are indicators, not a malware verdict.";
			tabs.DocumentModified += (_, _) => { coordinator.Invalidate(); cancellation?.Cancel(); status.Text = "Document changed. Run analysis again."; };
			tabs.DocumentTreeView.DocumentService.CollectionChanged += (_, _) => { coordinator.Invalidate(); cancellation?.Cancel(); };
		}

		static GridView MakeColumns(params (string header, string binding, double width)[] columns) {
			var view = new GridView();
			foreach (var column in columns)
				view.Columns.Add(new GridViewColumn { Header = column.header, DisplayMemberBinding = new System.Windows.Data.Binding(column.binding), Width = column.width });
			return view;
		}

		void ShowDetails() {
			if (findings.SelectedItem is SecurityFinding finding)
				details.Text = finding.RuleId + " | " + finding.Explanation + Environment.NewLine + finding.Evidence + Environment.NewLine + finding.Method;
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
			var dialog = new SaveFileDialog { Filter = "Plain text|*.txt", FileName = "security-iocs.txt" };
			if (dialog.ShowDialog() != true) return;
			try {
				File.WriteAllLines(dialog.FileName, current.Iocs.Select(i => i.Kind + "\t" + i.Value + "\t" + i.Details).Distinct());
				status.Text = "IOCs exported: " + dialog.FileName;
			} catch (Exception ex) { Debug.WriteLine("Security IOC export: " + ex); status.Text = "IOC export failed: " + ex.Message; }
		}

		void ExtractResource() {
			if (resources.SelectedItem is not SecurityResource resource || resource.Source is null) { status.Text = "Select a resource first."; return; }
			var dialog = new SaveFileDialog { FileName = Path.GetFileName(resource.Name) };
			if (dialog.ShowDialog() != true) return;
			try {
				using var input = resource.Source.CreateReader().AsStream();
				using var output = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write);
				input.CopyTo(output);
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
			var module = tabs.DocumentTreeView.TreeView.SelectedItems.OfType<DocumentTreeNodeData>().Select(n => n.GetModule()).FirstOrDefault(m => m is not null);
			if (module is null) { status.Text = "Select a module or member in the document tree."; return; }
			cancellation?.Cancel();
			var source = cancellation = new CancellationTokenSource();
			status.Text = "Analyzing " + module.Name + "...";
			_ = RunAnalysis(module, source);
		}

		async Task RunAnalysis(ModuleDef module, CancellationTokenSource source) {
			try {
				var progress = new Progress<string>(name => { if (source == cancellation) status.Text = "Analyzing: " + name; });
				var result = await Task.Run(() => coordinator.Analyze(module, source.Token, name => ((IProgress<string>)progress).Report(name)), source.Token);
				if (source != cancellation) return;
				current = result;
				findings.ItemsSource = result.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category).ToArray();
				iocs.ItemsSource = result.Iocs.GroupBy(i => i.Kind + "\0" + i.Value).Select(g => g.First()).ToArray();
				resources.ItemsSource = result.Resources.ToArray();
				overview.Text = "File: " + result.FileName + "\r\nPath: " + result.FullPath + "\r\nSize: " + result.FileSize +
					"\r\nAssembly: " + result.AssemblyName + "\r\nModule: " + result.ModuleName + "\r\nCLR: " + result.RuntimeVersion +
					"\r\nMD5: " + result.Md5 + "\r\nSHA-1: " + result.Sha1 + "\r\nSHA-256: " + result.Sha256 + "\r\n\r\n" + result.PeInformation;
				status.Text = "Findings: " + string.Join("  ", Enum.GetValues(typeof(SecuritySeverity)).Cast<SecuritySeverity>().Reverse().Select(s => result.Findings.Count(f => f.Severity == s) + " " + s));
			} catch (OperationCanceledException) { if (source == cancellation) status.Text = "Analysis canceled."; }
			catch (Exception ex) { Debug.WriteLine("Security Analysis: " + ex); if (source == cancellation) status.Text = "Analysis failed; see debug output."; }
			finally { source.Dispose(); }
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
