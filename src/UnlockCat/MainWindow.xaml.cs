using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using UnlockCat.Core;

namespace UnlockCat;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<OwnerRow> _rows = [];
    private bool _busy;
    private TargetKind _lastKind;
    private string? _lastTarget;

    public MainWindow()
    {
        InitializeComponent();
        ResultsGrid.ItemsSource = _rows;
        RefreshDrives();
        ProcessControl.TryEnableDebugPrivilege(out _);
    }

    private void RefreshDrives()
    {
        var choices = DriveInfo.GetDrives()
            .Where(d => d.IsReady)
            .OrderBy(d => d.DriveType == DriveType.Removable ? 0 : 1)
            .ThenBy(d => d.Name)
            .Select(d => new DriveChoice(
                d.Name,
                $"{d.Name}   {SafeDriveLabel(d)}   ({d.DriveType})"))
            .ToArray();
        VolumeBox.ItemsSource = choices;
        if (choices.Length > 0)
            VolumeBox.SelectedItem = choices.FirstOrDefault(c => c.Display.Contains("Removable")) ?? choices[0];
    }

    private static string SafeDriveLabel(DriveInfo drive)
    {
        try { return drive.VolumeLabel; }
        catch { return string.Empty; }
    }

    private void BrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "잠긴 파일 선택",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) == true)
            FilePathBox.Text = dialog.FileName;
    }

    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "검사할 폴더 선택",
            Multiselect = false
        };
        if (dialog.ShowDialog(this) == true)
            FilePathBox.Text = dialog.FolderName;
    }

    private void TargetTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.Source, TargetTabs))
            return;
        if (TargetTabs.SelectedIndex == 1 && VolumeBox is not null)
            RefreshDrives();
    }

    private (TargetKind Kind, string Target) CurrentTarget()
    {
        return TargetTabs.SelectedIndex switch
        {
            0 => PathTarget(FilePathBox.Text.Trim()),
            1 => (TargetKind.Volume, VolumeBox.SelectedItem is DriveChoice drive &&
                                      VolumeBox.Text == drive.Display ? drive.Root : VolumeBox.Text.Trim()),
            2 => (TargetKind.Port, PortBox.Text.Trim()),
            _ => throw new InvalidOperationException("검사 대상을 선택하세요.")
        };
    }

    private static (TargetKind Kind, string Target) PathTarget(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return (TargetKind.File, path);

        var attributes = File.GetAttributes(path);
        return ((attributes & FileAttributes.Directory) != 0 ? TargetKind.Directory : TargetKind.File, path);
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        try
        {
            var (kind, target) = CurrentTarget();
            if (string.IsNullOrWhiteSpace(target))
                throw new ArgumentException("검사할 대상 값을 입력하세요.");
            await RunScanAsync(kind, target);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private async Task RunScanAsync(TargetKind kind, string target)
    {
        _lastTarget = null;
        _rows.Clear();
        EvidenceBox.Clear();
        SetBusy(true, "점유 프로세스를 검색 중입니다…");
        try
        {
            var scan = await Task.Run(() => ScanCore(kind, target));
            _lastKind = kind;
            _lastTarget = target;
            _rows.Clear();
            foreach (var row in scan.Rows)
                _rows.Add(row);

            var coverage = scan.IsComplete ? "전체 검색 완료" : "일부 프로세스 접근 불가 — 결과가 불완전할 수 있음";
            StatusText.Text = $"{_rows.Count}개 프로세스 발견 · {coverage}";
            if (!string.IsNullOrWhiteSpace(scan.Diagnostics))
                AppendLog(scan.Diagnostics);
            else if (_rows.Count == 0)
                AppendLog("점유 프로세스를 찾지 못했습니다. 파일 시스템 또는 보호된 프로세스의 잠금은 검색되지 않을 수 있습니다.");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private static ScanView ScanCore(TargetKind kind, string target)
    {
        var evidence = new Dictionary<int, List<string>>();
        var exactServices = new Dictionary<int, HashSet<string>>();
        var confirmedPids = new HashSet<int>();
        var complete = true;
        var diagnostics = string.Empty;

        if (kind == TargetKind.Port)
        {
            var unattributed = new List<string>();
            foreach (var owner in new PortScanner().Scan(target))
            {
                var remote = owner.RemoteEndPoint is null ? "" : $" → {owner.RemoteEndPoint}";
                if (owner.ProcessId <= 0)
                {
                    unattributed.Add($"{owner.Protocol} {owner.LocalEndPoint} {owner.TcpState}");
                    continue;
                }
                string moduleLabel = "";
                try
                {
                    var module = PortModuleResolver.Resolve(owner);
                    if (module.HasModule)
                        moduleLabel = $" · 소유 모듈 {module.ModuleName}";
                }
                catch (Exception ex)
                {
                    diagnostics += (diagnostics.Length > 0 ? Environment.NewLine : "") +
                        $"PID {owner.ProcessId} 모듈 이름 조회 실패: {ex.Message}";
                }
                AddEvidence(owner.ProcessId,
                    $"{owner.Protocol} {owner.LocalEndPoint}{remote} · {owner.TcpState?.ToString() ?? "UDP"} · {owner.MatchKind}{moduleLabel}");
                if (owner.MatchKind != PortMatchKind.PotentialDualStack)
                    confirmedPids.Add(owner.ProcessId);
            }
            if (unattributed.Count > 0)
            {
                complete = false;
                diagnostics += (diagnostics.Length > 0 ? Environment.NewLine : "") +
                    "소유 PID가 없는 Windows TCP/UDP 항목: " +
                    string.Join(", ", unattributed.Distinct());
            }
        }
        else
        {
            var result = kind switch
            {
                TargetKind.File => FileLockScanner.ScanFile(target),
                TargetKind.Directory => FileLockScanner.ScanDirectory(target),
                TargetKind.Volume => FileLockScanner.ScanVolume(target),
                _ => throw new InvalidOperationException("알 수 없는 검사 대상입니다.")
            };
            foreach (var owner in result.Owners)
            {
                AddEvidence(owner.Pid, $"{owner.Kind}: {owner.EvidencePath}" +
                    (string.IsNullOrWhiteSpace(owner.ServiceName) ? "" : $" · 서비스 {owner.ServiceName}"));
                confirmedPids.Add(owner.Pid);
                if (!string.IsNullOrWhiteSpace(owner.ServiceName))
                {
                    if (!exactServices.TryGetValue(owner.Pid, out var names))
                        exactServices.Add(owner.Pid, names = new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    names.Add(owner.ServiceName);
                }
            }
            complete = result.IsComplete;
            diagnostics = string.Join(Environment.NewLine, result.Errors);
            if (result.InaccessibleProcessCount > 0)
                diagnostics = $"접근할 수 없는 프로세스 {result.InaccessibleProcessCount}개." +
                    (diagnostics.Length > 0 ? Environment.NewLine + diagnostics : "");
        }

        var servicesByPid = new Dictionary<int, ServiceInfo[]>();
        if (evidence.Count > 0)
        {
            try
            {
                servicesByPid = ServiceControl.ListServices()
                    .Where(s => s.ProcessId > 0 && s.State != ServiceState.Stopped)
                    .GroupBy(s => s.ProcessId)
                    .ToDictionary(g => g.Key, g => g.ToArray());
            }
            catch (Exception ex)
            {
                complete = false;
                diagnostics += (diagnostics.Length > 0 ? Environment.NewLine : "") +
                    $"서비스 정보 조회 실패: {ex.Message}";
            }
        }

        var rows = evidence
            .OrderBy(kv => kv.Key)
            .Select(kv => new OwnerRow(
                ProcessControl.Describe(kv.Key),
                kv.Value.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                servicesByPid.GetValueOrDefault(kv.Key) ?? [],
                exactServices.GetValueOrDefault(kv.Key) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                confirmedPids.Contains(kv.Key)))
            .ToArray();
        return new ScanView(rows, complete, diagnostics);

        void AddEvidence(int pid, string item)
        {
            if (!evidence.TryGetValue(pid, out var list))
                evidence.Add(pid, list = []);
            list.Add(item);
        }
    }

    private async void KillSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected = ResultsGrid.SelectedItems.Cast<OwnerRow>().ToArray();
        await KillAsync(selected);
    }

    private async void KillAll_Click(object sender, RoutedEventArgs e)
    {
        await KillAsync(_rows.ToArray());
    }

    private async Task KillAsync(OwnerRow[] selected)
    {
        if (_busy || selected.Length == 0 || _lastTarget is null)
            return;

        SetBusy(true, "종료 또는 탐색기 재시작 전에 점유 상태를 다시 확인 중입니다…");
        try
        {
            var kind = _lastKind;
            var target = _lastTarget;
            var messages = await Task.Run(() =>
            {
                // The resource may have been released or the PID reused since the scan.
                // Recheck ownership, then ProcessControl checks creation time on its kill handle.
                var currentPids = ScanCore(kind, target).Rows
                    .Where(r => r.ConfirmedOwnership).Select(r => r.ProcessId).ToHashSet();
                var results = new List<string>();
                foreach (var row in selected.DistinctBy(r => r.ProcessId))
                {
                    if (!row.ConfirmedOwnership)
                    {
                        results.Add($"PID {row.ProcessId}: IPv6 소켓의 IPv4 점유는 확인되지 않아 건너뜀.");
                        continue;
                    }
                    if (!currentPids.Contains(row.ProcessId))
                    {
                        results.Add($"PID {row.ProcessId}: 대상 점유가 더 이상 확인되지 않아 건너뜀.");
                        continue;
                    }

                    var result = ProcessControl.TerminateOrRestartExplorer(row.Process, TimeSpan.FromSeconds(10));
                    results.Add($"PID {row.ProcessId} ({row.ProcessName}): {result.Message}");
                }
                return results;
            });
            foreach (var message in messages)
                AppendLog(message);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            SetBusy(false);
        }

        try
        {
            await RunScanAsync(_lastKind, _lastTarget);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private async void StopServices_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _lastTarget is null)
            return;

        var selectedRows = ResultsGrid.SelectedItems.Cast<OwnerRow>()
            .Where(r => r.ConfirmedOwnership).ToArray();
        var candidates = selectedRows.SelectMany(r => r.Services)
            .DistinctBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s.Name)
            .ToArray();
        if (candidates.Length == 0)
            return;

        var preferred = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in selectedRows)
        {
            preferred.UnionWith(row.ExactServiceNames);
            if (row.Services.Length == 1)
                preferred.Add(row.Services[0].Name);
        }

        var chosen = PickServices(candidates, preferred);
        if (chosen.Length == 0)
            return;

        var kind = _lastKind;
        var target = _lastTarget;
        SetBusy(true, "서비스 중지 전에 점유 상태를 다시 확인 중입니다…");
        try
        {
            var messages = await Task.Run(() =>
            {
                var current = ScanCore(kind, target);
                var currentRows = current.Rows.ToDictionary(r => r.ProcessId);
                var results = new List<string>();
                foreach (var service in chosen)
                {
                    if (!currentRows.TryGetValue(service.ProcessId, out var row) || !row.ConfirmedOwnership ||
                        !row.Services.Any(s => s.Name.Equals(service.Name, StringComparison.OrdinalIgnoreCase)))
                    {
                        results.Add($"서비스 {service.Name}: 현재 점유 프로세스와 연결되지 않아 건너뜀.");
                        continue;
                    }

                    var result = ServiceControl.StopService(service, TimeSpan.FromSeconds(20));
                    results.Add($"서비스 {service.Name}: {result.Message}");
                }
                return results;
            });
            foreach (var message in messages)
                AppendLog(message);
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            SetBusy(false);
        }

        try { await RunScanAsync(kind, target); }
        catch (Exception ex) { ShowError(ex); }
    }

    private ServiceInfo[] PickServices(ServiceInfo[] candidates, HashSet<string> preferred)
    {
        var window = new Window
        {
            Title = "중지할 서비스 선택",
            Owner = this,
            Width = 570,
            Height = Math.Min(520, 160 + candidates.Length * 38),
            MinWidth = 450,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.CanResize
        };
        var panel = new DockPanel { Margin = new Thickness(16) };
        var footer = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var stop = new Button { Content = "선택한 서비스 중지", IsDefault = true };
        var cancel = new Button { Content = "취소", IsCancel = true, Margin = new Thickness(0) };
        footer.Children.Add(stop);
        footer.Children.Add(cancel);
        DockPanel.SetDock(footer, Dock.Bottom);
        panel.Children.Add(footer);
        var intro = new TextBlock
        {
            Text = "공유 프로세스에 여러 서비스가 있을 수 있습니다. 중지할 서비스를 선택하세요.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 12)
        };
        DockPanel.SetDock(intro, Dock.Top);
        panel.Children.Add(intro);
        var list = new StackPanel();
        var boxes = new List<(CheckBox Box, ServiceInfo Service)>();
        foreach (var service in candidates)
        {
            var box = new CheckBox
            {
                Content = $"{service.Name} — {service.DisplayName} (PID {service.ProcessId})",
                IsChecked = preferred.Contains(service.Name),
                Foreground = (System.Windows.Media.Brush)FindResource("TextBrush"),
                Margin = new Thickness(0, 0, 0, 9)
            };
            list.Children.Add(box);
            boxes.Add((box, service));
        }
        panel.Children.Add(new ScrollViewer { Content = list, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        window.Content = panel;
        stop.Click += (_, _) => window.DialogResult = true;
        if (window.ShowDialog() != true)
            return [];
        return boxes.Where(pair => pair.Box.IsChecked == true).Select(pair => pair.Service).ToArray();
    }

    private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EvidenceBox is null || KillSelectedButton is null || StopServiceButton is null)
            return;
        var selected = ResultsGrid.SelectedItem as OwnerRow;
        EvidenceBox.Text = selected is null ? "" : string.Join(Environment.NewLine, selected.Evidence);
        UpdateButtons();
    }

    private void SetBusy(bool busy, string? status = null)
    {
        _busy = busy;
        if (status is not null)
            StatusText.Text = status;
        ScanButton.IsEnabled = !busy;
        TargetTabs.IsEnabled = !busy;
        UpdateButtons();
    }

    private void UpdateButtons()
    {
        KillSelectedButton.IsEnabled = !_busy &&
            ResultsGrid.SelectedItems.Cast<OwnerRow>().Any(row => row.ConfirmedOwnership);
        KillAllButton.IsEnabled = !_busy && _rows.Any(row => row.ConfirmedOwnership);
        StopServiceButton.IsEnabled = !_busy &&
            ResultsGrid.SelectedItems.Cast<OwnerRow>().Any(row => row.ConfirmedOwnership && row.Services.Length > 0);
    }

    private void ShowError(Exception ex)
    {
        StatusText.Text = "작업 실패";
        AppendLog(ex.Message);
        MessageBox.Show(this, ex.Message, "UnlockCat", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void AppendLog(string message)
    {
        LogBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        LogBox.ScrollToEnd();
    }

    private sealed record DriveChoice(string Root, string Display);
    private sealed record ScanView(OwnerRow[] Rows, bool IsComplete, string Diagnostics);

    private sealed class OwnerRow
    {
        public OwnerRow(ProcessInfo process, string[] evidence, ServiceInfo[] services,
            HashSet<string> exactServiceNames, bool confirmedOwnership)
        {
            Process = process;
            Evidence = evidence;
            Services = services;
            ExactServiceNames = exactServiceNames;
            ConfirmedOwnership = confirmedOwnership;
        }

        public ProcessInfo Process { get; }
        public int ProcessId => Process.ProcessId;
        public string ProcessName => Process.Name;
        public string ImagePath => Process.ImagePath ?? "(조회 불가)";
        public string Summary => Evidence.Length == 1 ? Evidence[0] : $"{Evidence[0]} 외 {Evidence.Length - 1}개";
        public string[] Evidence { get; }
        public ServiceInfo[] Services { get; }
        public HashSet<string> ExactServiceNames { get; }
        public bool ConfirmedOwnership { get; }
        public string ServiceNames => Services.Length == 0 ? "" :
            string.Join(", ", Services.Select(s => s.Name +
                (ExactServiceNames.Contains(s.Name) ? " (확인됨)" : "")));
        public string ProcessStatus => !ConfirmedOwnership ? "점유 가능성만 있음" :
            ProcessId is 0 or 4 ? "시스템 보호" :
            Process.IsCritical == true ? "중요 프로세스" :
            !Process.CanTerminate ? "신원 확인 불가" :
            ProcessControl.IsWindowsExplorerImage(Process.ImagePath) ? "종료 후 재시작" : "종료 가능";
    }

    private enum TargetKind { File, Directory, Volume, Port }
}
