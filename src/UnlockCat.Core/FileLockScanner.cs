using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace UnlockCat.Core;

public sealed record LockOwner(
    int Pid,
    string EvidencePath,
    string Kind,
    DateTime? StartedAtUtc = null,
    string? ServiceName = null);

public sealed record InaccessibleProcess(int Pid, string Reason);

public sealed class LockScanResult
{
    public LockScanResult(
        IReadOnlyList<LockOwner> owners,
        IReadOnlyList<InaccessibleProcess> inaccessibleProcesses,
        IReadOnlyList<string> errors)
    {
        Owners = owners;
        InaccessibleProcesses = inaccessibleProcesses;
        Errors = errors;
    }

    public IReadOnlyList<LockOwner> Owners { get; }
    public IReadOnlyList<InaccessibleProcess> InaccessibleProcesses { get; }
    public int InaccessibleProcessCount => InaccessibleProcesses.Select(process => process.Pid).Distinct().Count();
    public IReadOnlyList<string> Errors { get; }
    public bool IsComplete => InaccessibleProcesses.Count == 0 && Errors.Count == 0;
}

/// <summary>
/// Finds file and volume users through Restart Manager and the documented Process
/// Snapshotting API. A scan is a point-in-time observation; callers should scan again
/// after termination to check that a resource was actually released.
/// </summary>
public static class FileLockScanner
{
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint PssCaptureHandles = 0x00000004;
    private const uint PssCaptureHandleNameInformation = 0x00000008;
    private const uint PssCaptureVaSpace = 0x00000800;
    private const uint PssCaptureVaSpaceSectionInformation = 0x00001000;
    private const uint PssWalkVaSpace = 1;
    private const uint PssWalkHandles = 2;
    private const uint PssHandleHaveName = 0x02;
    private const uint ErrorNoMoreItems = 259;
    private const uint ErrorMoreData = 234;
    private const uint ErrorInvalidParameter = 87;
    private const uint ErrorNotAllAssigned = 1300;
    private const uint FileShareRead = 1;
    private const uint FileShareWrite = 2;
    private const uint FileShareDelete = 4;
    private const uint FileTypeDisk = 1;
    private const int FileIdInfoClass = 18;
    private const uint DuplicateSameAccess = 2;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint VolumeNameNt = 2;
    private const uint TokenAdjustPrivileges = 0x20;
    private const uint TokenQuery = 0x08;
    private const uint SePrivilegeEnabled = 0x02;
    private static readonly IntPtr InvalidHandle = new(-1);

    public static LockScanResult ScanFile(string path)
    {
        var scan = new ScanBuilder();
        if (!OperatingSystem.IsWindows())
        {
            scan.Errors.Add("File scans require Windows.");
            return scan.Build();
        }

        if (!TryResolveTarget(path, out var target, out var error))
        {
            scan.Errors.Add(error);
            return scan.Build();
        }

        if (Directory.Exists(target.FullPath))
        {
            scan.Errors.Add("ScanFile requires a file path; use ScanVolume for a whole volume.");
            return scan.Build();
        }

        ScanRestartManager(target.FullPath, scan);
        ScanProcesses(target, volumeScan: false, scan);
        return scan.Build();
    }

    public static LockScanResult ScanVolume(string driveRoot)
    {
        var scan = new ScanBuilder();
        if (!OperatingSystem.IsWindows())
        {
            scan.Errors.Add("Volume scans require Windows.");
            return scan.Build();
        }

        if (!TryResolveTarget(driveRoot, out var target, out var error))
        {
            scan.Errors.Add(error);
            return scan.Build();
        }

        if (!string.Equals(target.FullPath.TrimEnd('\\'), target.VolumeRoot.TrimEnd('\\'),
                StringComparison.OrdinalIgnoreCase))
        {
            scan.Errors.Add($"ScanVolume requires a volume root or mounted-folder root (resolved root: {target.VolumeRoot}).");
            return scan.Build();
        }

        ScanProcesses(target, volumeScan: true, scan);
        return scan.Build();
    }

    private static void ScanRestartManager(string path, ScanBuilder scan)
    {
        var key = new StringBuilder(33); // CCH_RM_SESSION_KEY + 1
        var status = RmStartSession(out var session, 0, key);
        if (status != 0)
        {
            scan.Errors.Add($"Restart Manager could not start: {Describe(status)}");
            return;
        }

        try
        {
            status = RmRegisterResources(session, 1, new[] { path }, 0, IntPtr.Zero, 0, IntPtr.Zero);
            if (status != 0)
            {
                scan.Errors.Add($"Restart Manager could not register the file: {Describe(status)}");
                return;
            }

            uint allocated = 0;
            for (var attempt = 0; attempt < 5; attempt++)
            {
                uint needed;
                uint rebootReasons;
                RmProcessInfo[]? processes = allocated == 0 ? null : new RmProcessInfo[allocated];
                var capacity = allocated;
                status = RmGetList(session, out needed, ref capacity, processes, out rebootReasons);
                if (status == 0)
                {
                    if (processes != null)
                    {
                        for (var i = 0; i < capacity; i++)
                        {
                            var info = processes[i];
                            if (info.Process.ProcessId > 0)
                            {
                                scan.AddOwner(new LockOwner(
                                    info.Process.ProcessId,
                                    path,
                                    "restart-manager",
                                    ToUtc(info.Process.StartTime),
                                    string.IsNullOrWhiteSpace(info.ServiceShortName)
                                        ? null : info.ServiceShortName));
                            }
                        }
                    }

                    return;
                }

                if (status != ErrorMoreData)
                {
                    scan.Errors.Add($"Restart Manager failed to list file users: {Describe(status)}");
                    return;
                }

                allocated = Math.Max(needed, allocated + 8);
            }

            scan.Errors.Add("Restart Manager's process list changed too often to capture.");
        }
        finally
        {
            status = RmEndSession(session);
            if (status != 0)
                scan.Errors.Add($"Restart Manager could not end its session: {Describe(status)}");
        }
    }

    private static void ScanProcesses(Target target, bool volumeScan, ScanBuilder scan)
    {
        if (IntPtr.Size != 8 || Marshal.SizeOf<PssHandleEntry>() != 136 ||
            Marshal.SizeOf<PssVaSpaceEntry>() != 80)
        {
            scan.Errors.Add("The process-snapshot interop layout does not match Windows x64.");
            return;
        }

        EnableDebugPrivilege();

        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch (Exception ex)
        {
            scan.Errors.Add($"Could not enumerate processes: {ex.Message}");
            return;
        }

        try
        {
            foreach (var process in processes)
            {
                int pid;
                try { pid = process.Id; }
                catch { continue; }
                if (pid == 0) // Idle has no user-mode handles.
                    continue;

                ScanProcess(pid, target, volumeScan, scan);
            }
        }
        finally
        {
            foreach (var process in processes)
                process.Dispose();
        }
    }

    private static void ScanProcess(int pid, Target target, bool volumeScan, ScanBuilder scan)
    {
        // Obtain only the rights that are needed. VM_READ is optional: a process
        // may still disclose its file handles when mapped-section capture is denied.
        var processHandle = OpenProcess(
            ProcessQueryInformation | ProcessDuplicateHandle | ProcessVmRead, false, pid);
        var canReadMappings = processHandle != IntPtr.Zero;
        if (processHandle == IntPtr.Zero)
        {
            processHandle = OpenProcess(ProcessQueryInformation | ProcessDuplicateHandle, false, pid);
            if (processHandle == IntPtr.Zero)
                processHandle = OpenProcess(ProcessQueryLimitedInformation | ProcessDuplicateHandle, false, pid);
        }

        if (processHandle == IntPtr.Zero)
        {
            var code = Marshal.GetLastWin32Error();
            if (code != ErrorInvalidParameter) // The process exited during enumeration.
                scan.Inaccessible.Add(new InaccessibleProcess(pid, $"OpenProcess: {Describe((uint)code)}"));
            return;
        }

        try
        {
            var startedAt = GetProcessStartedAtUtc(processHandle);
            var flags = PssCaptureHandles | PssCaptureHandleNameInformation;
            if (canReadMappings)
                flags |= PssCaptureVaSpace | PssCaptureVaSpaceSectionInformation;

            var status = PssCaptureSnapshot(processHandle, flags, 0, out var snapshot);
            var scannedMappings = canReadMappings && status == 0;
            if (status != 0 && canReadMappings)
                status = PssCaptureSnapshot(processHandle,
                    PssCaptureHandles | PssCaptureHandleNameInformation, 0, out snapshot);

            if (status != 0)
            {
                scan.Inaccessible.Add(new InaccessibleProcess(pid, $"PssCaptureSnapshot: {Describe(status)}"));
                return;
            }

            try
            {
                WalkHandles(processHandle, snapshot, pid, startedAt, target, volumeScan, scan);
                if (scannedMappings)
                    WalkMappings(snapshot, pid, startedAt, target, volumeScan, scan);
                else
                    scan.Inaccessible.Add(new InaccessibleProcess(pid, "Mapped sections could not be scanned (PROCESS_VM_READ or snapshot denied)."));
            }
            finally
            {
                var freeStatus = PssFreeSnapshot(GetCurrentProcess(), snapshot);
                if (freeStatus != 0)
                    scan.Errors.Add($"Could not free snapshot for PID {pid}: {Describe(freeStatus)}");
            }
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    private static void WalkHandles(
        IntPtr processHandle, IntPtr snapshot, int pid, DateTime? startedAt,
        Target target, bool volumeScan, ScanBuilder scan)
    {
        var status = PssWalkMarkerCreate(IntPtr.Zero, out var marker);
        if (status != 0)
        {
            scan.Inaccessible.Add(new InaccessibleProcess(pid, $"Handle walk marker: {Describe(status)}"));
            return;
        }

        try
        {
            uint unresolvedDiskHandles = 0;
            while (true)
            {
                status = PssWalkHandle(snapshot, PssWalkHandles, marker,
                    out var entry, (uint)Marshal.SizeOf<PssHandleEntry>());
                if (status == ErrorNoMoreItems)
                    break;
                if (status != 0)
                {
                    scan.Inaccessible.Add(new InaccessibleProcess(pid, $"Handle walk: {Describe(status)}"));
                    return;
                }

                var typeName = ReadWideString(entry.TypeName, entry.TypeNameLength);
                if (!string.Equals(typeName, "File", StringComparison.OrdinalIgnoreCase))
                    continue;
                var name = (entry.Flags & PssHandleHaveName) != 0 && entry.ObjectName != IntPtr.Zero
                    ? ReadWideString(entry.ObjectName, entry.ObjectNameLength)
                    : "";
                if (Matches(name, target, volumeScan))
                {
                    scan.AddOwner(new LockOwner(pid, ToFriendlyPath(name, target), "file-handle", startedAt));
                    continue;
                }

                // Windows often captures the type of a File handle but omits
                // ObjectName entirely. Duplicate it and ask the file system for
                // the final NT path. Check the type first so pipe/socket handles
                // never enter a potentially blocking path query.
                if (!DuplicateHandle(processHandle, entry.Handle, GetCurrentProcess(),
                        out var duplicate, 0, false, DuplicateSameAccess))
                {
                    // A handle closed since the snapshot is not an unknown lock.
                    if (Marshal.GetLastWin32Error() != 6)
                        unresolvedDiskHandles++;
                    continue;
                }

                try
                {
                    if (GetFileType(duplicate) != FileTypeDisk)
                        continue;
                    // The same file can be open through another hard-link name, or
                    // through a reparse alias. Its volume serial and 128-bit file ID
                    // identify the object even when the two paths differ.
                    var sameFile = !volumeScan && target.FileIdentity.HasValue &&
                        TryGetFileIdentity(duplicate, out var identity) &&
                        identity.Equals(target.FileIdentity.Value);
                    var finalPath = new StringBuilder(32768);
                    var length = GetFinalPathNameByHandleW(
                        duplicate, finalPath, (uint)finalPath.Capacity, VolumeNameNt);
                    if (length == 0 || length >= finalPath.Capacity)
                    {
                        if (sameFile)
                            scan.AddOwner(new LockOwner(pid, target.FullPath, "file-handle", startedAt));
                        else
                            unresolvedDiskHandles++;
                        continue;
                    }

                    name = finalPath.ToString();
                    if (sameFile || Matches(name, target, volumeScan))
                        scan.AddOwner(new LockOwner(pid, ToFriendlyPath(name, target), "file-handle", startedAt));
                }
                finally { CloseHandle(duplicate); }
            }

            if (unresolvedDiskHandles > 0)
                scan.Inaccessible.Add(new InaccessibleProcess(pid,
                    $"{unresolvedDiskHandles} disk-file handles could not be resolved."));
        }
        finally
        {
            PssWalkMarkerFree(marker);
        }
    }

    private static void WalkMappings(
        IntPtr snapshot, int pid, DateTime? startedAt, Target target, bool volumeScan, ScanBuilder scan)
    {
        var status = PssWalkMarkerCreate(IntPtr.Zero, out var marker);
        if (status != 0)
        {
            scan.Inaccessible.Add(new InaccessibleProcess(pid, $"Mapping walk marker: {Describe(status)}"));
            return;
        }

        try
        {
            while (true)
            {
                status = PssWalkVaEntry(snapshot, PssWalkVaSpace, marker,
                    out var entry, (uint)Marshal.SizeOf<PssVaSpaceEntry>());
                if (status == ErrorNoMoreItems)
                    break;
                if (status != 0)
                {
                    scan.Inaccessible.Add(new InaccessibleProcess(pid, $"Mapping walk: {Describe(status)}"));
                    return;
                }

                if (entry.MappedFileName == IntPtr.Zero || entry.MappedFileNameLength == 0)
                    continue;
                var name = ReadWideString(entry.MappedFileName, entry.MappedFileNameLength);
                if (Matches(name, target, volumeScan))
                    scan.AddOwner(new LockOwner(pid, ToFriendlyPath(name, target), "mapped-section", startedAt));
            }
        }
        finally
        {
            PssWalkMarkerFree(marker);
        }
    }

    private static bool Matches(string objectName, Target target, bool volumeScan)
    {
        var ntName = NormalizeToNtPath(objectName);
        if (ntName is null)
            return false;
        if (volumeScan)
            return ntName.Equals(target.NtVolume, StringComparison.OrdinalIgnoreCase)
                || ntName.StartsWith(target.NtVolume + "\\", StringComparison.OrdinalIgnoreCase);
        return ntName.Equals(target.NtPath, StringComparison.OrdinalIgnoreCase)
            || ntName.StartsWith(target.NtPath + ":", StringComparison.OrdinalIgnoreCase);
    }

    private static string ToFriendlyPath(string objectName, Target target)
    {
        var ntName = NormalizeToNtPath(objectName);
        if (ntName is null || !ntName.StartsWith(target.NtVolume, StringComparison.OrdinalIgnoreCase))
            return objectName;
        var relative = ntName[target.NtVolume.Length..].TrimStart('\\');
        return target.VolumeRoot + relative;
    }

    private static string? NormalizeToNtPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        path = path.Replace('/', '\\');
        if (path.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
            return path.TrimEnd('\\');
        if (path.StartsWith("\\??\\", StringComparison.Ordinal))
            path = path[4..];
        else if (path.StartsWith("\\\\?\\", StringComparison.Ordinal))
            path = path[4..];

        var separator = path.IndexOf('\\');
        var deviceName = separator < 0 ? path : path[..separator];
        if (deviceName.Length != 2 || deviceName[1] != ':')
        {
            if (!deviceName.StartsWith("Volume{", StringComparison.OrdinalIgnoreCase))
                return null;
        }

        var devicePath = QueryDevice(deviceName);
        return devicePath is null ? null : devicePath.TrimEnd('\\') + (separator < 0 ? "" : path[separator..]);
    }

    private static bool TryResolveTarget(string path, out Target target, out string error)
    {
        target = default!;
        error = "";
        if (string.IsNullOrWhiteSpace(path))
        {
            error = "A file path or volume path is required.";
            return false;
        }

        string fullPath;
        try
        {
            // Path.GetFullPath("E:") means the current directory on E:, not the
            // root of E:. Treat a bare drive designator as a volume selection.
            var requestedPath = path.Length == 2 && path[1] == ':' ? path + "\\" : path;
            fullPath = Path.GetFullPath(requestedPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            error = $"Invalid path: {ex.Message}";
            return false;
        }

        var root = new StringBuilder(32768);
        if (!GetVolumePathNameW(fullPath, root, (uint)root.Capacity))
        {
            error = $"Cannot identify the containing volume: {Describe((uint)Marshal.GetLastWin32Error())}";
            return false;
        }

        var volumeRoot = root.ToString();
        var volumeName = new StringBuilder(1024);
        string? deviceName = null;
        if (GetVolumeNameForVolumeMountPointW(volumeRoot, volumeName, (uint)volumeName.Capacity))
            deviceName = volumeName.ToString().TrimEnd('\\').Replace("\\\\?\\", "");
        if (deviceName is null && volumeRoot.Length >= 2 && volumeRoot[1] == ':')
            deviceName = volumeRoot[..2];
        if (deviceName is null)
        {
            error = "This path does not resolve to a local mounted volume.";
            return false;
        }

        var ntVolume = QueryDevice(deviceName);
        if (ntVolume is null)
        {
            error = $"Cannot resolve the volume device for {volumeRoot}.";
            return false;
        }

        ntVolume = ntVolume.TrimEnd('\\');
        var relative = fullPath.StartsWith(volumeRoot, StringComparison.OrdinalIgnoreCase)
            ? fullPath[volumeRoot.Length..].TrimStart('\\')
            : "";
        var ntPath = relative.Length == 0 ? ntVolume : ntVolume + "\\" + relative;

        // A metadata-only open usually succeeds even when the target denies read,
        // write and delete sharing. If it succeeds, use the resolved object path so
        // reparse points and mount-point aliases do not hide a matching handle.
        FileIdInfo? fileIdentity = null;
        var file = CreateFileW(fullPath, 0, FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics, IntPtr.Zero);
        if (file != InvalidHandle)
        {
            try
            {
                if (TryGetFileIdentity(file, out var identity))
                    fileIdentity = identity;
                var finalPath = new StringBuilder(32768);
                var resultLength = GetFinalPathNameByHandleW(file, finalPath, (uint)finalPath.Capacity, VolumeNameNt);
                if (resultLength > 0 && resultLength < finalPath.Capacity)
                {
                    var resolved = finalPath.ToString().TrimEnd('\\');
                    if (resolved.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
                        ntPath = resolved;
                }
            }
            finally { CloseHandle(file); }
        }

        target = new Target(fullPath, volumeRoot, ntVolume, ntPath, fileIdentity);
        return true;
    }

    private static bool TryGetFileIdentity(IntPtr file, out FileIdInfo identity) =>
        GetFileInformationByHandleEx(file, FileIdInfoClass, out identity,
            (uint)Marshal.SizeOf<FileIdInfo>());

    private static string? QueryDevice(string dosDevice)
    {
        var buffer = new StringBuilder(32768);
        var length = QueryDosDeviceW(dosDevice, buffer, (uint)buffer.Capacity);
        if (length == 0)
            return null;
        var names = buffer.ToString();
        var end = names.IndexOf('\0');
        return (end < 0 ? names : names[..end]).TrimEnd('\\');
    }

    private static string ReadWideString(IntPtr pointer, ushort bytes) =>
        pointer == IntPtr.Zero || bytes == 0
            ? ""
            : (Marshal.PtrToStringUni(pointer, bytes / 2) ?? "").TrimEnd('\0');

    private static DateTime? GetProcessStartedAtUtc(IntPtr process)
    {
        if (!GetProcessTimes(process, out var created, out _, out _, out _))
            return null;
        return ToUtc(created);
    }

    private static DateTime? ToUtc(FileTime time)
    {
        var ticks = ((long)time.High << 32) | time.Low;
        if (ticks <= 0)
            return null;
        try { return DateTime.FromFileTimeUtc(ticks); }
        catch (ArgumentOutOfRangeException) { return null; }
    }

    private static void EnableDebugPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            return;
        try
        {
            if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out var luid))
                return;
            var privileges = new TokenPrivileges { Count = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            if (AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero)
                && Marshal.GetLastWin32Error() != ErrorNotAllAssigned)
            {
                // The privilege is now available for processes that allow it.
            }
        }
        finally { CloseHandle(token); }
    }

    private static string Describe(uint error) =>
        $"{new Win32Exception(unchecked((int)error)).Message} ({error})";

    private sealed record Target(
        string FullPath, string VolumeRoot, string NtVolume, string NtPath, FileIdInfo? FileIdentity);

    private sealed class ScanBuilder
    {
        private readonly HashSet<LockOwner> _owners = new();
        public readonly List<InaccessibleProcess> Inaccessible = new();
        public readonly List<string> Errors = new();

        public void AddOwner(LockOwner owner) => _owners.Add(owner);

        public LockScanResult Build() => new(
            _owners.OrderBy(owner => owner.Pid).ThenBy(owner => owner.EvidencePath).ToArray(),
            Inaccessible.ToArray(),
            Errors.ToArray());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    // The native type-specific union occupies 48 bytes on Windows x64.
    [StructLayout(LayoutKind.Sequential)]
    private struct PssHandleUnion
    {
        public long Part0, Part1, Part2, Part3, Part4, Part5;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PssHandleEntry
    {
        public IntPtr Handle;
        public uint Flags;
        public uint ObjectType;
        public FileTime CaptureTime;
        public uint Attributes;
        public uint GrantedAccess;
        public uint HandleCount;
        public uint PointerCount;
        public uint PagedPoolCharge;
        public uint NonPagedPoolCharge;
        public FileTime CreationTime;
        public ushort TypeNameLength;
        public IntPtr TypeName;
        public ushort ObjectNameLength;
        public IntPtr ObjectName;
        public PssHandleUnion TypeSpecificInformation;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PssVaSpaceEntry
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint TimeDateStamp;
        public uint SizeOfImage;
        public IntPtr ImageBase;
        public uint CheckSum;
        public ushort MappedFileNameLength;
        public IntPtr MappedFileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RmUniqueProcess
    {
        public int ProcessId;
        public FileTime StartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RmProcessInfo
    {
        public RmUniqueProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string AppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string ServiceShortName;
        public uint ApplicationType;
        public uint AppStatus;
        public uint SessionId;
        public int Restartable;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint Count;
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
        out IntPtr targetHandle, uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(IntPtr file);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        IntPtr process, out FileTime creationTime, out FileTime exitTime,
        out FileTime kernelTime, out FileTime userTime);

    [DllImport("kernel32.dll")]
    private static extern uint PssCaptureSnapshot(IntPtr process, uint flags, uint threadContextFlags, out IntPtr snapshot);

    [DllImport("kernel32.dll")]
    private static extern uint PssFreeSnapshot(IntPtr process, IntPtr snapshot);

    [DllImport("kernel32.dll")]
    private static extern uint PssWalkMarkerCreate(IntPtr allocator, out IntPtr marker);

    [DllImport("kernel32.dll")]
    private static extern uint PssWalkMarkerFree(IntPtr marker);

    [DllImport("kernel32.dll", EntryPoint = "PssWalkSnapshot")]
    private static extern uint PssWalkHandle(
        IntPtr snapshot, uint informationClass, IntPtr marker, out PssHandleEntry entry, uint length);

    [DllImport("kernel32.dll", EntryPoint = "PssWalkSnapshot")]
    private static extern uint PssWalkVaEntry(
        IntPtr snapshot, uint informationClass, IntPtr marker, out PssVaSpaceEntry entry, uint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string path, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetVolumePathNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathNameW(string fileName, StringBuilder volumePathName, uint capacity);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetVolumeNameForVolumeMountPointW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string volumeMountPoint, StringBuilder volumeName, uint capacity);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "QueryDosDeviceW", SetLastError = true)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, uint capacity);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(IntPtr file, StringBuilder path, uint capacity, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        IntPtr file, int informationClass, out FileIdInfo fileInformation, uint bufferSize);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmStartSession(out uint session, uint flags, StringBuilder sessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmRegisterResources(
        uint session, uint fileCount,
        [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] files,
        uint applicationCount, IntPtr applications, uint serviceCount, IntPtr services);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern uint RmGetList(
        uint session, out uint processesNeeded, ref uint processesAvailable,
        [In, Out] RmProcessInfo[]? processes, out uint rebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern uint RmEndSession(uint session);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        ref TokenPrivileges newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);
}
