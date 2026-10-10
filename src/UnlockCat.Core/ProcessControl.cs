using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace UnlockCat.Core;

/// <summary>
/// A process snapshot. CreationTimeFileTime is the exact Windows FILETIME value used
/// to reject a recycled PID before terminating a process.
/// </summary>
public sealed record ProcessInfo(
    int ProcessId,
    string Name,
    string? ImagePath,
    long? CreationTimeFileTime,
    bool? IsCritical,
    int? InspectionWin32Error)
{
    public DateTimeOffset? StartedAtUtc => CreationTimeFileTime is long value
        ? new DateTimeOffset(DateTime.FromFileTimeUtc(value))
        : null;

    public bool CanTerminate => ProcessId > 4
        && ProcessId != Environment.ProcessId
        && CreationTimeFileTime.HasValue
        && IsCritical == false;
}

public enum TerminationStatus
{
    Terminated,
    Restarted,
    RestartFailed,
    AlreadyExited,
    IdentityChanged,
    Protected,
    CannotVerifyIdentity,
    AccessDenied,
    TimedOut,
    Failed
}

public sealed record TerminationResult(
    int ProcessId,
    TerminationStatus Status,
    int? Win32Error = null,
    string? Detail = null)
{
    public bool Succeeded => Status is TerminationStatus.Terminated or TerminationStatus.Restarted or TerminationStatus.AlreadyExited;

    public string Message
    {
        get
        {
            var description = Status switch
            {
                TerminationStatus.Terminated => "Process terminated and its exit was confirmed.",
                TerminationStatus.Restarted => "Windows Explorer terminated and its restart was requested.",
                TerminationStatus.RestartFailed => "Windows Explorer terminated, but its restart failed.",
                TerminationStatus.AlreadyExited => "The original process has already exited.",
                TerminationStatus.IdentityChanged => "PID now belongs to a different process. Scan again.",
                TerminationStatus.Protected => "Refusing to terminate the current or a critical system process.",
                TerminationStatus.CannotVerifyIdentity => "Could not verify process identity or critical status.",
                TerminationStatus.AccessDenied => "Windows denied termination. Run elevated or check process protection.",
                TerminationStatus.TimedOut => "Termination was requested, but process exit was not confirmed before timeout.",
                _ => "Process termination failed."
            };
            var message = Win32Error is int error
                ? $"{description} Windows error {error}: {new Win32Exception(error).Message}"
                : description;
            return Detail is null ? message : $"{message} {Detail}";
        }
    }
}

/// <summary>
/// Uses one process handle for identity, critical-process, termination, and exit checks.
/// This prevents a PID recycled after discovery from targeting a different process.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ProcessControl
{
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Synchronize = 0x00100000;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint Infinite = 0xFFFFFFFF;

    private const int ErrorAccessDenied = 5;
    private const int ErrorInvalidParameter = 87;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNotAllAssigned = 1300;

    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private const uint WaitFailed = 0xFFFFFFFF;

    private static readonly Lazy<(bool Enabled, int Error)> DebugPrivilege =
        new(EnableDebugPrivilegeCore);

    private static readonly string WindowsExplorerPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");

    public static bool IsWindowsExplorerImage(string? imagePath) =>
        string.Equals(imagePath, WindowsExplorerPath, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Enables SeDebugPrivilege if the running token already has it. This cannot grant
    /// a privilege missing from the token; run elevated when access is denied.
    /// </summary>
    public static bool TryEnableDebugPrivilege(out int win32Error)
    {
        var result = DebugPrivilege.Value;
        win32Error = result.Error;
        return result.Enabled;
    }

    public static ProcessInfo Describe(int processId)
    {
        if (processId <= 0)
            return new ProcessInfo(processId, "System Idle Process", null, null, null, ErrorInvalidParameter);

        var handle = OpenWithDebugRetry(ProcessQueryLimitedInformation, processId, out var openError);
        if (handle == IntPtr.Zero)
        {
            var inaccessibleName = processId == 4 ? "System" : BestEffortName(processId);
            return new ProcessInfo(processId, inaccessibleName, null, null, null, openError);
        }

        try
        {
            int? inspectionError = null;
            string? path = QueryImagePath(handle, out var pathError);
            if (path is null)
                inspectionError = pathError;

            long? creation = null;
            if (GetProcessTimes(handle, out var created, out _, out _, out _))
                creation = created.ToInt64();
            else
                inspectionError ??= Marshal.GetLastWin32Error();

            bool? critical = null;
            if (IsProcessCritical(handle, out var isCritical))
                critical = isCritical;
            else
                inspectionError ??= Marshal.GetLastWin32Error();

            var name = path is null ? null : Path.GetFileName(path);
            if (string.IsNullOrEmpty(name))
                name = BestEffortName(processId);
            return new ProcessInfo(processId, name, path, creation, critical, inspectionError);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static string BestEffortName(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch
        {
            return $"PID {processId}";
        }
    }

    /// <summary>
    /// Forcefully terminates the specific process instance described by target and
    /// waits for its process handle to signal. A missing creation time is refused.
    /// </summary>
    public static TerminationResult Terminate(ProcessInfo target, TimeSpan? timeout = null)
        => TerminateCore(target, timeout, restartExplorer: false);

    /// <summary>
    /// Terminates the confirmed process instance and relaunches the Windows shell
    /// when its image is the actual Windows-directory explorer.exe.
    /// </summary>
    public static TerminationResult TerminateOrRestartExplorer(ProcessInfo target, TimeSpan? timeout = null)
        => TerminateCore(target, timeout, restartExplorer: true);

    private static TerminationResult TerminateCore(ProcessInfo target, TimeSpan? timeout, bool restartExplorer)
    {
        ArgumentNullException.ThrowIfNull(target);

        var processId = target.ProcessId;
        if (processId <= 0 || processId == 4 || processId == Environment.ProcessId)
            return new TerminationResult(processId, TerminationStatus.Protected);

        if (target.CreationTimeFileTime is not long expectedCreation)
            return new TerminationResult(processId, TerminationStatus.CannotVerifyIdentity);

        var waitMilliseconds = ToWaitMilliseconds(timeout ?? TimeSpan.FromSeconds(30));
        var access = ProcessTerminate | ProcessQueryLimitedInformation | Synchronize;
        var handle = OpenWithDebugRetry(access, processId, out var openError);
        if (handle == IntPtr.Zero)
        {
            if (openError == ErrorInvalidParameter)
                return new TerminationResult(processId, TerminationStatus.AlreadyExited);
            return new TerminationResult(
                processId,
                openError == ErrorAccessDenied ? TerminationStatus.AccessDenied : TerminationStatus.Failed,
                openError);
        }

        try
        {
            if (!GetProcessTimes(handle, out var created, out _, out _, out _))
                return new TerminationResult(processId, TerminationStatus.CannotVerifyIdentity, Marshal.GetLastWin32Error());

            if (created.ToInt64() != expectedCreation)
                return new TerminationResult(processId, TerminationStatus.IdentityChanged);

            if (!IsProcessCritical(handle, out var critical))
                return new TerminationResult(processId, TerminationStatus.CannotVerifyIdentity, Marshal.GetLastWin32Error());

            if (critical)
                return new TerminationResult(processId, TerminationStatus.Protected);

            var priorWait = WaitForSingleObject(handle, 0);
            if (priorWait == WaitObject0)
                return new TerminationResult(processId, TerminationStatus.AlreadyExited);
            if (priorWait == WaitFailed)
                return new TerminationResult(processId, TerminationStatus.Failed, Marshal.GetLastWin32Error());

            IntPtr explorerToken = IntPtr.Zero;
            string? explorerPath = null;
            if (restartExplorer)
            {
                var imagePath = QueryImagePath(handle, out var pathError);
                if (imagePath is null)
                    return new TerminationResult(processId, TerminationStatus.CannotVerifyIdentity, pathError,
                        "The executable path could not be checked before termination.");

                if (IsWindowsExplorerImage(imagePath))
                {
                    if (!ProcessIdToSessionId((uint)processId, out var targetSession) ||
                        !ProcessIdToSessionId((uint)Environment.ProcessId, out var currentSession))
                        return new TerminationResult(processId, TerminationStatus.CannotVerifyIdentity,
                            Marshal.GetLastWin32Error(), "Windows Explorer's session could not be checked.");
                    if (targetSession != currentSession)
                        return new TerminationResult(processId, TerminationStatus.Protected, null,
                            "Windows Explorer belongs to another session and cannot be restarted here.");

                    if (!OpenProcessToken(handle, TokenQuery | TokenDuplicate | TokenAssignPrimary, out explorerToken))
                        return new TerminationResult(processId, TerminationStatus.AccessDenied,
                            Marshal.GetLastWin32Error(), "Could not save Windows Explorer's user token for restart.");
                    explorerPath = imagePath;
                }
            }

            try
            {
                if (!TerminateProcess(handle, 1))
                {
                    var terminateError = Marshal.GetLastWin32Error();
                    if (WaitForSingleObject(handle, 0) == WaitObject0)
                        return explorerPath is null
                            ? new TerminationResult(processId, TerminationStatus.AlreadyExited)
                            : RestartExplorer(processId, explorerPath, explorerToken);
                    return new TerminationResult(
                        processId,
                        terminateError == ErrorAccessDenied ? TerminationStatus.AccessDenied : TerminationStatus.Failed,
                        terminateError);
                }

                // A second Explorer must not start while the old shell can still
                // accept its launch request. Wait for its actual exit before relaunch.
                var waitResult = WaitForSingleObject(handle,
                    explorerPath is null ? waitMilliseconds : Infinite);
                if (waitResult != WaitObject0)
                    return waitResult == WaitTimeout
                        ? new TerminationResult(processId, TerminationStatus.TimedOut)
                        : new TerminationResult(processId, TerminationStatus.Failed, Marshal.GetLastWin32Error());

                return explorerPath is null
                    ? new TerminationResult(processId, TerminationStatus.Terminated)
                    : RestartExplorer(processId, explorerPath, explorerToken);
            }
            finally
            {
                if (explorerToken != IntPtr.Zero)
                    CloseHandle(explorerToken);
            }
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static TerminationResult RestartExplorer(int processId, string imagePath, IntPtr token)
    {
        var startup = new StartupInfo
        {
            Size = (uint)Marshal.SizeOf<StartupInfo>(),
            Desktop = @"winsta0\default"
        };
        if (CreateProcessWithTokenW(token, 0, imagePath, null, 0, IntPtr.Zero, null,
            ref startup, out var started))
        {
            CloseStartedProcess(started);
            return new TerminationResult(processId, TerminationStatus.Restarted);
        }

        var tokenLaunchError = Marshal.GetLastWin32Error();
        if (!CreateEnvironmentBlock(out var environment, token, false))
            return new TerminationResult(processId, TerminationStatus.RestartFailed,
                Marshal.GetLastWin32Error(),
                $"Token launch also failed with Windows error {tokenLaunchError}.");

        try
        {
            if (CreateProcessAsUserW(token, imagePath, null, IntPtr.Zero, IntPtr.Zero, false,
                CreateUnicodeEnvironment, environment, null, ref startup, out started))
            {
                CloseStartedProcess(started);
                return new TerminationResult(processId, TerminationStatus.Restarted);
            }
            var fallbackError = Marshal.GetLastWin32Error();
            return new TerminationResult(processId, TerminationStatus.RestartFailed, fallbackError,
                $"Token launch also failed with Windows error {tokenLaunchError}.");
        }
        finally
        {
            DestroyEnvironmentBlock(environment);
        }
    }

    private static void CloseStartedProcess(ProcessInformation started)
    {
        CloseHandle(started.Thread);
        CloseHandle(started.Process);
    }

    private static uint ToWaitMilliseconds(TimeSpan timeout)
    {
        if (timeout < TimeSpan.Zero || timeout.TotalMilliseconds >= uint.MaxValue - 1)
            throw new ArgumentOutOfRangeException(nameof(timeout));
        return (uint)Math.Ceiling(timeout.TotalMilliseconds);
    }

    private static IntPtr OpenWithDebugRetry(uint access, int processId, out int win32Error)
    {
        var handle = OpenProcess(access, false, (uint)processId);
        if (handle != IntPtr.Zero)
        {
            win32Error = 0;
            return handle;
        }

        win32Error = Marshal.GetLastWin32Error();
        if (win32Error == ErrorAccessDenied && TryEnableDebugPrivilege(out _))
        {
            handle = OpenProcess(access, false, (uint)processId);
            win32Error = handle == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        }

        return handle;
    }

    private static string? QueryImagePath(IntPtr handle, out int win32Error)
    {
        for (var capacity = 512; capacity <= 32768; capacity *= 2)
        {
            var path = new StringBuilder(capacity);
            var length = capacity;
            if (QueryFullProcessImageName(handle, 0, path, ref length))
            {
                win32Error = 0;
                return path.ToString(0, length);
            }

            win32Error = Marshal.GetLastWin32Error();
            if (win32Error != ErrorInsufficientBuffer)
                return null;
        }

        win32Error = ErrorInsufficientBuffer;
        return null;
    }

    private static (bool Enabled, int Error) EnableDebugPrivilegeCore()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            return (false, Marshal.GetLastWin32Error());

        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid))
                return (false, Marshal.GetLastWin32Error());

            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SePrivilegeEnabled
            };

            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                return (false, Marshal.GetLastWin32Error());

            // AdjustTokenPrivileges succeeds even when the privilege was not assigned.
            var error = Marshal.GetLastWin32Error();
            return error == 0 ? (true, 0) : (false, error == ErrorNotAllAssigned ? ErrorAccessDenied : error);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct FileTime
    {
        public readonly uint Low;
        public readonly uint High;
        public long ToInt64() => ((long)High << 32) | Low;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct Luid
    {
        public readonly uint LowPart;
        public readonly int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint Size;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2;
        public IntPtr ReservedPointer;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process;
        public IntPtr Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process, uint flags, StringBuilder imagePath, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(
        IntPtr process, out FileTime creationTime, out FileTime exitTime,
        out FileTime kernelTime, out FileTime userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(IntPtr process, [MarshalAs(UnmanagedType.Bool)] out bool critical);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", EntryPoint = "CreateProcessWithTokenW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr token, uint logonFlags, string applicationName, string? commandLine,
        uint creationFlags, IntPtr environment, string? currentDirectory,
        ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUserW(
        IntPtr token, string applicationName, string? commandLine,
        IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags,
        IntPtr environment, string? currentDirectory,
        ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateEnvironmentBlock(
        out IntPtr environment, IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAllPrivileges, ref TokenPrivileges newState,
        uint bufferLength, IntPtr previousState, IntPtr returnLength);
}
