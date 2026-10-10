using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;

namespace UnlockCat.Core;

public enum ServiceState : uint
{
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7
}

public enum ServiceStartType : uint
{
    Boot = 0,
    System = 1,
    Automatic = 2,
    Manual = 3,
    Disabled = 4
}

/// <summary>A snapshot of an SCM service entry, including its current host PID.</summary>
public sealed record ServiceInfo(
    string Name,
    string DisplayName,
    int ProcessId,
    ServiceState State,
    uint ServiceType,
    uint ControlsAccepted,
    ServiceStartType? StartType,
    int? ConfigurationWin32Error)
{
    public bool IsSharedProcess => (ServiceType & 0x20) != 0;
    public bool CanStop => State != ServiceState.Stopped &&
        (ControlsAccepted & 0x00000001) != 0;
}

public enum ServiceStopStatus
{
    Stopped,
    AlreadyStopped,
    IdentityChanged,
    NotStoppable,
    DependentServicesRunning,
    AccessDenied,
    TimedOut,
    Failed
}

public sealed record ServiceStopResult(
    string Name,
    ServiceStopStatus Status,
    ServiceState? FinalState = null,
    int? Win32Error = null)
{
    public bool Succeeded => Status is ServiceStopStatus.Stopped or ServiceStopStatus.AlreadyStopped;

    public string Message
    {
        get
        {
            var description = Status switch
            {
                ServiceStopStatus.Stopped => "The service reached the stopped state.",
                ServiceStopStatus.AlreadyStopped => "The service was already stopped.",
                ServiceStopStatus.IdentityChanged => "The service changed process or no longer exists. Scan again.",
                ServiceStopStatus.NotStoppable => "The service does not currently accept stop requests.",
                ServiceStopStatus.DependentServicesRunning => "Other running services depend on this service.",
                ServiceStopStatus.AccessDenied => "Windows denied the service stop request. Run elevated or check service protection.",
                ServiceStopStatus.TimedOut => "The service did not reach the stopped state before timeout.",
                _ => "The service stop request failed."
            };
            return Win32Error is int error
                ? $"{description} Windows error {error}: {new Win32Exception(error).Message}"
                : description;
        }
    }
}

/// <summary>
/// Enumerates Win32 services and stops a selected service through the Service
/// Control Manager. It never terminates a shared host process.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceControl
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerEnumerateService = 0x0004;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceWin32 = 0x0030;
    private const uint ServiceStateAll = 0x0003;
    private const uint ServiceControlStop = 0x00000001;
    private const int ScEnumProcessInfo = 0;
    private const int ScStatusProcessInfo = 0;

    private const int ErrorAccessDenied = 5;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorMoreData = 234;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceCannotAcceptControl = 1061;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorDependentServicesRunning = 1051;
    private const int ErrorInvalidServiceControl = 1052;
    private const int EnumerationBufferSize = 256 * 1024;

    /// <summary>
    /// Returns all visible Win32 services. Windows silently omits services for
    /// which the caller lacks SERVICE_QUERY_STATUS permission.
    /// </summary>
    public static IReadOnlyList<ServiceInfo> ListServices()
    {
        var manager = OpenSCManager(null, null, ScManagerConnect | ScManagerEnumerateService);
        if (manager == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open the Service Control Manager.");

        try
        {
            var services = new List<ServiceInfo>();
            var buffer = Marshal.AllocHGlobal(EnumerationBufferSize);
            try
            {
                uint resume = 0;
                while (true)
                {
                    var oldResume = resume;
                    var ok = EnumServicesStatusEx(
                        manager, ScEnumProcessInfo, ServiceWin32, ServiceStateAll,
                        buffer, EnumerationBufferSize, out _, out var returned,
                        ref resume, null);
                    var enumerationError = ok ? 0 : Marshal.GetLastWin32Error();
                    if (!ok && enumerationError != ErrorMoreData)
                        throw new Win32Exception(enumerationError, "Could not enumerate services.");

                    var stride = Marshal.SizeOf<EnumServiceStatusProcess>();
                    for (var i = 0; i < returned; i++)
                    {
                        var native = Marshal.PtrToStructure<EnumServiceStatusProcess>(
                            IntPtr.Add(buffer, checked((int)i * stride)));
                        var name = Marshal.PtrToStringUni(native.ServiceName);
                        if (string.IsNullOrEmpty(name))
                            continue;

                        var display = Marshal.PtrToStringUni(native.DisplayName) ?? name;
                        var startType = QueryStartType(manager, name, out var configError);
                        var status = native.Status;
                        services.Add(new ServiceInfo(
                            name, display, checked((int)status.ProcessId),
                            (ServiceState)status.CurrentState, status.ServiceType,
                            status.ControlsAccepted, startType, configError));
                    }

                    if (ok)
                        return services;

                    if (returned == 0 && resume == oldResume)
                        throw new Win32Exception(ErrorMoreData, "Service enumeration made no progress.");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    /// <summary>Finds all visible active services hosted by a process.</summary>
    public static IReadOnlyList<ServiceInfo> ForProcess(int processId)
    {
        if (processId <= 0)
            return Array.Empty<ServiceInfo>();

        var result = new List<ServiceInfo>();
        foreach (var service in ListServices())
        {
            if (service.ProcessId == processId && service.State != ServiceState.Stopped)
                result.Add(service);
        }
        return result;
    }

    /// <summary>
    /// Sends SERVICE_CONTROL_STOP to one named service and polls SCM until it is
    /// stopped. A changed host PID is refused so a stale scan cannot stop a newly
    /// hosted instance. This does not kill the service's process.
    /// </summary>
    public static ServiceStopResult StopService(ServiceInfo target, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (string.IsNullOrWhiteSpace(target.Name))
            throw new ArgumentException("A service name is required.", nameof(target));

        var limit = timeout ?? TimeSpan.FromSeconds(30);
        if (limit < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeout));

        var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
            return Failure(target.Name, Marshal.GetLastWin32Error());

        try
        {
            var service = OpenService(manager, target.Name, ServiceQueryStatus | ServiceStop);
            if (service == IntPtr.Zero)
                return Failure(target.Name, Marshal.GetLastWin32Error());

            try
            {
                var timer = Stopwatch.StartNew();
                var requestAccepted = false;
                while (true)
                {
                    if (!QueryServiceStatusEx(
                            service, ScStatusProcessInfo, out var status,
                            Marshal.SizeOf<ServiceStatusProcess>(), out _))
                        return Failure(target.Name, Marshal.GetLastWin32Error());

                    var state = (ServiceState)status.CurrentState;
                    if (state == ServiceState.Stopped)
                    {
                        return new ServiceStopResult(
                            target.Name,
                            requestAccepted || target.State != ServiceState.Stopped
                                ? ServiceStopStatus.Stopped
                                : ServiceStopStatus.AlreadyStopped,
                            state);
                    }

                    if (target.ProcessId != checked((int)status.ProcessId))
                        return new ServiceStopResult(target.Name, ServiceStopStatus.IdentityChanged, state);

                    if (!requestAccepted && state != ServiceState.StopPending)
                    {
                        // A service cannot reliably accept STOP during a pending
                        // transition; wait for it to become running or paused.
                        if (state is not (ServiceState.StartPending or
                            ServiceState.ContinuePending or ServiceState.PausePending))
                        {
                            if ((status.ControlsAccepted & ServiceControlStop) == 0)
                                return new ServiceStopResult(target.Name, ServiceStopStatus.NotStoppable, state);

                            if (!ControlService(service, ServiceControlStop, out _))
                            {
                                var error = Marshal.GetLastWin32Error();
                                if (error == ErrorServiceNotActive)
                                {
                                    if (timer.Elapsed >= limit)
                                        return new ServiceStopResult(target.Name, ServiceStopStatus.TimedOut, state);
                                    SleepUntilNextPoll(timer, limit);
                                    continue;
                                }
                                if (error == ErrorServiceCannotAcceptControl && timer.Elapsed < limit)
                                {
                                    SleepUntilNextPoll(timer, limit);
                                    continue;
                                }
                                return Failure(target.Name, error, state);
                            }
                            requestAccepted = true;
                        }
                    }

                    if (timer.Elapsed >= limit)
                        return new ServiceStopResult(target.Name, ServiceStopStatus.TimedOut, state);

                    SleepUntilNextPoll(timer, limit);
                }
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static ServiceStopResult Failure(string name, int error, ServiceState? state = null)
    {
        var status = error switch
        {
            ErrorAccessDenied => ServiceStopStatus.AccessDenied,
            ErrorServiceDoesNotExist => ServiceStopStatus.IdentityChanged,
            ErrorDependentServicesRunning => ServiceStopStatus.DependentServicesRunning,
            ErrorInvalidServiceControl or ErrorServiceCannotAcceptControl => ServiceStopStatus.NotStoppable,
            _ => ServiceStopStatus.Failed
        };
        return new ServiceStopResult(name, status, state, error);
    }

    private static void SleepUntilNextPoll(Stopwatch timer, TimeSpan limit)
    {
        var remaining = limit - timer.Elapsed;
        if (remaining > TimeSpan.Zero)
            Thread.Sleep(remaining < TimeSpan.FromMilliseconds(250) ? remaining : TimeSpan.FromMilliseconds(250));
    }

    private static ServiceStartType? QueryStartType(IntPtr manager, string name, out int? win32Error)
    {
        var service = OpenService(manager, name, ServiceQueryConfig);
        if (service == IntPtr.Zero)
        {
            win32Error = Marshal.GetLastWin32Error();
            return null;
        }

        try
        {
            if (QueryServiceConfig(service, IntPtr.Zero, 0, out var needed))
            {
                win32Error = ErrorInsufficientBuffer;
                return null;
            }

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer || needed <= 0 || needed > 8192)
            {
                win32Error = error;
                return null;
            }

            var buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!QueryServiceConfig(service, buffer, needed, out _))
                {
                    win32Error = Marshal.GetLastWin32Error();
                    return null;
                }
                var config = Marshal.PtrToStructure<QueryServiceConfigNative>(buffer);
                win32Error = null;
                return (ServiceStartType)config.StartType;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            CloseServiceHandle(service);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public ServiceStatusProcess Status;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusNative
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigNative
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", EntryPoint = "EnumServicesStatusExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusEx(
        IntPtr manager, int infoLevel, uint serviceType, uint serviceState,
        IntPtr services, int bufferSize, out int bytesNeeded,
        out uint servicesReturned, ref uint resumeHandle, string? groupName);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        IntPtr service, IntPtr config, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service, int infoLevel, out ServiceStatusProcess status,
        int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(IntPtr service, uint control, out ServiceStatusNative status);
}
