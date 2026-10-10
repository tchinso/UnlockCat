using System;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace UnlockCat.Core;

public enum PortModuleResolutionStatus
{
    Resolved,
    EndpointUnavailable,
    AmbiguousEndpoint,
    LookupFailed
}

/// <summary>
/// An IP Helper owner-module label for one endpoint. ModuleName is deliberately
/// unclassified: Windows may return an executable, service, or component name.
/// It must not be treated as a confirmed Windows service name by itself.
/// </summary>
public sealed record PortModuleResolution(
    PortModuleResolutionStatus Status,
    string? ModuleName = null,
    string? ModulePath = null,
    int? Win32Error = null)
{
    public bool HasModule => Status == PortModuleResolutionStatus.Resolved;
}

/// <summary>
/// Resolves optional owner-module information using documented IP Helper APIs.
/// The endpoint is matched again against a fresh owner-module table; a vanished
/// or non-unique endpoint is never attributed to a guessed module.
/// </summary>
public static class PortModuleResolver
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;
    private const int TcpTableOwnerModuleAll = 8;
    private const int UdpTableOwnerModule = 2;
    private const uint ErrorSuccess = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ErrorNotFound = 1168;
    private const uint InitialTableBytes = 16 * 1024;
    private const uint MaximumTableBytes = 256 * 1024 * 1024;
    private const int MaximumAttempts = 8;

    // These are the native x64/ARM64 layouts (8-byte alignment for LARGE_INTEGER
    // and ULONGLONG). Each OWNER_MODULE table has a DWORD count followed by four
    // padding bytes before its first row. TCPIP_OWNING_MODULE_SIZE is 16.
    private const int FirstRowOffset = 8;
    private const int Tcp4RowBytes = 160;
    private const int Tcp6RowBytes = 192;
    private const int Udp4RowBytes = 160;
    private const int Udp6RowBytes = 176;

    public static PortModuleResolution Resolve(PortOwner owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
        {
            throw new PlatformNotSupportedException("Owner-module resolution requires 64-bit Windows.");
        }

        if (owner.ProcessId <= 0)
        {
            return new PortModuleResolution(PortModuleResolutionStatus.EndpointUnavailable);
        }

        bool tcp = owner.Protocol == PortProtocol.Tcp;
        bool ipv6 = owner.AddressFamily == AddressFamily.InterNetworkV6;
        uint family = ipv6 ? AfInet6 : AfInet;
        int rowBytes = tcp
            ? (ipv6 ? Tcp6RowBytes : Tcp4RowBytes)
            : (ipv6 ? Udp6RowBytes : Udp4RowBytes);

        IntPtr table = IntPtr.Zero;
        try
        {
            uint tableBytes;
            uint error = GetTable(tcp, family, out table, out tableBytes);
            if (error != ErrorSuccess)
            {
                return new PortModuleResolution(
                    PortModuleResolutionStatus.LookupFailed, Win32Error: checked((int)error));
            }

            int count = Marshal.ReadInt32(table);
            if (count < 0 || (long)FirstRowOffset + (long)count * rowBytes > tableBytes)
            {
                throw new InvalidDataException("Windows returned an invalid owner-module table.");
            }

            IntPtr matchedRow = IntPtr.Zero;
            for (int index = 0; index < count; index++)
            {
                IntPtr row = IntPtr.Add(table, checked(FirstRowOffset + index * rowBytes));
                if (!Matches(owner, row, tcp, ipv6))
                {
                    continue;
                }

                if (matchedRow != IntPtr.Zero)
                {
                    return new PortModuleResolution(PortModuleResolutionStatus.AmbiguousEndpoint);
                }

                matchedRow = row;
            }

            if (matchedRow == IntPtr.Zero)
            {
                return new PortModuleResolution(PortModuleResolutionStatus.EndpointUnavailable);
            }

            return ResolveRow(matchedRow, tcp, ipv6);
        }
        finally
        {
            if (table != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(table);
            }
        }
    }

    private static uint GetTable(bool tcp, uint family, out IntPtr table, out uint tableBytes)
    {
        table = IntPtr.Zero;
        tableBytes = 0;
        uint capacity = InitialTableBytes;

        for (int attempt = 0; attempt < MaximumAttempts; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)capacity));
            try
            {
                uint size = capacity;
                uint result = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerModuleAll, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerModule, 0);

                if (result == ErrorSuccess)
                {
                    if (size < sizeof(uint) || size > capacity)
                    {
                        throw new InvalidDataException("Windows returned an invalid owner-module table size.");
                    }

                    table = buffer;
                    tableBytes = size;
                    buffer = IntPtr.Zero;
                    return ErrorSuccess;
                }

                if (result != ErrorInsufficientBuffer)
                {
                    return result;
                }

                ulong next = Math.Max((ulong)size, (ulong)capacity * 2);
                if (next > MaximumTableBytes)
                {
                    throw new IOException("The owner-module table exceeded the supported buffer size.");
                }

                capacity = (uint)next;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        throw new IOException("The owner-module table changed too often to capture.");
    }

    private static bool Matches(PortOwner owner, IntPtr row, bool tcp, bool ipv6)
    {
        int pidOffset = tcp ? (ipv6 ? 52 : 20) : (ipv6 ? 24 : 8);
        int portOffset = tcp ? (ipv6 ? 20 : 8) : (ipv6 ? 20 : 4);
        if (Marshal.ReadInt32(row, pidOffset) != owner.ProcessId ||
            ReadPort(row, portOffset) != owner.LocalPort)
        {
            return false;
        }

        IPAddress local = ReadAddress(row, tcp && !ipv6 ? 4 : 0, ipv6, ipv6 ? 16 : -1);
        if (!local.Equals(owner.LocalAddress))
        {
            return false;
        }

        if (!tcp)
        {
            return true;
        }

        TcpState state = (TcpState)Marshal.ReadInt32(row, ipv6 ? 48 : 0);
        if (owner.TcpState is not null && state != owner.TcpState.Value)
        {
            return false;
        }

        if (state == TcpState.Listen)
        {
            return true;
        }

        if (owner.RemoteAddress is null || owner.RemotePort is null)
        {
            return false;
        }

        IPAddress remote = ReadAddress(row, ipv6 ? 24 : 12, ipv6, ipv6 ? 40 : -1);
        return remote.Equals(owner.RemoteAddress) &&
               ReadPort(row, ipv6 ? 44 : 16) == owner.RemotePort.Value;
    }

    private static IPAddress ReadAddress(IntPtr row, int offset, bool ipv6, int scopeOffset)
    {
        byte[] bytes = new byte[ipv6 ? 16 : 4];
        Marshal.Copy(IntPtr.Add(row, offset), bytes, 0, bytes.Length);
        if (!ipv6)
        {
            return new IPAddress(bytes);
        }

        long scope = (uint)((Marshal.ReadByte(row, scopeOffset) << 24) |
                            (Marshal.ReadByte(row, scopeOffset + 1) << 16) |
                            (Marshal.ReadByte(row, scopeOffset + 2) << 8) |
                            Marshal.ReadByte(row, scopeOffset + 3));
        return new IPAddress(bytes, scope);
    }

    private static int ReadPort(IntPtr row, int offset) =>
        (Marshal.ReadByte(row, offset) << 8) | Marshal.ReadByte(row, offset + 1);

    private static PortModuleResolution ResolveRow(IntPtr row, bool tcp, bool ipv6)
    {
        uint capacity = 0;
        uint status = GetOwnerModule(row, tcp, ipv6, IntPtr.Zero, ref capacity);
        if (status != ErrorInsufficientBuffer || capacity < 2 * IntPtr.Size)
        {
            return status == ErrorNotFound || status == ErrorSuccess
                ? new PortModuleResolution(PortModuleResolutionStatus.EndpointUnavailable)
                : new PortModuleResolution(PortModuleResolutionStatus.LookupFailed,
                    Win32Error: checked((int)status));
        }

        for (int attempt = 0; attempt < MaximumAttempts; attempt++)
        {
            if (capacity > 1024 * 1024)
            {
                throw new InvalidDataException("Windows returned an excessive owner-module information size.");
            }

            IntPtr buffer = Marshal.AllocHGlobal(checked((int)capacity));
            try
            {
                uint size = capacity;
                status = GetOwnerModule(row, tcp, ipv6, buffer, ref size);
                if (status == ErrorInsufficientBuffer)
                {
                    capacity = Math.Max(size, checked(capacity * 2));
                    continue;
                }

                if (status != ErrorSuccess)
                {
                    return status == ErrorNotFound
                        ? new PortModuleResolution(PortModuleResolutionStatus.EndpointUnavailable)
                        : new PortModuleResolution(PortModuleResolutionStatus.LookupFailed,
                            Win32Error: checked((int)status));
                }

                if (size < 2 * IntPtr.Size || size > capacity)
                {
                    throw new InvalidDataException("Windows returned an invalid owner-module information size.");
                }

                string? name = ReadBufferString(buffer, size, Marshal.ReadIntPtr(buffer));
                string? path = ReadBufferString(buffer, size, Marshal.ReadIntPtr(buffer, IntPtr.Size));
                if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(path))
                {
                    return new PortModuleResolution(PortModuleResolutionStatus.EndpointUnavailable);
                }

                return new PortModuleResolution(PortModuleResolutionStatus.Resolved, name, path);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return new PortModuleResolution(PortModuleResolutionStatus.LookupFailed,
            Win32Error: checked((int)ErrorInsufficientBuffer));
    }

    private static string? ReadBufferString(IntPtr buffer, uint size, IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
        {
            return null;
        }

        long offset = pointer.ToInt64() - buffer.ToInt64();
        if (offset < 2 * IntPtr.Size || offset >= size || (offset & 1) != 0)
        {
            throw new InvalidDataException("Windows returned an invalid owner-module string pointer.");
        }

        int maximumChars = checked((int)((size - offset) / 2));
        for (int length = 0; length < maximumChars; length++)
        {
            if (Marshal.ReadInt16(pointer, length * 2) == 0)
            {
                return Marshal.PtrToStringUni(pointer, length);
            }
        }

        throw new InvalidDataException("Windows returned an unterminated owner-module string.");
    }

    private static uint GetOwnerModule(IntPtr row, bool tcp, bool ipv6, IntPtr buffer, ref uint size)
    {
        if (tcp)
        {
            return ipv6
                ? GetOwnerModuleFromTcp6Entry(row, 0, buffer, ref size)
                : GetOwnerModuleFromTcpEntry(row, 0, buffer, ref size);
        }

        return ipv6
            ? GetOwnerModuleFromUdp6Entry(row, 0, buffer, ref size)
            : GetOwnerModuleFromUdpEntry(row, 0, buffer, ref size);
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order, uint family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetOwnerModuleFromTcpEntry(IntPtr entry, int infoClass, IntPtr buffer, ref uint size);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetOwnerModuleFromTcp6Entry(IntPtr entry, int infoClass, IntPtr buffer, ref uint size);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetOwnerModuleFromUdpEntry(IntPtr entry, int infoClass, IntPtr buffer, ref uint size);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetOwnerModuleFromUdp6Entry(IntPtr entry, int infoClass, IntPtr buffer, ref uint size);
}
