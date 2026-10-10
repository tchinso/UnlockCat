using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace UnlockCat.Core;

public enum PortProtocol
{
    Tcp,
    Udp
}

/// <summary>How a local endpoint matched the requested address and port.</summary>
public enum PortMatchKind
{
    PortOnly,
    ExactAddress,
    WildcardAddress,
    PotentialDualStack
}

/// <summary>A snapshot of one local TCP connection/listener or UDP endpoint.</summary>
public sealed record PortOwner(
    int ProcessId,
    PortProtocol Protocol,
    IPAddress LocalAddress,
    int LocalPort,
    TcpState? TcpState,
    IPAddress? RemoteAddress,
    int? RemotePort)
{
    public AddressFamily AddressFamily => LocalAddress.AddressFamily;
    public IPEndPoint LocalEndPoint => new(LocalAddress, LocalPort);
    public IPEndPoint? RemoteEndPoint => RemoteAddress is null || RemotePort is null
        ? null
        : new IPEndPoint(RemoteAddress, RemotePort.Value);

    /// <summary>Null for ScanAll; populated by Scan.</summary>
    public PortMatchKind? MatchKind { get; init; }
}

/// <summary>
/// Reads the four Windows IP Helper owner-PID tables. The returned entries are a
/// point-in-time snapshot; callers must recheck process identity before termination.
/// </summary>
public sealed class PortScanner
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorSuccess = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint InitialBufferSize = 16 * 1024;
    private const uint MaximumBufferSize = 256 * 1024 * 1024;
    private const int MaximumReadAttempts = 8;

    /// <summary>
    /// Finds local TCP and UDP endpoints for a port, localhost:port, IPv4:port, or
    /// [IPv6]:port. A specific address includes wildcard binds in that family.
    /// An IPv6 wildcard is reported as a potential dual-stack match for IPv4.
    /// </summary>
    public IReadOnlyList<PortOwner> Scan(string target)
    {
        PortQuery query = ParseQuery(target);
        List<PortOwner> matches = new();

        foreach (PortOwner entry in ScanAll())
        {
            PortMatchKind? kind = Match(query, entry);
            if (kind is not null)
            {
                matches.Add(entry with { MatchKind = kind });
            }
        }

        return matches.AsReadOnly();
    }

    /// <summary>Returns all TCP (including connected sockets) and UDP endpoints.</summary>
    public IReadOnlyList<PortOwner> ScanAll()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("PortScanner requires Windows IP Helper APIs.");
        }

        List<PortOwner> entries = new();
        ReadTcp(ReadTable(tcp: true, AfInet), ipv6: false, entries);
        ReadTcp(ReadTable(tcp: true, AfInet6), ipv6: true, entries);
        ReadUdp(ReadTable(tcp: false, AfInet), ipv6: false, entries);
        ReadUdp(ReadTable(tcp: false, AfInet6), ipv6: true, entries);

        entries.Sort(static (left, right) =>
        {
            int comparison = left.LocalPort.CompareTo(right.LocalPort);
            if (comparison != 0) return comparison;
            comparison = left.Protocol.CompareTo(right.Protocol);
            if (comparison != 0) return comparison;
            comparison = string.CompareOrdinal(left.LocalAddress.ToString(), right.LocalAddress.ToString());
            return comparison != 0 ? comparison : left.ProcessId.CompareTo(right.ProcessId);
        });

        return entries.AsReadOnly();
    }

    private static byte[] ReadTable(bool tcp, uint addressFamily)
    {
        uint capacity = InitialBufferSize;
        string tableName = $"{(tcp ? "TCP" : "UDP")}/{(addressFamily == AfInet ? "IPv4" : "IPv6")}";

        for (int attempt = 0; attempt < MaximumReadAttempts; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)capacity));
            try
            {
                uint actualSize = capacity;
                uint result = tcp
                    ? GetExtendedTcpTable(buffer, ref actualSize, false, addressFamily, TcpTableOwnerPidAll, 0)
                    : GetExtendedUdpTable(buffer, ref actualSize, false, addressFamily, UdpTableOwnerPid, 0);

                if (result == ErrorSuccess)
                {
                    if (actualSize < sizeof(uint) || actualSize > capacity)
                    {
                        throw new InvalidDataException($"Windows returned an invalid {tableName} table size.");
                    }

                    byte[] snapshot = new byte[checked((int)actualSize)];
                    Marshal.Copy(buffer, snapshot, 0, snapshot.Length);
                    return snapshot;
                }

                if (result != ErrorInsufficientBuffer)
                {
                    throw new Win32Exception(checked((int)result), $"Could not read the {tableName} owner-PID table.");
                }

                // Endpoint counts can grow between the size report and the retry.
                ulong nextSize = Math.Max((ulong)actualSize, (ulong)capacity * 2);
                if (nextSize > MaximumBufferSize)
                {
                    throw new IOException($"The {tableName} owner-PID table exceeded {MaximumBufferSize} bytes.");
                }

                capacity = (uint)nextSize;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new IOException($"The {tableName} owner-PID table changed too often to read consistently.");
    }

    private static void ReadTcp(byte[] table, bool ipv6, List<PortOwner> entries)
    {
        int rowSize = ipv6 ? 56 : 24;
        int count = ValidateTable(table, rowSize);
        ReadOnlySpan<byte> data = table;

        for (int index = 0; index < count; index++)
        {
            ReadOnlySpan<byte> row = data.Slice(4 + index * rowSize, rowSize);
            TcpState state;
            IPAddress local;
            int localPort;
            IPAddress remote;
            int remotePort;
            int processId;

            if (ipv6)
            {
                local = ReadIpv6(row, 0, 16);
                localPort = ReadPort(row, 20);
                remote = ReadIpv6(row, 24, 40);
                remotePort = ReadPort(row, 44);
                state = (TcpState)ReadUInt32(row, 48);
                processId = ReadPid(row, 52);
            }
            else
            {
                state = (TcpState)ReadUInt32(row, 0);
                local = new IPAddress(row.Slice(4, 4));
                localPort = ReadPort(row, 8);
                remote = new IPAddress(row.Slice(12, 4));
                remotePort = ReadPort(row, 16);
                processId = ReadPid(row, 20);
            }

            // The remote fields of a listening row are unspecified by Windows.
            bool listening = state == TcpState.Listen;
            entries.Add(new PortOwner(
                processId, PortProtocol.Tcp, local, localPort, state,
                listening ? null : remote, listening ? null : remotePort));
        }
    }

    private static void ReadUdp(byte[] table, bool ipv6, List<PortOwner> entries)
    {
        int rowSize = ipv6 ? 28 : 12;
        int count = ValidateTable(table, rowSize);
        ReadOnlySpan<byte> data = table;

        for (int index = 0; index < count; index++)
        {
            ReadOnlySpan<byte> row = data.Slice(4 + index * rowSize, rowSize);
            IPAddress address = ipv6
                ? ReadIpv6(row, 0, 16)
                : new IPAddress(row.Slice(0, 4));
            int port = ReadPort(row, ipv6 ? 20 : 4);
            int processId = ReadPid(row, ipv6 ? 24 : 8);
            entries.Add(new PortOwner(processId, PortProtocol.Udp, address, port, null, null, null));
        }
    }

    private static int ValidateTable(byte[] table, int rowSize)
    {
        if (table.Length < sizeof(uint))
        {
            throw new InvalidDataException("Windows returned a truncated owner-PID table.");
        }

        uint count = ReadUInt32(table, 0);
        if (count > (table.Length - sizeof(uint)) / rowSize)
        {
            throw new InvalidDataException("Windows returned an invalid owner-PID row count.");
        }

        return checked((int)count);
    }

    private static IPAddress ReadIpv6(ReadOnlySpan<byte> row, int addressOffset, int scopeOffset)
    {
        long scope = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(scopeOffset, sizeof(uint)));
        return new IPAddress(row.Slice(addressOffset, 16), scope);
    }

    private static int ReadPort(ReadOnlySpan<byte> row, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(row.Slice(offset, sizeof(ushort)));

    private static uint ReadUInt32(ReadOnlySpan<byte> row, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(offset, sizeof(uint)));

    private static int ReadPid(ReadOnlySpan<byte> row, int offset)
    {
        uint pid = ReadUInt32(row, offset);
        if (pid > int.MaxValue)
        {
            throw new InvalidDataException($"Windows returned an out-of-range process ID: {pid}.");
        }

        return (int)pid;
    }

    private static PortQuery ParseQuery(string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        string input = target.Trim();
        string? addressText = null;
        string portText;

        if (input.StartsWith('['))
        {
            int closingBracket = input.IndexOf(']');
            if (closingBracket <= 1 || closingBracket + 1 >= input.Length || input[closingBracket + 1] != ':')
            {
                throw new FormatException("An IPv6 endpoint must use [address]:port.");
            }

            addressText = input[1..closingBracket];
            portText = input[(closingBracket + 2)..];
        }
        else
        {
            int colon = input.IndexOf(':');
            if (colon < 0)
            {
                portText = input;
            }
            else
            {
                if (input.LastIndexOf(':') != colon || colon == 0)
                {
                    throw new FormatException("An IPv6 endpoint must use [address]:port.");
                }

                addressText = input[..colon];
                portText = input[(colon + 1)..];
            }
        }

        if (!ushort.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out ushort port) || port == 0)
        {
            throw new FormatException("Enter a port from 1 through 65535.");
        }

        if (addressText is null)
        {
            return new PortQuery(port, null, false);
        }

        if (addressText.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return new PortQuery(port, null, true);
        }

        if (!IPAddress.TryParse(addressText, out IPAddress? address) ||
            (!input.StartsWith('[') && address.AddressFamily != AddressFamily.InterNetwork) ||
            (input.StartsWith('[') && address.AddressFamily != AddressFamily.InterNetworkV6))
        {
            throw new FormatException("Enter localhost, an IPv4 address, or a bracketed IPv6 address.");
        }

        return new PortQuery(port, address, false);
    }

    private static PortMatchKind? Match(PortQuery query, PortOwner owner)
    {
        if (query.Port != owner.LocalPort)
        {
            return null;
        }

        if (query.Address is null && !query.Localhost)
        {
            return PortMatchKind.PortOnly;
        }

        IPAddress local = owner.LocalAddress;
        if (query.Localhost)
        {
            if (IsWildcard(local)) return PortMatchKind.WildcardAddress;
            if (IPAddress.IsLoopback(local) ||
                (local.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(local.MapToIPv4())))
            {
                return PortMatchKind.ExactAddress;
            }

            return null;
        }

        IPAddress address = query.Address!;
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IsWildcard(address))
        {
            if (local.AddressFamily == address.AddressFamily)
            {
                return IsWildcard(local) ? PortMatchKind.WildcardAddress : PortMatchKind.ExactAddress;
            }

            return address.AddressFamily == AddressFamily.InterNetworkV6
                ? PortMatchKind.PotentialDualStack
                : IsWildcard(local) ? PortMatchKind.PotentialDualStack : null;
        }

        if (local.AddressFamily == address.AddressFamily)
        {
            if (local.Equals(address)) return PortMatchKind.ExactAddress;
            return IsWildcard(local) ? PortMatchKind.WildcardAddress : null;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork &&
            local.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (local.IsIPv4MappedToIPv6 && local.MapToIPv4().Equals(address))
            {
                return PortMatchKind.ExactAddress;
            }

            if (IsWildcard(local)) return PortMatchKind.PotentialDualStack;
        }

        return null;
    }

    private static bool IsWildcard(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    private readonly record struct PortQuery(int Port, IPAddress? Address, bool Localhost);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        uint addressFamily,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr table,
        ref uint size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        uint addressFamily,
        int tableClass,
        uint reserved);
}
