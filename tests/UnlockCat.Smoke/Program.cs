using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using UnlockCat.Core;

if (args.Length > 0)
{
    if (args[0] == "hold-file")
    {
        using var file = new FileStream(args[1], FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        Console.WriteLine("READY");
        Console.Out.Flush();
        Thread.Sleep(Timeout.Infinite);
        return 0;
    }
    if (args[0] == "hold-port")
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Console.WriteLine(((IPEndPoint)listener.LocalEndpoint).Port);
        Console.Out.Flush();
        Thread.Sleep(Timeout.Infinite);
        return 0;
    }
}

var temporaryDirectory = Path.Combine(Path.GetTempPath(), $"UnlockCat-smoke-{Guid.NewGuid():N}");
var nestedDirectory = Path.Combine(temporaryDirectory, "nested");
var temporaryFile = Path.Combine(nestedDirectory, "held.txt");
var siblingDirectory = temporaryDirectory + "-outside";
var siblingFile = Path.Combine(siblingDirectory, "held.txt");
var children = new List<Process>();
Directory.CreateDirectory(nestedDirectory);
Directory.CreateDirectory(siblingDirectory);
File.WriteAllText(temporaryFile, "UnlockCat smoke test");
File.WriteAllText(siblingFile, "Outside the selected folder");
try
{
    var explorerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
    Assert(ProcessControl.IsWindowsExplorerImage(explorerPath.ToUpperInvariant()),
        "Windows Explorer path matching should ignore case.");
    Assert(!ProcessControl.IsWindowsExplorerImage(Path.Combine(temporaryDirectory, "explorer.exe")),
        "An unrelated explorer.exe must not be treated as the Windows shell.");

    {
        var holder = Launch("hold-file", temporaryFile);
        Assert(holder.StandardOutput.ReadLine() == "READY", "File holder did not start.");
        var outsideHolder = Launch("hold-file", siblingFile);
        Assert(outsideHolder.StandardOutput.ReadLine() == "READY", "Outside file holder did not start.");
        var file = FileLockScanner.ScanFile(temporaryFile);
        Assert(file.Owners.Any(o => o.Pid == holder.Id && o.Kind == "file-handle"),
            "Held file was not found through handle enumeration.");
        var directory = FileLockScanner.ScanDirectory(temporaryDirectory);
        Assert(directory.Owners.Any(o => o.Pid == holder.Id &&
            o.EvidencePath.Contains("nested", StringComparison.OrdinalIgnoreCase)),
            "Held nested file was not found in directory scan.");
        Assert(!directory.Owners.Any(o => o.Pid == outsideHolder.Id),
            "Directory scan included a file outside the selected folder.");
        var root = Path.GetPathRoot(temporaryFile)!;
        var volume = FileLockScanner.ScanVolume(root);
        Assert(volume.Owners.Any(o => o.Pid == holder.Id && o.EvidencePath.Contains(Path.GetFileName(temporaryFile), StringComparison.OrdinalIgnoreCase)),
            "Held file was not found in volume scan.");
        Console.WriteLine($"File, directory and volume lookup: PASS (inaccessible processes: {file.InaccessibleProcessCount}/{directory.InaccessibleProcessCount}/{volume.InaccessibleProcessCount})");

        var identity = ProcessControl.Describe(holder.Id);
        Assert(identity.CreationTimeFileTime.HasValue, "Process identity could not be read.");
        var wrongIdentity = identity with { CreationTimeFileTime = identity.CreationTimeFileTime + 1 };
        Assert(ProcessControl.Terminate(wrongIdentity).Status == TerminationStatus.IdentityChanged,
            "PID reuse protection did not reject a wrong creation time.");
        Assert(!holder.HasExited, "Wrong identity terminated the file holder.");
        var claimedExplorer = identity with { Name = "explorer.exe", ImagePath = explorerPath };
        var terminated = ProcessControl.TerminateOrRestartExplorer(claimedExplorer);
        Assert(terminated.Status == TerminationStatus.Terminated,
            $"The actual image path was not checked before termination: {terminated.Message}");
        Assert(!FileLockScanner.ScanFile(temporaryFile).Owners.Any(o => o.Pid == holder.Id),
            "File holder was still reported after termination.");
        Console.WriteLine("Verified force termination and release: PASS");
    }

    {
        var holder = Launch("hold-port");
        Assert(int.TryParse(holder.StandardOutput.ReadLine(), out var port), "Port holder did not start.");
        var scanner = new PortScanner();
        Assert(scanner.Scan($"localhost:{port}").Any(o => o.ProcessId == holder.Id && o.TcpState == TcpState.Listen),
            "TCP listener owner was not found.");
        var identity = ProcessControl.Describe(holder.Id);
        Assert(ProcessControl.Terminate(identity).Succeeded, "Port holder termination failed.");
        Assert(!scanner.Scan($"127.0.0.1:{port}").Any(o => o.ProcessId == holder.Id && o.TcpState == TcpState.Listen),
            "TCP listener remained after termination.");
        Console.WriteLine("Port lookup and release: PASS");
    }

    Assert(ServiceControl.ListServices().Count > 0, "Windows services could not be enumerated.");
    Console.WriteLine("Service enumeration: PASS");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}
finally
{
    foreach (var child in children)
    {
        try
        {
            if (!child.HasExited)
            {
                child.Kill(entireProcessTree: true);
                child.WaitForExit(2000);
            }
        }
        catch { }
        child.Dispose();
    }
    try { Directory.Delete(temporaryDirectory, recursive: true); } catch { }
    try { Directory.Delete(siblingDirectory, recursive: true); } catch { }
}

Process Launch(params string[] childArgs)
{
    var executable = Environment.ProcessPath!;
    var isDotnet = Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase);
    var start = new ProcessStartInfo(executable)
    {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };
    if (isDotnet)
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
    foreach (var arg in childArgs)
        start.ArgumentList.Add(arg);
    var child = Process.Start(start) ?? throw new InvalidOperationException("Could not launch child process.");
    children.Add(child);
    return child;
}

static void Assert(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}
