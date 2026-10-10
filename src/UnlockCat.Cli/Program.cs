using UnlockCat.Core;

if (args.Length != 3 || !new[] { "scan", "unlock" }.Contains(args[0], StringComparer.OrdinalIgnoreCase) ||
    !new[] { "file", "volume", "port", "service" }.Contains(args[1], StringComparer.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("Usage: unlockcat scan|unlock file|volume|port|service <path|drive|endpoint|name>");
    Console.Error.WriteLine("Examples: unlockcat scan file C:\\temp\\busy.txt");
    Console.Error.WriteLine("          unlockcat unlock volume E:\\");
    Console.Error.WriteLine("          unlockcat unlock port localhost:5000");
    Console.Error.WriteLine("          unlockcat unlock service Spooler");
    return 2;
}

try
{
    var action = args[0].ToLowerInvariant();
    var kind = args[1].ToLowerInvariant();
    var target = args[2];
    ProcessControl.TryEnableDebugPrivilege(out _);

    if (kind == "service")
    {
        var service = ServiceControl.ListServices()
            .FirstOrDefault(s => s.Name.Equals(target, StringComparison.OrdinalIgnoreCase));
        if (service is null)
        {
            Console.Error.WriteLine($"Service '{target}' was not found or could not be inspected.");
            return 3;
        }
        Console.WriteLine($"{service.Name} — {service.DisplayName}; PID {service.ProcessId}; {service.State}; start {service.StartType}");
        if (action == "scan")
            return 0;
        var result = ServiceControl.StopService(service, TimeSpan.FromSeconds(30));
        Console.WriteLine(result.Message);
        return result.Succeeded ? 0 : 3;
    }

    var first = Scan(kind, target);
    Print(first);
    if (action == "scan")
        return first.Complete ? 0 : 3;

    if (first.ConfirmedPids.Count == 0)
        return first.Owners.Count == 0 && first.Complete ? 0 : 3;

    // The target can change between discovery and action. Verify ownership again,
    // and use the creation time from the first scan to reject recycled PIDs.
    var identities = first.ConfirmedPids.ToDictionary(pid => pid, ProcessControl.Describe);
    var current = Scan(kind, target);
    var failed = false;
    foreach (var (pid, identity) in identities)
    {
        if (!current.ConfirmedPids.Contains(pid))
        {
            Console.WriteLine($"PID {pid}: no longer owns the requested resource; skipped.");
            continue;
        }

        var result = ProcessControl.Terminate(identity, TimeSpan.FromSeconds(10));
        Console.WriteLine($"PID {pid}: {result.Message}");
        failed |= !result.Succeeded;
    }

    var after = Scan(kind, target);
    Console.WriteLine("After termination:");
    Print(after);
    return after.ConfirmedPids.Count == 0 && after.Complete && !failed ? 0 : 3;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"UnlockCat: {ex.Message}");
    return 1;
}

static ScanResult Scan(string kind, string target)
{
    var owners = new Dictionary<int, List<string>>();
    var confirmedPids = new HashSet<int>();
    var complete = true;
    var diagnostics = new List<string>();

    if (kind == "port")
    {
        foreach (var endpoint in new PortScanner().Scan(target))
        {
            if (endpoint.ProcessId <= 0)
            {
                complete = false;
                diagnostics.Add($"Unattributed Windows endpoint: {endpoint.Protocol} {endpoint.LocalEndPoint} {endpoint.TcpState}");
                continue;
            }
            var moduleLabel = "";
            try
            {
                var module = PortModuleResolver.Resolve(endpoint);
                if (module.HasModule)
                    moduleLabel = $"; module {module.ModuleName}";
            }
            catch (Exception ex)
            {
                diagnostics.Add($"Owner-module lookup failed for PID {endpoint.ProcessId}: {ex.Message}");
            }
            Add(endpoint.ProcessId,
                $"{endpoint.Protocol} {endpoint.LocalEndPoint} {endpoint.TcpState?.ToString() ?? "UDP"} ({endpoint.MatchKind}){moduleLabel}");
            if (endpoint.MatchKind != PortMatchKind.PotentialDualStack)
                confirmedPids.Add(endpoint.ProcessId);
        }
    }
    else
    {
        var result = kind == "file" ? FileLockScanner.ScanFile(target) : FileLockScanner.ScanVolume(target);
        foreach (var owner in result.Owners)
            Add(owner.Pid, $"{owner.Kind}: {owner.EvidencePath}");
        foreach (var owner in result.Owners)
            confirmedPids.Add(owner.Pid);
        complete = result.IsComplete;
        diagnostics.AddRange(result.Errors);
        if (result.InaccessibleProcesses.Count > 0)
            diagnostics.Add($"{result.InaccessibleProcesses.Count} processes could not be inspected.");
    }

    return new ScanResult(owners, confirmedPids, complete, diagnostics);

    void Add(int pid, string evidence)
    {
        if (!owners.TryGetValue(pid, out var list))
            owners.Add(pid, list = []);
        list.Add(evidence);
    }
}

static void Print(ScanResult result)
{
    Dictionary<int, string> serviceNames = [];
    if (result.Owners.Count > 0)
    {
        try
        {
            serviceNames = ServiceControl.ListServices()
                .Where(s => s.ProcessId > 0 && s.State != ServiceState.Stopped)
                .GroupBy(s => s.ProcessId)
                .ToDictionary(g => g.Key, g => string.Join(", ", g.Select(s => s.Name)));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Service lookup incomplete: {ex.Message}");
        }
    }
    if (result.Owners.Count == 0)
        Console.WriteLine("No owning process found.");
    foreach (var (pid, evidence) in result.Owners.OrderBy(kv => kv.Key))
    {
        var process = ProcessControl.Describe(pid);
        Console.WriteLine($"PID {pid}  {process.Name}  {process.ImagePath ?? "(path unavailable)"}");
        if (serviceNames.TryGetValue(pid, out var names))
            Console.WriteLine($"  services: {names}");
        foreach (var item in evidence.Distinct(StringComparer.OrdinalIgnoreCase))
            Console.WriteLine($"  {item}");
    }
    if (!result.Complete)
        Console.WriteLine("Scan incomplete: some processes or resources were inaccessible.");
    foreach (var diagnostic in result.Diagnostics)
        Console.Error.WriteLine(diagnostic);
}

internal sealed record ScanResult(
    Dictionary<int, List<string>> Owners,
    HashSet<int> ConfirmedPids,
    bool Complete,
    List<string> Diagnostics);
