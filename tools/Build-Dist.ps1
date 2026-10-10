param(
    [string]$DotnetPath,
    [switch]$ValidationAsInvoker
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$project = Join-Path $repository 'src\UnlockCat\UnlockCat.csproj'
$manifest = Join-Path $repository 'src\UnlockCat\app.manifest'
$artifacts = Join-Path $repository 'artifacts'
$dist = if ($ValidationAsInvoker) {
    Join-Path $artifacts 'validation-customhost'
} else {
    Join-Path $repository 'dist'
}

if (-not $DotnetPath) {
    $command = Get-Command dotnet -ErrorAction SilentlyContinue
    $DotnetPath = if ($command) { $command.Source } else { Join-Path $env:USERPROFILE '.dotnet\dotnet.exe' }
}
$DotnetPath = (Resolve-Path -LiteralPath $DotnetPath).Path
$dotnetRoot = Split-Path -Parent $DotnetPath
$packRoot = Join-Path $dotnetRoot 'packs\Microsoft.NETCore.App.Host.win-x64'
$singleFileHostPath = Get-ChildItem -LiteralPath $packRoot -Directory |
    Where-Object { $_.Name -like '10.*' } |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName 'runtimes\win-x64\native\singlefilehost.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $singleFileHostPath) { throw 'The .NET 10 win-x64 single-file host pack was not found.' }

if (-not ('UnlockCat.NativeManifest' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace UnlockCat {
    public static class NativeManifest {
        private static readonly IntPtr ResourceType = new IntPtr(24);
        private static readonly IntPtr ResourceName = new IntPtr(1);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool ResourceLanguageCallback(
            IntPtr module, IntPtr type, IntPtr name, ushort language, IntPtr parameter);

        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr module);

        [DllImport("kernel32.dll", EntryPoint = "EnumResourceLanguagesW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumResourceLanguages(
            IntPtr module, IntPtr type, IntPtr name, ResourceLanguageCallback callback, IntPtr parameter);

        [DllImport("kernel32.dll", EntryPoint = "FindResourceW", SetLastError = true)]
        private static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SizeofResource(IntPtr module, IntPtr resource);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadResource(IntPtr module, IntPtr resource);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LockResource(IntPtr loadedResource);

        [DllImport("kernel32.dll", EntryPoint = "BeginUpdateResourceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr BeginUpdateResource(string path, [MarshalAs(UnmanagedType.Bool)] bool deleteExisting);

        [DllImport("kernel32.dll", EntryPoint = "UpdateResourceW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateResource(
            IntPtr update, IntPtr type, IntPtr name, ushort language, byte[] data, uint length);

        [DllImport("kernel32.dll", EntryPoint = "EndUpdateResourceW", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EndUpdateResource(IntPtr update, [MarshalAs(UnmanagedType.Bool)] bool discard);

        public static string Read(string executable) {
            var module = LoadLibraryEx(executable, IntPtr.Zero, 2);
            if (module == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                var resource = FindResource(module, ResourceName, ResourceType);
                if (resource == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                var size = SizeofResource(module, resource);
                var loaded = LoadResource(module, resource);
                if (loaded == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                var pointer = LockResource(loaded);
                if (pointer == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                var bytes = new byte[checked((int)size)];
                Marshal.Copy(pointer, bytes, 0, bytes.Length);
                return Encoding.UTF8.GetString(bytes);
            } finally {
                FreeLibrary(module);
            }
        }

        public static void Replace(string executable, byte[] manifest) {
            var module = LoadLibraryEx(executable, IntPtr.Zero, 2); // LOAD_LIBRARY_AS_DATAFILE
            if (module == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            var languages = new List<ushort>();
            try {
                ResourceLanguageCallback callback = (handle, type, name, language, parameter) => {
                    languages.Add(language);
                    return true;
                };
                if (!EnumResourceLanguages(module, ResourceType, ResourceName, callback, IntPtr.Zero)) {
                    var error = Marshal.GetLastWin32Error();
                    if (error != 1813 && error != 1814 && error != 1815)
                        throw new Win32Exception(error);
                }
            } finally {
                FreeLibrary(module);
            }
            if (languages.Count == 0) languages.Add(0); // The runtime host template has no manifest resource.

            var update = BeginUpdateResource(executable, false);
            if (update == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            var discard = true;
            try {
                foreach (var language in languages)
                    if (!UpdateResource(update, ResourceType, ResourceName, language, manifest, (uint)manifest.Length))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                discard = false;
            } finally {
                if (!EndUpdateResource(update, discard))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
'@
}

New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$customHost = Join-Path $artifacts $(if ($ValidationAsInvoker) { 'singlefilehost-validation.exe' } else { 'singlefilehost-admin.exe' })
Copy-Item -LiteralPath $singleFileHostPath -Destination $customHost -Force
$manifestText = [IO.File]::ReadAllText($manifest)
$publishManifest = $manifest
if ($ValidationAsInvoker) {
    $manifestText = $manifestText.Replace('requireAdministrator', 'asInvoker')
    $publishManifest = Join-Path $artifacts 'validation.asInvoker.manifest'
    [IO.File]::WriteAllText($publishManifest, $manifestText, [Text.Encoding]::UTF8)
}
[UnlockCat.NativeManifest]::Replace($customHost, [Text.Encoding]::UTF8.GetBytes($manifestText))

& $DotnetPath publish $project -t:Rebuild -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true -p:DebugType=None -p:DebugSymbols=false `
    "-p:ApplicationManifest=$publishManifest" `
    "-p:SingleFileHostSourcePath=$customHost" -o $dist -v minimal
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

$exe = Join-Path $dist 'UnlockCat.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'The publish did not create UnlockCat.exe.' }
$embeddedManifest = [UnlockCat.NativeManifest]::Read($exe)
$expectedLevel = if ($ValidationAsInvoker) { 'asInvoker' } else { 'requireAdministrator' }
if (-not $embeddedManifest.Contains("level=`"$expectedLevel`"")) {
    throw "The published EXE does not contain the $expectedLevel manifest."
}
Write-Output "Created $exe"
Get-FileHash -LiteralPath $exe -Algorithm SHA256 | Select-Object Algorithm, Hash, Path
