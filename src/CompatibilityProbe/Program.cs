using System.Text.Json;
using UAssetAPI.Unversioned;

namespace CompatibilityProbe;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--help")
        {
            Console.WriteLine("CompatibilityProbe <asset-or-directory> <report.json> [mappings.usmap]");
            Console.WriteLine("Trusted local UE 4.25 compatibility experiments only. No policy evaluation or safety verdict.");
            Console.WriteLine("Exit: 0 = parser experiment complete; 2 = incomplete; 1 = usage/configuration/report error.");
            return 0;
        }
        if (args.Length is < 2 or > 3)
        {
            Console.Error.WriteLine("Usage: CompatibilityProbe <asset-or-directory> <report.json> [mappings.usmap]");
            return 1;
        }
        try
        {
            var input = Path.GetFullPath(args[0]);
            var output = Path.GetFullPath(args[1]);
            var directory = Directory.Exists(input);
            var paths = directory
                ? Directory.EnumerateFiles(input, "*", SearchOption.AllDirectories).Where(IsPackage).Order(StringComparer.Ordinal).ToArray()
                : IsPackage(input) && File.Exists(input) ? [input] : [];
            if (paths.Length == 0)
                throw new ArgumentException("No supported packages.");
            // Refuse to overwrite a package/sidecar or mappings file with its report.
            if (IsPackage(output) || Path.GetExtension(output).ToLowerInvariant() is ".uexp" or ".ubulk" or ".usmap"
                || paths.Contains(output, StringComparer.Ordinal) || File.Exists(output))
                throw new ArgumentException("Report must be a new non-asset file.");
            var mappings = args.Length == 3 ? new Usmap(args[2]) : null;
            var reports = paths.Select(path => Probe.Read(path,
                directory ? Path.GetRelativePath(input, path).Replace('\\', '/') : Path.GetFileName(path), mappings)).ToArray();
            var report = new ProbeReport(reports);
            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower,
                WriteIndented = true
            });
            using (var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(stream))
                writer.WriteLine(json);
            Console.WriteLine($"Packages={reports.Length}; functions={reports.Sum(a => a.Functions)}; invocations={reports.Sum(a => a.Invocations.Length)}; diagnostics={reports.Sum(a => a.Diagnostics.Length)}.");
            Console.WriteLine("Compatibility experiment only; analysis-complete=false. Read the report limitations.");
            return report.ParseComplete ? 0 : 2;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            Console.Error.WriteLine($"Probe configuration/report error ({error.GetType().Name}). No safety verdict produced.");
            return 1;
        }
    }

    private static bool IsPackage(string path) => Path.GetExtension(path).ToLowerInvariant() is ".uasset" or ".umap";
}
