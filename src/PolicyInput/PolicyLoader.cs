using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;
using PakRisk.Policy;

namespace PakRisk.PolicyInput;

public enum PolicyLogLevel { Error, Warn, Info, Verbose }

// No source paths, supplied values, or upstream exceptions.
public sealed class PolicyInputException(string code) : Exception($"Policy input failed ({code}).")
{
    public string Code { get; } = code;
}

// Not a record: automatic string conversion must not expose the AST.
public sealed class LoadedPolicy
{
    internal LoadedPolicy(PolicyDocument document) => Document = document;
    [JsonIgnore]
    public PolicyDocument Document { get; }
    public override string ToString() => "LoadedPolicy";
}

public static class PolicyLoader
{
    public const string EnvironmentName = "UE_PAK_POLICY_RULES";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static PolicyLogLevel ParseLogLevel(string? value) => value switch
    {
        null or "info" => PolicyLogLevel.Info,
        "error" => PolicyLogLevel.Error,
        "warn" => PolicyLogLevel.Warn,
        "verbose" => PolicyLogLevel.Verbose,
        _ => throw new PolicyInputException("invalid-log-level")
    };

    // The injected reader must return null only for an absent variable, never for empty.
    // It is trusted transport code; production uses bounded raw libc getenv bytes.
    public static LoadedPolicy Load(string? filePath = null, string? logLevel = null,
        Action<string>? log = null, int maxBytes = PolicyYaml.MaxInputBytes,
        CancellationToken cancellationToken = default, Func<int, byte[]?>? readEnvironment = null)
    {
        var level = ParseLogLevel(logLevel); // Before reading either policy source.
        if (maxBytes < 1 || maxBytes > PolicyYaml.MaxInputBytes)
            throw new PolicyInputException("invalid-size-limit");
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? bytes = null;
        try
        {
            if (readEnvironment is null) bytes = LinuxPolicySource.ReadEnvironment(maxBytes);
            else
            {
                try { bytes = readEnvironment(maxBytes); }
                catch (Exception) { throw new PolicyInputException("source-or-log-failure"); }
            }
            if (filePath is not null && bytes is not null)
                throw new PolicyInputException("conflicting-sources");
            if (filePath is null && bytes is null)
                throw new PolicyInputException("missing-source");
            if (filePath is not null)
                bytes = LinuxPolicySource.ReadFile(filePath, maxBytes, cancellationToken);
            if (bytes!.Length > maxBytes)
                throw new PolicyInputException("size-limit");
            cancellationToken.ThrowIfCancellationRequested();
            return Parse(bytes, level, log, cancellationToken);
        }
        catch (PolicyInputException) { throw; }
        catch (PolicyException) { throw; }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Do not retain caller-supplied exception messages or tokens in diagnostics.
            throw new OperationCanceledException();
        }
        catch (Exception)
        {
            throw new PolicyInputException("source-or-log-failure");
        }
        finally
        {
            if (bytes is not null) Array.Clear(bytes);
        }
    }

    private static LoadedPolicy Parse(byte[] bytes, PolicyLogLevel level, Action<string>? log,
        CancellationToken cancellationToken)
    {
        string supplied;
        try { supplied = StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException) { throw new PolicyInputException("invalid-utf8"); }
        if (level == PolicyLogLevel.Verbose)
        {
            try
            {
                log?.Invoke("WARNING: VERBOSE DISCLOSES THE FULL POLICY TO EVERYONE WITH LOG ACCESS. Escaped policy follows.");
                log?.Invoke(Escape(supplied));
            }
            catch (Exception) { throw new PolicyInputException("source-or-log-failure"); }
        }
        cancellationToken.ThrowIfCancellationRequested();
        // UTF-8 BOM is accepted and logged, but is not part of the YAML document.
        var yaml = supplied.StartsWith('\uFEFF') ? supplied[1..] : supplied;
        if (string.IsNullOrWhiteSpace(yaml)) throw new PolicyInputException("empty-source");
        return new LoadedPolicy(PolicyYaml.Parse(yaml));
    }

    // Reversible representation blocks both :: commands and legacy ##[ commands.
    // Backslash, colon, hash, and controls become \uXXXX escapes; LF remains.
    internal static string Escape(string text)
    {
        var output = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            var category = char.GetUnicodeCategory(c);
            if (c is '\\' or ':' or '#' || (c != '\n' && (char.IsControl(c)
                || category is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)))
                output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            else output.Append(c);
        }
        return output.ToString();
    }

    // Call only with reviewed, nonsecret allowlisted values. Never copy the host environment.
    // This is a helper for a future trusted orchestration stage, not current parser integration.
    public static void SetParserEnvironment(ProcessStartInfo startInfo, IReadOnlyDictionary<string, string> allowlisted)
    {
        if (allowlisted.Keys.Any(key => key.Equals(EnvironmentName, StringComparison.OrdinalIgnoreCase)))
            throw new PolicyInputException("policy-in-parser-environment");
        startInfo.Environment.Clear();
        foreach (var (key, value) in allowlisted) startInfo.Environment.Add(key, value);
    }
}
