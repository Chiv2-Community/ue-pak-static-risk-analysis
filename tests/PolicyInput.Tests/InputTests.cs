using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PakRisk.Policy;
using PakRisk.PolicyInput;
using Xunit;

namespace PolicyInput.Tests;

public sealed class InputTests : IDisposable
{
    private const string Yaml = """
        schema-version: 1
        rules:
          - id: private-canary-id
            description: 'private-canary-description $HOME `whoami` $(touch NEVER) & * !'
            effect: forbid
            expression:
              argument:
                name: URL
                predicate:
                  kind: regex-match
                  pattern: '^private-canary-literal'
        """;
    private readonly string directory = Path.Combine("/tmp/opencode", "policy-input-tests-" + Guid.NewGuid().ToString("N"));
    public InputTests() => Directory.CreateDirectory(directory);
    public void Dispose() => Directory.Delete(directory, recursive: true);
    private static Func<int, byte[]?> Env(string? text) => _ => text is null ? null : Encoding.UTF8.GetBytes(text);
    private string Write(byte[] bytes)
    {
        var path = Path.Combine(directory, "private-canary-path");
        File.WriteAllBytes(path, bytes);
        return path;
    }
    private static string Decode(string escaped) => Regex.Replace(escaped, @"\\u([0-9a-f]{4})",
        match => ((char)Convert.ToInt32(match.Groups[1].Value, 16)).ToString());
    private static void NoCanaries(string text)
    {
        foreach (var canary in new[] { "private-canary-id", "private-canary-description", "private-canary-literal", "private-canary-path", "unrelated-secret" })
            Assert.DoesNotContain(canary, text);
    }

    [Theory]
    [InlineData("error")]
    [InlineData("warn")]
    [InlineData("info")]
    [InlineData("verbose")]
    [InlineData(null)]
    public void FileAndEnvironmentHaveIdenticalSemanticsAtEveryLevel(string? level)
    {
        var logs = new List<string>();
        var path = Write(Encoding.UTF8.GetBytes(Yaml));
        var file = PolicyLoader.Load(path, level, logs.Add, readEnvironment: Env(null));
        var env = PolicyLoader.Load(logLevel: level, log: logs.Add, readEnvironment: Env(Yaml));
        Assert.Equal(PolicyYaml.Write(file.Document), PolicyYaml.Write(env.Document));
        var analysis = new InvocationAnalysis([new(new("/Game/Test", "Run", 0),
            new InvocationTarget.Resolved("/Script/Engine.KismetSystemLibrary", "LaunchURL"),
            new ArgumentMetadata.Known([new("URL", new ArgumentValue.Constant(new PolicyLiteral.String("private-canary-literal/test")))]))], []);
        var expected = new PolicyEvaluator(PolicyYaml.Parse(Yaml)).Evaluate(analysis);
        var actual = new PolicyEvaluator(env.Document).Evaluate(analysis);
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        Assert.NotEmpty(actual.Findings);
        NoCanaries(env.ToString());
        NoCanaries(JsonSerializer.Serialize(env));
        if (level == "verbose")
        {
            Assert.Equal(4, logs.Count);
            Assert.StartsWith("WARNING:", logs[0]);
            Assert.Equal(Yaml, Decode(logs[1]));
            Assert.Equal(Yaml, Decode(logs[3]));
        }
        else NoCanaries(string.Join('\n', logs));
        Assert.Single(Directory.GetFiles(directory));
    }

    [Theory]
    [InlineData("error")]
    [InlineData("warn")]
    [InlineData("info")]
    [InlineData("verbose")]
    public void MalformedYamlIsDisclosedOnlyAtVerbose(string level)
    {
        var source = Yaml + "\n: [private-canary-literal";
        var logs = new List<string>();
        foreach (var file in new[] { false, true })
        {
            logs.Clear();
            var exception = Assert.Throws<PolicyException>(() => PolicyLoader.Load(
                file ? Write(Encoding.UTF8.GetBytes(source)) : null, level, logs.Add,
                readEnvironment: Env(file ? null : source)));
            NoCanaries(exception.ToString());
            if (level == "verbose")
            {
                Assert.StartsWith("WARNING:", logs[0]);
                Assert.Equal(source, Decode(logs[1]));
            }
            else NoCanaries(string.Join('\n', logs));
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("VERBOSE")]
    [InlineData("private-canary-literal")]
    public void InvalidLevelNeverReadsOrDiscloses(string level)
    {
        var logs = new List<string>();
        var exception = Assert.Throws<PolicyInputException>(() => PolicyLoader.Load("private-canary-path", level, logs.Add,
            readEnvironment: _ => throw new Exception("must not read")));
        Assert.Equal("invalid-log-level", exception.Code);
        NoCanaries(exception.ToString());
        Assert.Empty(logs);
    }

    [Theory]
    [InlineData(null, null, "missing-source")]
    [InlineData(null, "", "empty-source")]
    [InlineData(null, " \n\t", "empty-source")]
    [InlineData("private-canary-path", "", "conflicting-sources")]
    [InlineData("private-canary-path", "x", "conflicting-sources")]
    [InlineData("", null, "invalid-file-source")]
    [InlineData("private-canary-path", null, "file-open-failed")]
    public void SourceSelectionFailsClosed(string? path, string? env, string code)
    {
        var exception = Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(path, readEnvironment: Env(env)));
        Assert.Equal(code, exception.Code);
        NoCanaries(exception.ToString());
        Assert.Empty(Directory.GetFiles(directory));
    }

    [Fact]
    public void StrictEncodingBoundsAndBom()
    {
        foreach (var bytes in new[] { new byte[] { 0xff }, new byte[] { 0xc0, 0xaf }, new byte[] { 0xe2, 0x82 }, new byte[] { 0xed, 0xa0, 0x80 } })
        foreach (var file in new[] { false, true })
        {
            var logs = new List<string>();
            var exception = Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(file ? Write(bytes) : null,
                "verbose", logs.Add, readEnvironment: _ => file ? null : bytes.ToArray()));
            Assert.Equal("invalid-utf8", exception.Code);
            Assert.Empty(logs);
        }
        var valid = Encoding.UTF8.GetBytes(Yaml);
        foreach (var file in new[] { false, true })
        {
            var path = file ? Write(valid) : null;
            Assert.NotNull(PolicyLoader.Load(path, maxBytes: valid.Length, readEnvironment: _ => file ? null : valid.ToArray()));
            var exception = Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(path,
                maxBytes: valid.Length - 1, readEnvironment: _ => file ? null : valid.ToArray()));
            Assert.Equal("size-limit", exception.Code);
        }
        Assert.NotNull(PolicyLoader.Load(readEnvironment: Env("\uFEFF" + Yaml)));
        Assert.NotNull(PolicyLoader.Load(Write(Encoding.UTF8.GetBytes("\uFEFF" + Yaml)), readEnvironment: Env(null)));
        Assert.Equal("empty-source", Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(readEnvironment: Env("\uFEFF"))).Code);
        Assert.Equal("invalid-size-limit", Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(maxBytes: 0)).Code);
    }

    [Fact]
    public void VerboseRenderingIsReversibleAndCannotRunWorkflowOrTerminalCommands()
    {
        var source = "::add-mask::canary\n::stop-commands::attacker\n::attacker::\n" +
            "##[error]forged annotation\nprefix ##[add-mask]canary\n" +
            "\u001b[2J\r\b\0\t\u0085\u202e\u2028\u2029\\u003a\n" + Yaml;
        var logs = new List<string>();
        Assert.Throws<PolicyException>(() => PolicyLoader.Load(logLevel: "verbose", log: logs.Add, readEnvironment: Env(source)));
        Assert.StartsWith("WARNING:", logs[0]);
        Assert.Equal(source, Decode(logs[1]));
        Assert.DoesNotContain(':', logs[1]);
        Assert.DoesNotContain('#', logs[1]);
        Assert.All(logs[1], c => Assert.False((char.IsControl(c) && c != '\n') || c is '\u202e' or '\u2028' or '\u2029'));
    }

    [DllImport("libc", EntryPoint = "mkfifo")]
    private static extern int MkFifo(string path, uint mode);

    [Fact]
    public void RejectsSpecialFilesAndSymlinksWithoutBlocking()
    {
        var fifo = Path.Combine(directory, "fifo");
        Assert.Equal(0, MkFifo(fifo, 0x180));
        var link = Path.Combine(directory, "link");
        File.CreateSymbolicLink(link, Write(Encoding.UTF8.GetBytes(Yaml)));
        foreach (var path in new[] { fifo, link, directory, "/dev/zero" })
        {
            var watch = Stopwatch.StartNew();
            Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(path, readEnvironment: Env(null)));
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2));
        }
    }

    [Fact]
    public void CancellationAndCallbackFailuresLeaveNoTempsOrRawExceptions()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => PolicyLoader.Load(cancellationToken: cancellation.Token,
            readEnvironment: _ => throw new Exception("must not read")));
        using var during = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => PolicyLoader.Load(logLevel: "verbose",
            log: _ => during.Cancel(), cancellationToken: during.Token, readEnvironment: Env(Yaml)));
        var error = Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(logLevel: "verbose",
            log: _ => throw new Exception(Yaml), readEnvironment: Env(Yaml)));
        NoCanaries(error.ToString());
        Assert.Null(error.InnerException);
        var sourceError = Assert.Throws<PolicyInputException>(() => PolicyLoader.Load(readEnvironment: _ => throw new Exception(Yaml)));
        NoCanaries(sourceError.ToString());
        Assert.Empty(Directory.GetFiles(directory));
    }

    [Fact]
    public void CancellationAfterSourceSelectionClosesFileAndClearsTransferredBytes()
    {
        var bytes = Encoding.UTF8.GetBytes(Yaml);
        var path = Write(bytes);
        using var cancellation = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => PolicyLoader.Load(path,
            cancellationToken: cancellation.Token, readEnvironment: _ =>
            {
                cancellation.Cancel();
                return null;
            }));
        Assert.Single(Directory.GetFiles(directory));
        File.Delete(path);
        Assert.Empty(Directory.GetFiles(directory));
        var transferred = Encoding.UTF8.GetBytes(Yaml);
        Assert.NotNull(PolicyLoader.Load(readEnvironment: _ => transferred));
        Assert.All(transferred, value => Assert.Equal(0, value));
        transferred = Encoding.UTF8.GetBytes("[bad YAML");
        Assert.Throws<PolicyException>(() => PolicyLoader.Load(readEnvironment: _ => transferred));
        Assert.All(transferred, value => Assert.Equal(0, value));
    }

    [Fact]
    public void ParserEnvironmentIsExplicitAllowlistNotHostCopy()
    {
        var start = new ProcessStartInfo("not-started");
        start.Environment[PolicyLoader.EnvironmentName] = Yaml;
        start.Environment["AES_KEY"] = "unrelated-secret";
        PolicyLoader.SetParserEnvironment(start, new Dictionary<string, string> { ["LANG"] = "C.UTF-8" });
        Assert.Single(start.Environment);
        Assert.Equal("C.UTF-8", start.Environment["LANG"]);
        Assert.Throws<PolicyInputException>(() => PolicyLoader.SetParserEnvironment(start,
            new Dictionary<string, string> { [PolicyLoader.EnvironmentName] = Yaml }));
    }
}
