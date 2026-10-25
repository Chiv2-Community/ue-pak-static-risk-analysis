using System.Text;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;

namespace PakRisk.Policy;

// Parse events, not arbitrary objects. No tag resolution, aliases, or merge expansion.
internal static class YamlTree
{
    internal abstract record Node(Mark Mark);
    internal sealed record Text(string Value, ScalarStyle Style, Mark Start) : Node(Start);
    internal sealed record Map(IReadOnlyDictionary<string, Node> Fields, Mark Start) : Node(Start);
    internal sealed record Sequence(IReadOnlyList<Node> Items, Mark Start) : Node(Start);

    public const int MaxBytes = 262_144;
    public const int MaxDepth = 32;
    public const int MaxNodes = 8192;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static Node Read(string yaml)
    {
        try
        {
            if (yaml.Length > MaxBytes || Utf8.GetByteCount(yaml) > MaxBytes)
                throw new PolicyException("input-size-limit");
        }
        catch (EncoderFallbackException)
        {
            throw new PolicyException("invalid-unicode");
        }
        try
        {
            var parser = new Parser(new StringReader(yaml));
            parser.Consume<StreamStart>();
            var document = parser.Consume<DocumentStart>();
            // The parser includes its two built-in tag directives on every document.
            if (document.Version is not null || document.Tags?.Any(tag =>
                !((tag.Handle == "!" && tag.Prefix == "!")
                  || (tag.Handle == "!!" && tag.Prefix == "tag:yaml.org,2002:"))) == true)
                throw Error("directives-not-supported", document.Start);
            var nodes = 0;
            var root = ReadNode(parser, 0, ref nodes);
            parser.Consume<DocumentEnd>();
            if (!parser.TryConsume<StreamEnd>(out _))
                throw new PolicyException("multiple-documents");
            return root;
        }
        catch (YamlException error)
        {
            // Never retain error.Message/InnerException: the library quotes input.
            throw Error("invalid-yaml", error.Start);
        }
    }

    private static Node ReadNode(IParser parser, int depth, ref int count)
    {
        if (depth > MaxDepth)
            throw new PolicyException("nesting-limit");
        if (++count > MaxNodes)
            throw new PolicyException("node-limit");
        var current = parser.Current;
        if (current is AnchorAlias)
            throw Error("aliases-not-supported", current.Start);
        if (current is not NodeEvent node)
            throw new PolicyException("expected-node");
        if (!node.Anchor.IsEmpty || !node.Tag.IsEmpty)
            throw Error("anchors-and-tags-not-supported", node.Start);
        switch (current)
        {
            case Scalar scalar:
                parser.Consume<Scalar>();
                return new Text(scalar.Value, scalar.Style, scalar.Start);
            case MappingStart mapping:
                parser.Consume<MappingStart>();
                var fields = new Dictionary<string, Node>(StringComparer.Ordinal);
                while (!parser.TryConsume<MappingEnd>(out _))
                {
                    var key = ReadNode(parser, depth + 1, ref count) as Text
                        ?? throw Error("expected-scalar-key", mapping.Start);
                    if (key.Value == "<<")
                        throw Error("merge-keys-not-supported", key.Mark);
                    if (fields.ContainsKey(key.Value))
                        throw Error("duplicate-key", key.Mark);
                    fields.Add(key.Value, ReadNode(parser, depth + 1, ref count));
                }
                return new Map(fields, mapping.Start);
            case SequenceStart sequence:
                parser.Consume<SequenceStart>();
                var items = new List<Node>();
                while (!parser.TryConsume<SequenceEnd>(out _))
                    items.Add(ReadNode(parser, depth + 1, ref count));
                return new Sequence(items, sequence.Start);
            default:
                throw Error("expected-node", node.Start);
        }
    }

    internal static PolicyException Error(string code, Mark mark) => new(code, mark.Line, mark.Column);

    internal static void ValidateUnicode(string value, Mark mark)
    {
        try { _ = Utf8.GetByteCount(value); }
        catch (EncoderFallbackException) { throw Error("invalid-unicode", mark); }
    }
}
