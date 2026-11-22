// Test-only differential oracle for internal/pwshparse.
// Runs the reference parser (System.Management.Automation.Language.Parser) over
// a script and prints one compact JSON line: the AST in pre-order with depth,
// the token stream and the parse errors. Written in C# 5 so it also compiles in
// Windows PowerShell 5.1 (Add-Type uses the CodeDom compiler there).
//
// Offsets are UTF-16 code unit offsets, exactly what the parser reports.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Reflection;
using System.Text;

public static class PwshOracle
{
    // AST type name -> public properties that are dumped (the ones detection reads,
    // plus the structure that decides how a command is read).
    static readonly Dictionary<string, string[]> Props = new Dictionary<string, string[]>
    {
        { "NamedBlockAst", new string[] { "BlockKind", "Unnamed" } },
        { "CommandAst", new string[] { "InvocationOperator", "DefiningKeyword" } },
        { "CommandParameterAst", new string[] { "ParameterName" } },
        { "StringConstantExpressionAst", new string[] { "StringConstantType", "Value" } },
        { "ExpandableStringExpressionAst", new string[] { "StringConstantType", "Value" } },
        { "ConstantExpressionAst", new string[] { "StaticType", "Value" } },
        { "VariableExpressionAst", new string[] { "VariablePath", "Splatted" } },
        { "BinaryExpressionAst", new string[] { "Operator" } },
        { "UnaryExpressionAst", new string[] { "TokenKind" } },
        { "AssignmentStatementAst", new string[] { "Operator" } },
        { "MemberExpressionAst", new string[] { "Static", "NullConditional" } },
        { "InvokeMemberExpressionAst", new string[] { "Static", "NullConditional" } },
        { "BaseCtorInvokeMemberExpressionAst", new string[] { "Static", "NullConditional" } },
        { "FileRedirectionAst", new string[] { "FromStream", "Append" } },
        { "MergingRedirectionAst", new string[] { "FromStream", "ToStream" } },
        { "TypeExpressionAst", new string[] { "TypeName" } },
        { "TypeConstraintAst", new string[] { "TypeName" } },
        { "ConvertExpressionAst", new string[] { "StaticType" } },
        { "AttributeAst", new string[] { "TypeName" } },
        { "FunctionDefinitionAst", new string[] { "Name", "IsFilter", "IsWorkflow" } },
        { "NamedAttributeArgumentAst", new string[] { "ArgumentName", "ExpressionOmitted" } },
        { "PipelineAst", new string[] { "Background" } },
        { "PipelineChainAst", new string[] { "Operator", "IsBackground" } },
        { "UsingStatementAst", new string[] { "UsingStatementKind" } },
        { "DataStatementAst", new string[] { "Variable" } },
        { "CatchClauseAst", new string[] { "IsCatchAll" } },
        { "ForEachStatementAst", new string[] { "Flags" } },
        { "SwitchStatementAst", new string[] { "Flags" } },
        { "ParamBlockAst", new string[] { } },
        { "ScriptBlockAst", new string[] { } },
    };

    static readonly Dictionary<Type, PropertyInfo[]> Cache = new Dictionary<Type, PropertyInfo[]>();

    static PropertyInfo[] PropsOf(Type t)
    {
        PropertyInfo[] r;
        if (Cache.TryGetValue(t, out r)) return r;
        string[] names;
        List<PropertyInfo> l = new List<PropertyInfo>();
        // walk the type hierarchy so the exact AST type name decides the list
        Type cur = t;
        string[] found = null;
        while (cur != null && found == null)
        {
            if (Props.TryGetValue(cur.Name, out names)) found = names;
            cur = cur.BaseType;
        }
        if (found != null)
        {
            foreach (string n in found)
            {
                PropertyInfo p = null;
                foreach (PropertyInfo c in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (c.Name != n) continue;
                    if (p == null || c.DeclaringType == t) p = c;
                }
                if (p != null) l.Add(p);
            }
        }
        r = l.ToArray();
        Cache[t] = r;
        return r;
    }

    static void Esc(StringBuilder sb, string s)
    {
        if (s == null) { sb.Append("null"); return; }
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20 || (c >= 0xD800 && c <= 0xDFFF))
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static string Render(object v)
    {
        if (v == null) return null;
        if (v is bool) return ((bool)v) ? "true" : "false";
        if (v is string) return (string)v;
        if (v is Enum) return v.ToString();
        if (v is IFormattable) return ((IFormattable)v).ToString(null, CultureInfo.InvariantCulture);
        if (v is VariablePath) return ((VariablePath)v).UserPath;
        if (v is ITypeName) return ((ITypeName)v).FullName;
        if (v is Type) return ((Type)v).FullName;
        return v.ToString();
    }

    static void Tokens(StringBuilder sb, Token[] toks)
    {
        sb.Append("\"tok\":[");
        for (int i = 0; i < toks.Length; i++)
        {
            Token t = toks[i];
            if (i > 0) sb.Append(',');
            sb.Append('[');
            Esc(sb, t.Kind.ToString()); sb.Append(',');
            Esc(sb, t.TokenFlags.ToString()); sb.Append(',');
            sb.Append(t.Extent.StartOffset.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(t.Extent.EndOffset.ToString(CultureInfo.InvariantCulture)).Append(',');
            string v = null;
            StringLiteralToken sl = t as StringLiteralToken;
            StringExpandableToken se = t as StringExpandableToken;
            VariableToken vt = t as VariableToken;
            ParameterToken pt = t as ParameterToken;
            NumberToken nt = t as NumberToken;
            LabelToken lt = t as LabelToken;
            if (sl != null) v = sl.Value;
            else if (se != null) v = se.Value;
            else if (vt != null) v = vt.VariablePath.UserPath;
            else if (pt != null) v = pt.ParameterName;
            else if (nt != null) v = Render(nt.Value);
            else if (lt != null) v = lt.LabelText;
            Esc(sb, v);
            sb.Append(']');
        }
        sb.Append(']');
    }

    // Dump returns one JSON object for the script text.
    public static string Dump(int index, string text)
    {
        Token[] toks;
        ParseError[] errs;
        ScriptBlockAst ast = Parser.ParseInput(text, out toks, out errs);
        StringBuilder sb = new StringBuilder(text.Length * 8 + 256);
        sb.Append("{\"i\":").Append(index.ToString(CultureInfo.InvariantCulture)).Append(",\"ast\":[");
        IEnumerable<Ast> all = ast.FindAll(delegate(Ast a) { return true; }, true);
        Dictionary<Ast, int> depth = new Dictionary<Ast, int>();
        bool first = true;
        foreach (Ast n in all)
        {
            int d = 0;
            if (n.Parent != null && depth.TryGetValue(n.Parent, out d)) d = d + 1; else d = 0;
            depth[n] = d;
            if (!first) sb.Append(',');
            first = false;
            sb.Append('[');
            sb.Append(d.ToString(CultureInfo.InvariantCulture)).Append(',');
            Esc(sb, n.GetType().Name); sb.Append(',');
            sb.Append(n.Extent.StartOffset.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(n.Extent.EndOffset.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append('{');
            bool pf = true;
            CommandAst ca = n as CommandAst;
            if (ca != null)
            {
                string cn = null;
                try { cn = ca.GetCommandName(); } catch (Exception) { cn = null; }
                Esc(sb, "CommandName"); sb.Append(':'); Esc(sb, cn);
                pf = false;
            }
            foreach (PropertyInfo p in PropsOf(n.GetType()))
            {
                object v = null;
                try { v = p.GetValue(n, null); } catch (Exception) { v = null; }
                if (!pf) sb.Append(',');
                pf = false;
                Esc(sb, p.Name); sb.Append(':'); Esc(sb, Render(v));
            }
            sb.Append("}]");
        }
        sb.Append("],");
        Tokens(sb, toks);
        sb.Append(",\"err\":[");
        for (int i = 0; i < errs.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append('[');
            Esc(sb, errs[i].ErrorId); sb.Append(',');
            sb.Append(errs[i].Extent.StartOffset.ToString(CultureInfo.InvariantCulture)).Append(',');
            sb.Append(errs[i].Extent.EndOffset.ToString(CultureInfo.InvariantCulture)).Append(']');
        }
        sb.Append("]}");
        return sb.ToString();
    }
}
