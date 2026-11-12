//! Secret names in a shell command, for the `PreToolUse` hook (`piifence restore`). The shell expands a `$PIIF_SECRET_<N>` name itself from the exported variables, except where its quoting stops it: single quotes, ANSI-C `$'…'` quotes, quoted heredocs, and a backslash before the `$`. `fill_command` puts the value in place of each name of that second kind, escaped for the place it is in, so a command never uses a name as text.

use anyhow::{bail, Context, Result};
use regex::Regex;

const UNPLACEABLE: &str = "piifence cannot follow the quoting of this command (an unclosed quote, heredoc, `$(` or backtick), so it cannot tell whether the shell expands the secret names in it; write each name in double quotes or in an unquoted heredoc";

#[derive(Clone, Copy, PartialEq)]
enum Sub {
    Top,
    Paren { depth: usize, arith: bool },
    Backtick,
}

#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Plain(Sub),
    Double,
    Single,
    AnsiC,
    /// Index into the heredoc list, and whether the delimiter was quoted.
    Heredoc(usize, bool),
}

/// How a value is written where the shell would not expand its name.
#[derive(Clone, Copy)]
enum Esc {
    Plain,
    Double,
    Single,
    AnsiC,
    Heredoc,
    Raw,
}

impl Esc {
    /// The escape for a name in `ctx`, escaped by a backslash or not. None when the shell expands the name itself.
    fn for_ctx(ctx: Ctx, escaped: bool) -> Option<Esc> {
        match ctx {
            Ctx::Single => Some(Esc::Single),
            Ctx::AnsiC => Some(Esc::AnsiC),
            Ctx::Heredoc(_, true) => Some(Esc::Raw),
            _ if !escaped => None,
            Ctx::Plain(_) => Some(Esc::Plain),
            Ctx::Double => Some(Esc::Double),
            Ctx::Heredoc(_, false) => Some(Esc::Heredoc),
        }
    }

    fn apply(self, value: &str) -> Result<String> {
        let backslashed = |specials: &[char]| {
            value.chars().fold(String::new(), |mut out, c| {
                if specials.contains(&c) {
                    out.push('\\');
                }
                out.push(c);
                out
            })
        };
        Ok(match self {
            Esc::Plain => format!("'{}'", value.replace('\'', "'\\''")),
            Esc::Single => value.replace('\'', "'\\''"),
            Esc::Double => backslashed(&['\\', '$', '`', '"']),
            Esc::Heredoc => backslashed(&['\\', '$', '`']),
            Esc::AnsiC => backslashed(&['\\', '\'']),
            Esc::Raw if value.contains('\n') => {
                bail!("a secret value holds a line break, so it cannot go into a quoted heredoc; write its name in an unquoted heredoc instead")
            }
            Esc::Raw => value.to_string(),
        })
    }
}

/// A name found in the command: its variable name, the byte where it ends, and whether it is written without braces.
struct Name {
    var: String,
    end: usize,
    bare: bool,
}

struct Scan<'a> {
    cmd: &'a str,
    pattern: Regex,
    value_of: &'a dyn Fn(&str) -> Option<String>,
    out: String,
    copied: usize,
}

impl Scan<'_> {
    /// The name whose `$` is at byte `i`.
    fn name_at(&self, i: usize) -> Option<Name> {
        let caps = self.pattern.captures(self.cmd.get(i..)?)?;
        Some(Name {
            var: caps.get(1).or(caps.get(2))?.as_str().to_string(),
            end: i + caps[0].len(),
            bare: caps.get(2).is_some(),
        })
    }

    /// Replace `start..name.end` with the name's value, escaped by `esc` and then once more for each enclosing backtick substitution. Returns where scanning goes on.
    fn fill(&mut self, start: usize, name: Name, esc: Esc, backticks: usize) -> Result<usize> {
        let var = &name.var;
        if name.bare && self.cmd[name.end..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
        {
            bail!("${var} runs into the text after it, so a shell would read a longer variable name; write ${{{var}}} instead");
        }
        let value = (self.value_of)(var)
            .with_context(|| format!("this session has no value for ${var}"))?;
        let mut text = esc.apply(&value)?;
        for _ in 0..backticks {
            text = Esc::Heredoc.apply(&text)?;
        }
        self.out.push_str(&self.cmd[self.copied..start]);
        self.out.push_str(&text);
        self.copied = name.end;
        Ok(name.end)
    }

    /// A name at `start` (its `$`, or the backslash that escapes it) in `ctx`: filled in, or skipped when the shell expands it.
    fn name(&mut self, start: usize, name: Name, ctx: Ctx, stack: &[Ctx]) -> Result<usize> {
        match Esc::for_ctx(ctx, self.cmd.as_bytes()[start] == b'\\') {
            Some(esc) => {
                let backticks = stack
                    .iter()
                    .filter(|c| **c == Ctx::Plain(Sub::Backtick))
                    .count();
                self.fill(start, name, esc, backticks)
            }
            None => Ok(name.end),
        }
    }
}

/// The delimiter of the heredoc whose word starts at or after byte `i` (after `<<` or `<<-`), whether any part of the word is quoted, and the byte after the word.
fn heredoc_word(cmd: &str, mut i: usize) -> Result<(String, bool, usize)> {
    let bytes = cmd.as_bytes();
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    let (mut word, mut quoted) = (String::new(), false);
    while let Some(&c) = bytes.get(i) {
        match c {
            b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' => break,
            b'\'' | b'"' => {
                let close = cmd[i + 1..].find(c as char).context(UNPLACEABLE)?;
                word.push_str(&cmd[i + 1..i + 1 + close]);
                quoted = true;
                i += close + 2;
            }
            _ => {
                if c == b'\\' {
                    quoted = true;
                    i += 1;
                }
                let ch = cmd[i..].chars().next().context(UNPLACEABLE)?;
                word.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    if word.is_empty() {
        bail!(UNPLACEABLE);
    }
    Ok((word, quoted, i))
}

/// `command` with every name that the shell would not expand replaced by its value, escaped for the place it is in. `Ok(None)` when nothing changes.
pub fn fill_command(
    command: &str,
    value_of: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<String>> {
    let mut scan = Scan {
        cmd: command,
        pattern: Regex::new(r"^\$(?:\{(PIIF_SECRET_\d+)\}|(PIIF_SECRET_\d+))")
            .expect("valid pattern"),
        value_of,
        out: String::new(),
        copied: 0,
    };
    if !command
        .match_indices('$')
        .any(|(i, _)| scan.name_at(i).is_some())
    {
        return Ok(None);
    }
    let bytes = command.as_bytes();
    let len = bytes.len();
    let mut stack = vec![Ctx::Plain(Sub::Top)];
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut pending: Vec<Ctx> = Vec::new();
    let mut i = 0;
    while i < len {
        let ctx = *stack.last().expect("the top level is never popped");
        if let Ctx::Heredoc(h, _) = ctx {
            if i == 0 || bytes[i - 1] == b'\n' {
                let end = command[i..].find('\n').map_or(len, |n| i + n);
                let (delim, strip_tabs) = &heredocs[h];
                let line = &command[i..end];
                let line = if *strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if line == delim {
                    stack.pop();
                    i = (end + 1).min(len);
                    continue;
                }
            }
        }
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();
        let expands = matches!(ctx, Ctx::Plain(_) | Ctx::Double | Ctx::Heredoc(_, false));
        if c == b'\\' {
            if let Some(name) = scan.name_at(i + 1) {
                i = scan.name(i, name, ctx, &stack)?;
                continue;
            }
            let pair = match ctx {
                Ctx::Plain(_) | Ctx::AnsiC => next.is_some(),
                Ctx::Double => matches!(next, Some(b'$' | b'`' | b'"' | b'\\' | b'\n')),
                Ctx::Heredoc(_, false) => matches!(next, Some(b'$' | b'`' | b'\\' | b'\n')),
                Ctx::Single | Ctx::Heredoc(_, true) => next == Some(b'\\'),
            };
            i += if pair { 2 } else { 1 };
            continue;
        }
        if c == b'$' {
            if let Some(name) = scan.name_at(i) {
                i = scan.name(i, name, ctx, &stack)?;
            } else if expands && next == Some(b'(') {
                let arith = bytes.get(i + 2) == Some(&b'(');
                stack.push(Ctx::Plain(Sub::Paren { depth: 0, arith }));
                i += 2;
            } else if matches!(ctx, Ctx::Plain(_)) && next == Some(b'\'') {
                stack.push(Ctx::AnsiC);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if c == b'`' && expands {
            if ctx == Ctx::Plain(Sub::Backtick) {
                stack.pop();
            } else {
                stack.push(Ctx::Plain(Sub::Backtick));
            }
            i += 1;
            continue;
        }
        match (ctx, c) {
            (Ctx::Plain(_), b'\'') => stack.push(Ctx::Single),
            (Ctx::Plain(_), b'"') => stack.push(Ctx::Double),
            (Ctx::Double, b'"') | (Ctx::Single | Ctx::AnsiC, b'\'') => {
                stack.pop();
            }
            (Ctx::Plain(Sub::Paren { .. }), b'(' | b')') => {
                let Some(Ctx::Plain(Sub::Paren { depth, .. })) = stack.last_mut() else {
                    unreachable!("the top is a `$(` context");
                };
                match (c, *depth) {
                    (b'(', _) => *depth += 1,
                    (_, 0) => {
                        stack.pop();
                    }
                    _ => *depth -= 1,
                }
            }
            (Ctx::Plain(_), b'#') if i == 0 || b" \t\n;&|()".contains(&bytes[i - 1]) => {
                i = command[i..].find('\n').map_or(len, |n| i + n);
                continue;
            }
            (Ctx::Plain(sub), b'<')
                if next == Some(b'<') && !matches!(sub, Sub::Paren { arith: true, .. }) =>
            {
                if bytes.get(i + 2) == Some(&b'<') {
                    i += 3;
                    continue;
                }
                let strip_tabs = bytes.get(i + 2) == Some(&b'-');
                let (delim, quoted, end) = heredoc_word(command, i + 2 + strip_tabs as usize)?;
                pending.push(Ctx::Heredoc(heredocs.len(), quoted));
                heredocs.push((delim, strip_tabs));
                i = end;
                continue;
            }
            (Ctx::Plain(_), b'\n') => stack.extend(pending.drain(..).rev()),
            _ => {}
        }
        i += 1;
    }
    if stack.len() > 1 || !pending.is_empty() {
        bail!(UNPLACEABLE);
    }
    if scan.copied == 0 {
        return Ok(None);
    }
    scan.out.push_str(&command[scan.copied..]);
    Ok(Some(scan.out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare name, built at run time so this file never holds one literally.
    fn bare(n: usize) -> String {
        format!("$PIIF_SECRET_{n}")
    }

    /// A braced name, built the same way.
    fn braced(n: usize) -> String {
        format!("${{PIIF_SECRET_{n}}}")
    }

    /// A value that every kind of quoting has to escape.
    const VALUE: &str = "it's \"$HOME\" `x` \\ end";

    fn value_of(var: &str) -> Option<String> {
        (var == "PIIF_SECRET_1").then(|| VALUE.to_string())
    }

    fn fill(command: &str) -> Result<Option<String>> {
        fill_command(command, &value_of)
    }

    /// What bash prints for `command` once its names are filled in, with only `PIIF_SECRET_1` exported.
    fn run(command: &str) -> String {
        let filled = fill(command)
            .unwrap()
            .unwrap_or_else(|| command.to_string());
        let out = std::process::Command::new("/bin/bash")
            .arg("-c")
            .arg(&filled)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/nowhere")
            .env("PIIF_SECRET_1", VALUE)
            .output()
            .unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(
            out.status.success(),
            "{filled}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!stdout.contains("PIIF_SECRET"), "{filled} printed {stdout}");
        stdout
    }

    #[test]
    fn commands_print_the_value_wherever_the_name_stands() {
        let (n, b, v) = (bare(1), braced(1), VALUE);
        let cases = [
            (format!(r#"printf %s "{n}""#), v.to_string()),
            (format!("printf %s '{n}'"), v.to_string()),
            (format!(r#"printf %s "\{n}: bla""#), format!("{v}: bla")),
            (format!(r"printf %s \{n}"), v.to_string()),
            (format!("printf %s $'{n}'"), v.to_string()),
            (
                format!("cat <<'EOF'\n{n}: init\nEOF"),
                format!("{v}: init\n"),
            ),
            (
                format!("cat <<\"EOF\"\n{n}: init\nEOF\n"),
                format!("{v}: init\n"),
            ),
            (
                format!("cat <<\\EOF\n{n}: init\nEOF"),
                format!("{v}: init\n"),
            ),
            (
                format!("cat <<-'EOF'\n\t{n}: init\n\tEOF\n"),
                format!("{v}: init\n"),
            ),
            (format!("cat <<EOF\n\\{n}\nEOF"), format!("{v}\n")),
            (format!("cat <<EOF\n{n}\nEOF"), format!("{v}\n")),
            (format!(r#"printf %s "$(printf %s '{n}')""#), v.to_string()),
            (format!(r#"printf %s "`printf %s '{n}'`""#), v.to_string()),
            (
                format!(r#"printf %s "a \" '{n}' \"""#),
                format!("a \" '{v}' \""),
            ),
            (format!(r#"printf %s "\\{n}""#), format!("\\{v}")),
            (format!("cat <<<'{n}'"), format!("{v}\n")),
            (
                format!("cat <<'A'; cat <<\"B\"\n{n} one\nA\n{b} two\nB\n"),
                format!("{v} one\n{v} two\n"),
            ),
            (format!("# it's '{n}'\nprintf %s '{n}'"), v.to_string()),
            (format!("printf %s '{b}_old'"), format!("{v}_old")),
        ];
        for (command, want) in cases {
            assert_eq!(run(&command), want, "{command}");
        }
    }

    #[test]
    fn names_the_shell_expands_are_left_alone() {
        let n = bare(1);
        for command in [
            "git status".to_string(),
            format!(r#"printf %s "{n}""#),
            format!("cat <<EOF\n{n}\nEOF"),
            format!(r#"printf %s "{}""#, bare(2)),
        ] {
            assert_eq!(fill(&command).unwrap(), None, "{command}");
        }
    }

    #[test]
    fn an_escaped_name_in_a_commit_message_gets_the_value() {
        let command = format!(r#"git commit -m "\{}: bla bla""#, bare(1));
        assert_eq!(
            fill(&command).unwrap().unwrap(),
            r#"git commit -m "it's \"\$HOME\" \`x\` \\ end: bla bla""#
        );
    }

    #[test]
    fn names_that_cannot_be_placed_are_errors() {
        let n = bare(1);
        let err = |command: String| fill(&command).unwrap_err().to_string();
        assert!(err(format!("printf %s '{}'", bare(2))).contains("PIIF_SECRET_2"));
        assert!(err(format!("printf %s '{n}_old'")).contains(&braced(1)));
        assert!(err(format!("printf %s '{n}")).contains("double quotes"));
        assert!(err(format!("cat <<'EOF'\n{n}\n")).contains("double quotes"));
        let two_lines = |_: &str| Some("a\nb".to_string());
        let command = format!("cat <<'EOF'\n{n}\nEOF");
        let err = fill_command(&command, &two_lines).unwrap_err();
        assert!(err.to_string().contains("line break"), "{err}");
    }
}
