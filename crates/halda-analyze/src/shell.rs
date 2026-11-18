//! A small POSIX-shell reader.
//!
//! It does not execute or expand anything. It resolves quoting, splits pipelines
//! and lists, finds nested command substitutions, and records whenever a word's
//! value cannot be known without running the shell. Anything it cannot read
//! comes back flagged, and callers treat flagged input as ambiguous.

/// One word of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// Text with quoting resolved. Expansions appear literally (`$X`).
    pub text: String,
    /// True if the value depends on a variable, substitution or glob.
    pub dynamic: bool,
}

/// How a command connects to the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    /// `;`, newline, `&`, `&&`, `||` or the end of input.
    Sequence,
    /// `|`
    Pipe,
}

/// A redirection such as `> file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// The operator: `>`, `>>`, `<`, `<<`, `<<<`.
    pub op: String,
    /// The target or here-document body.
    pub target: Word,
}

/// A single command with its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Command {
    /// Leading `NAME=value` assignments.
    pub env: Vec<(String, Word)>,
    /// Command name followed by arguments.
    pub argv: Vec<Word>,
    /// Redirections.
    pub redirects: Vec<Redirect>,
    /// How this connects to the next command.
    pub connector: Option<Connector>,
}

/// Result of reading a command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Top-level commands, in order.
    pub commands: Vec<Command>,
    /// Bodies of `$(...)`, backticks and `<(...)`, wherever they appeared.
    pub substitutions: Vec<String>,
    /// True if some construct could not be read with confidence.
    pub unparsable: bool,
    /// Why.
    pub problem: Option<String>,
}

const MAX_DEPTH: usize = 12;

struct Reader<'a> {
    chars: Vec<char>,
    pos: usize,
    out: &'a mut Parsed,
}

impl Reader<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn fail(&mut self, why: &str) {
        self.out.unparsable = true;
        self.out.problem.get_or_insert_with(|| why.to_string());
    }

    /// Reads up to the parenthesis matching one already consumed.
    fn read_balanced(&mut self) -> String {
        let mut depth = 1usize;
        let mut body = String::new();
        let mut quote: Option<char> = None;
        while let Some(c) = self.bump() {
            match quote {
                Some(q) => {
                    if c == '\\' && q == '"' {
                        body.push(c);
                        if let Some(n) = self.bump() {
                            body.push(n);
                        }
                        continue;
                    }
                    if c == q {
                        quote = None;
                    }
                }
                None => match c {
                    '\'' | '"' => quote = Some(c),
                    '\\' => {
                        body.push(c);
                        if let Some(n) = self.bump() {
                            body.push(n);
                        }
                        continue;
                    }
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return body;
                        }
                    }
                    _ => {}
                },
            }
            body.push(c);
        }
        self.fail("unbalanced parentheses");
        body
    }

    /// Handles what follows a `$` inside or outside double quotes.
    fn read_dollar(&mut self, word: &mut Word) {
        word.dynamic = true;
        match self.peek() {
            Some('(') => {
                self.bump();
                if self.peek() == Some('(') {
                    // Arithmetic: not a command, but a value we cannot know.
                    self.bump();
                    let body = self.read_balanced();
                    self.bump();
                    word.text.push_str(&format!("$(({body}))"));
                } else {
                    let body = self.read_balanced();
                    word.text.push_str(&format!("$({body})"));
                    self.out.substitutions.push(body);
                }
            }
            Some('{') => {
                self.bump();
                let mut name = String::new();
                while let Some(c) = self.bump() {
                    if c == '}' {
                        break;
                    }
                    name.push(c);
                }
                // Bash 5.3 function substitution: `${ cmd; }` and `${| cmd; }` run
                // commands, and look like an ordinary expansion.
                if name.starts_with(char::is_whitespace) || name.starts_with('|') {
                    self.out
                        .substitutions
                        .push(name.trim_start_matches('|').to_string());
                    // New syntax that many tools misread, so never treat it as plain.
                    self.fail("function substitution");
                }
                // `${x@P}` expands prompt escapes, which can run commands.
                if name.starts_with('(') {
                    // zsh expansion flags can evaluate text.
                    self.fail("zsh expansion flags");
                }
                if name.ends_with("@P") || name.ends_with("@E") {
                    self.fail("parameter transformation that can run commands");
                }
                // ${X:-$(cmd)} and friends hide commands inside the braces.
                if let Some(start) = name.find("$(") {
                    let mut inner = Parsed::default();
                    let mut sub = Reader {
                        chars: name[start + 2..].chars().collect(),
                        pos: 0,
                        out: &mut inner,
                    };
                    let body = sub.read_balanced();
                    self.out.substitutions.push(body);
                }
                word.text.push_str(&format!("${{{name}}}"));
            }
            Some('\'') => {
                // ANSI-C quoting: $'\x72\x6d' is `rm`.
                self.bump();
                let mut raw = String::new();
                while let Some(c) = self.bump() {
                    if c == '\'' {
                        break;
                    }
                    if c == '\\' {
                        raw.push(c);
                        if let Some(n) = self.bump() {
                            raw.push(n);
                        }
                        continue;
                    }
                    raw.push(c);
                }
                word.dynamic = false;
                word.text.push_str(&decode_ansi_c(&raw));
            }
            Some(c) if c.is_alphanumeric() || "_@*#?$!-".contains(c) => {
                word.text.push('$');
                if c.is_alphabetic() || c == '_' {
                    while let Some(n) = self.peek() {
                        if n.is_alphanumeric() || n == '_' {
                            word.text.push(n);
                            self.bump();
                        } else {
                            break;
                        }
                    }
                } else {
                    word.text.push(c);
                    self.bump();
                }
            }
            _ => {
                word.dynamic = false;
                word.text.push('$');
            }
        }
    }

    fn read_backtick(&mut self, word: &mut Word) {
        word.dynamic = true;
        let mut body = String::new();
        loop {
            match self.bump() {
                Some('`') => break,
                Some('\\') => {
                    if let Some(n) = self.bump() {
                        body.push(n);
                    }
                }
                Some(c) => body.push(c),
                None => {
                    self.fail("unterminated backtick");
                    break;
                }
            }
        }
        word.text.push_str(&format!("`{body}`"));
        self.out.substitutions.push(body);
    }

    fn read_word(&mut self) -> Option<Word> {
        let mut word = Word {
            text: String::new(),
            dynamic: false,
        };
        let mut started = false;
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\n' | '\r' | ';' | '&' | '|' | '>' | '<' => break,
                '(' | ')' => break,
                '\'' => {
                    started = true;
                    self.bump();
                    loop {
                        match self.bump() {
                            Some('\'') => break,
                            Some(n) => word.text.push(n),
                            None => {
                                self.fail("unterminated single quote");
                                break;
                            }
                        }
                    }
                }
                '"' => {
                    started = true;
                    self.bump();
                    loop {
                        match self.peek() {
                            Some('"') => {
                                self.bump();
                                break;
                            }
                            Some('\\') => {
                                self.bump();
                                match self.bump() {
                                    Some(n @ ('"' | '\\' | '$' | '`')) => word.text.push(n),
                                    Some('\n') => {}
                                    Some(n) => {
                                        word.text.push('\\');
                                        word.text.push(n);
                                    }
                                    None => self.fail("unterminated double quote"),
                                }
                            }
                            Some('$') => {
                                self.bump();
                                self.read_dollar(&mut word);
                            }
                            Some('`') => {
                                self.bump();
                                self.read_backtick(&mut word);
                            }
                            Some(n) => {
                                word.text.push(n);
                                self.bump();
                            }
                            None => {
                                self.fail("unterminated double quote");
                                break;
                            }
                        }
                    }
                }
                '\\' => {
                    started = true;
                    self.bump();
                    match self.bump() {
                        Some('\n') => {}
                        Some(n) => word.text.push(n),
                        None => self.fail("trailing backslash"),
                    }
                }
                '$' => {
                    started = true;
                    self.bump();
                    self.read_dollar(&mut word);
                }
                '`' => {
                    started = true;
                    self.bump();
                    self.read_backtick(&mut word);
                }
                '*' | '?' | '[' => {
                    started = true;
                    word.dynamic = true;
                    word.text.push(c);
                    self.bump();
                }
                '{' if self.looks_like_brace_expansion() => {
                    started = true;
                    word.dynamic = true;
                    word.text.push(c);
                    self.bump();
                }
                _ => {
                    started = true;
                    word.text.push(c);
                    self.bump();
                }
            }
        }
        started.then_some(word)
    }

    /// `{rm,-rf,x}` and `{a..z}` run as commands or expand to several words.
    fn looks_like_brace_expansion(&self) -> bool {
        let rest: String = self.chars[self.pos..]
            .iter()
            .take_while(|c| !c.is_whitespace())
            .collect();
        rest.contains('}') && (rest.contains(',') || rest.contains(".."))
    }

    fn skip_blanks(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' => {
                    self.bump();
                }
                '\\' if self.peek_at(1) == Some('\n') => {
                    self.bump();
                    self.bump();
                }
                _ => break,
            }
        }
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }

    fn read_heredoc(&mut self, delimiter: &str, pending: &mut Vec<Word>) {
        // The body starts on the next line, but the rest of this line still
        // belongs to the command (`cat <<SQL | psql`), so lift the body out of
        // the input and leave that text to be read normally.
        let Some(newline) = self.chars[self.pos..]
            .iter()
            .position(|c| *c == '\n')
            .map(|i| i + self.pos)
        else {
            self.fail("unterminated here-document");
            return;
        };
        let mut body = String::new();
        let mut line = String::new();
        let mut closed = false;
        let mut end = newline + 1;
        while end < self.chars.len() {
            let c = self.chars[end];
            end += 1;
            if c == '\n' {
                if line.trim_start_matches('\t') == delimiter {
                    closed = true;
                    break;
                }
                body.push_str(&line);
                body.push('\n');
                line.clear();
            } else {
                line.push(c);
            }
        }
        if !closed && line.trim_start_matches('\t') == delimiter {
            closed = true;
        }
        if !closed {
            self.fail("unterminated here-document");
        }
        self.chars.drain(newline + 1..end);

        // An unquoted here-document expands its body, so `$(...)` in it runs.
        let dynamic = body.contains('$') || body.contains('`');
        if dynamic {
            let mut inner = Reader {
                chars: body.chars().collect(),
                pos: 0,
                out: &mut *self.out,
            };
            while let Some(c) = inner.bump() {
                let mut scratch = Word {
                    text: String::new(),
                    dynamic: false,
                };
                if c == '$' {
                    inner.read_dollar(&mut scratch);
                } else if c == '`' {
                    inner.read_backtick(&mut scratch);
                }
            }
        }
        pending.push(Word {
            text: body,
            dynamic,
        });
    }

    fn run(&mut self) {
        let mut current = Command::default();
        let mut seen_command = false;
        let finish = |cmd: &mut Command, conn: Connector, out: &mut Parsed, seen: &mut bool| {
            if !cmd.argv.is_empty() || !cmd.env.is_empty() || !cmd.redirects.is_empty() {
                cmd.connector = Some(conn);
                out.commands.push(std::mem::take(cmd));
            }
            *seen = false;
        };
        loop {
            self.skip_blanks();
            let Some(c) = self.peek() else { break };
            match c {
                '#' => self.skip_comment(),
                '\n' | ';' => {
                    self.bump();
                    finish(
                        &mut current,
                        Connector::Sequence,
                        self.out,
                        &mut seen_command,
                    );
                }
                '&' => {
                    self.bump();
                    if self.peek() == Some('&') {
                        self.bump();
                    } else if self.peek() == Some('>') {
                        // `&>file` redirects both streams.
                        self.bump();
                        if self.peek() == Some('>') {
                            self.bump();
                        }
                        self.skip_blanks();
                        if let Some(target) = self.read_word() {
                            current.redirects.push(Redirect {
                                op: ">".into(),
                                target,
                            });
                        }
                        continue;
                    }
                    finish(
                        &mut current,
                        Connector::Sequence,
                        self.out,
                        &mut seen_command,
                    );
                }
                '|' => {
                    self.bump();
                    let conn = if self.peek() == Some('|') {
                        self.bump();
                        Connector::Sequence
                    } else {
                        if self.peek() == Some('&') {
                            self.bump();
                        }
                        Connector::Pipe
                    };
                    finish(&mut current, conn, self.out, &mut seen_command);
                }
                '(' => {
                    // After a command name this is a function definition, which
                    // can silently redefine `ls`. Otherwise it is a subshell, and
                    // its commands run, so read them.
                    if !current.argv.is_empty() {
                        self.fail("function definition");
                    }
                    self.bump();
                    let body = self.read_balanced();
                    self.out.substitutions.push(body);
                }
                ')' => {
                    self.bump();
                    self.fail("unbalanced parentheses");
                }
                '>' | '<' => {
                    let mut op = String::new();
                    while let Some(n) = self.peek() {
                        if n == '>' || n == '<' {
                            op.push(n);
                            self.bump();
                        } else {
                            break;
                        }
                    }
                    if self.peek() == Some('(') {
                        // Process substitution.
                        self.bump();
                        let body = self.read_balanced();
                        self.out.substitutions.push(body);
                        continue;
                    }
                    if self.peek() == Some('&') {
                        // `2>&1`: a stream duplication, not a file.
                        self.bump();
                        let _ = self.read_word();
                        continue;
                    }
                    let strip = self.peek() == Some('-');
                    if strip && op == "<<" {
                        self.bump();
                    }
                    self.skip_blanks();
                    match self.read_word() {
                        Some(target) if op == "<<" => {
                            let mut bodies = Vec::new();
                            self.read_heredoc(&target.text.clone(), &mut bodies);
                            for body in bodies {
                                current.redirects.push(Redirect {
                                    op: op.clone(),
                                    target: body,
                                });
                            }
                        }
                        Some(target) => current.redirects.push(Redirect { op, target }),
                        None => self.fail("redirection without a target"),
                    }
                }
                _ => {
                    let Some(word) = self.read_word() else {
                        // A character read_word stops on but this loop does not handle.
                        self.bump();
                        self.fail("unexpected character");
                        continue;
                    };
                    if !seen_command {
                        if let Some((name, value)) = split_assignment(&word) {
                            current.env.push((name, value));
                            continue;
                        }
                    }
                    // A numeric word directly before a redirect is a file descriptor.
                    if matches!(self.peek(), Some('>' | '<'))
                        && word.text.chars().all(|d| d.is_ascii_digit())
                    {
                        continue;
                    }
                    seen_command = true;
                    current.argv.push(word);
                }
            }
        }
        finish(
            &mut current,
            Connector::Sequence,
            self.out,
            &mut seen_command,
        );
    }
}

fn split_assignment(word: &Word) -> Option<(String, Word)> {
    let (name, value) = word.text.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((
        name.to_string(),
        Word {
            text: value.to_string(),
            dynamic: word.dynamic,
        },
    ))
}

fn decode_ansi_c(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('x') => {
                let mut hex = String::new();
                while hex.len() < 2 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(*h);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some(d @ '0'..='7') => {
                let mut oct = String::from(d);
                while oct.len() < 3 {
                    match chars.peek() {
                        Some(o @ '0'..='7') => {
                            oct.push(*o);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if let Some(ch) = u32::from_str_radix(&oct, 8).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some('u') => {
                let mut hex = String::new();
                while hex.len() < 4 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(*h);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Reads a command line. Never panics; unreadable input comes back flagged.
pub fn parse(input: &str) -> Parsed {
    parse_at_depth(input, 0)
}

fn parse_at_depth(input: &str, depth: usize) -> Parsed {
    let mut out = Parsed::default();
    if depth > MAX_DEPTH {
        out.unparsable = true;
        out.problem = Some("commands nested too deeply".into());
        return out;
    }
    let mut reader = Reader {
        chars: input.chars().collect(),
        pos: 0,
        out: &mut out,
    };
    reader.run();
    out
}

/// Every command in `input`, including those inside substitutions and subshells,
/// plus whether any part could not be read.
pub fn all_commands(input: &str, depth: usize) -> (Vec<Command>, bool, Option<String>) {
    let parsed = parse_at_depth(input, depth);
    let mut commands = parsed.commands;
    let mut unparsable = parsed.unparsable;
    let mut problem = parsed.problem;
    for sub in parsed.substitutions {
        let (inner, bad, why) = all_commands(&sub, depth + 1);
        commands.extend(inner);
        if bad {
            unparsable = true;
            problem = problem.or(why);
        }
    }
    (commands, unparsable, problem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn argv(input: &str) -> Vec<String> {
        parse(input).commands[0]
            .argv
            .iter()
            .map(|w| w.text.clone())
            .collect()
    }

    #[test]
    fn quoting_is_resolved() {
        assert_eq!(argv(r#"te"rra"form destroy"#), ["terraform", "destroy"]);
        assert_eq!(argv(r"te''rraform de\stroy"), ["terraform", "destroy"]);
        assert_eq!(argv(r"$'\x74erraform' destroy"), ["terraform", "destroy"]);
        assert_eq!(argv(r"$'\164erraform' destroy"), ["terraform", "destroy"]);
    }

    #[test]
    fn variables_are_marked_dynamic() {
        let parsed = parse("$T destroy");
        assert!(parsed.commands[0].argv[0].dynamic);
    }

    #[test]
    fn lists_and_pipes_split() {
        let p = parse("a b; c && d || e | f & g\nh");
        let names: Vec<_> = p.commands.iter().map(|c| c.argv[0].text.as_str()).collect();
        assert_eq!(names, ["a", "c", "d", "e", "f", "g", "h"]);
        assert_eq!(p.commands[3].connector, Some(Connector::Pipe));
    }

    #[test]
    fn substitutions_are_found_at_every_level() {
        let (cmds, bad, _) = all_commands(r#"echo "$(cat $(which secret))" `id` <(ls)"#, 0);
        assert!(!bad);
        let names: Vec<_> = cmds.iter().map(|c| c.argv[0].text.as_str()).collect();
        for want in ["echo", "cat", "which", "id", "ls"] {
            assert!(names.contains(&want), "missing {want} in {names:?}");
        }
    }

    #[test]
    fn env_prefixes_and_redirects_are_separated() {
        let p = parse("A=1 B=\"2\" cmd arg > out 2>&1");
        let c = &p.commands[0];
        assert_eq!(c.env.len(), 2);
        assert_eq!(c.argv[0].text, "cmd");
        assert_eq!(c.argv.len(), 2);
        assert_eq!(c.redirects.len(), 1);
        assert_eq!(c.redirects[0].target.text, "out");
    }

    #[test]
    fn heredocs_capture_their_body() {
        let p = parse("psql <<SQL\nDROP TABLE orders;\nSQL\nls");
        assert_eq!(
            p.commands[0].redirects[0].target.text,
            "DROP TABLE orders;\n"
        );
        assert_eq!(p.commands[1].argv[0].text, "ls");
    }

    #[test]
    fn broken_input_is_flagged_not_dropped() {
        assert!(parse("echo 'oops").unparsable);
        assert!(parse("echo \"oops").unparsable);
        assert!(parse("echo $(oops").unparsable);
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_followed() {
        let mut s = String::from("x");
        for _ in 0..40 {
            s = format!("echo $({s})");
        }
        let (_, bad, _) = all_commands(&s, 0);
        assert!(bad);
    }

    proptest! {
        #[test]
        fn never_panics_on_any_input(s in "\\PC{0,200}") {
            let _ = all_commands(&s, 0);
        }

        #[test]
        fn never_panics_on_shell_shaped_input(s in "[ a-z$'\"`\\\\(){};|&<>#=\\n-]{0,120}") {
            let _ = all_commands(&s, 0);
        }
    }
}
