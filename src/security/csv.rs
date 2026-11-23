/// Neutralize Excel/Calc CSV formula injection (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`, Unicode full-width).
pub fn sanitize_csv_cell(raw: &str) -> String {
    let cleaned = raw.replace('\0', "");
    let starts_ctrl = cleaned
        .chars()
        .next()
        .map(|c| matches!(c, '\t' | '\r' | '\n'))
        .unwrap_or(false);
    let trimmed_start = cleaned.trim_start();
    let needs_prefix = starts_ctrl
        || trimmed_start
            .chars()
            .next()
            .map(|c| {
                matches!(
                    c,
                    '=' | '+'
                        | '-'
                        | '@'
                        | '\t'
                        | '\r'
                        | '\n'
                        | '\u{FF1D}'
                        | '\u{FF0B}'
                        | '\u{FF0D}'
                        | '\u{FF20}'
                )
            })
            .unwrap_or(false);

    let safe = if needs_prefix {
        format!("'{cleaned}")
    } else {
        cleaned
    };

    let escaped = safe.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_dangerous_formula_prefixes_and_fullwidth_variants() {
        assert_eq!(
            sanitize_csv_cell("=CMD|' /C calc'!A0"),
            "\"'=CMD|' /C calc'!A0\""
        );
        assert_eq!(sanitize_csv_cell("  +1+1"), "\"'  +1+1\"");
        assert_eq!(sanitize_csv_cell("-2+3"), "\"'-2+3\"");
        assert_eq!(sanitize_csv_cell("@SUM(A1:A2)"), "\"'@SUM(A1:A2)\"");
        assert_eq!(sanitize_csv_cell("\t=1+1"), "\"'\t=1+1\"");
        assert_eq!(sanitize_csv_cell("\tfoo"), "\"'\tfoo\"");
        assert_eq!(sanitize_csv_cell("\r+1"), "\"'\r+1\"");
        assert_eq!(sanitize_csv_cell("\u{FF1D}1+1"), "\"'\u{FF1D}1+1\"");
        assert_eq!(
            sanitize_csv_cell("Normal issue title"),
            "\"Normal issue title\""
        );
    }
}
