//! Names from other conversations. A `$PIIF_SECRET_<n>` name only means something in the conversation that made it, so when a tool shows another conversation's transcript (`cc-search`, or a `.jsonl` file under `~/.claude/projects`), its names would read as this conversation's. For a session that opts in, the gateway rewrites such a name as `[[piif:<first 8 hex of its conversation id>:<n>]]`, and `piifence reveal` resolves that form from the other conversation's stored table.

use std::sync::OnceLock;

use regex::Regex;

fn name_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\$(?:\{PIIF_SECRET_(\d+)\}|PIIF_SECRET_(\d+))").expect("valid pattern")
    })
}

fn uuid_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("valid pattern")
    })
}

/// `[[piif:<8 hex>:<n>]]`, with the prefix in group 1 and the number in group 2.
pub fn qualified_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"\[\[piif:([0-9a-f]{8}):(\d+)\]\]").expect("valid pattern"))
}

/// `text` with each name that belongs to another conversation written as `[[piif:<8 hex>:<n>]]`, or None when nothing changes. A name belongs to the conversation whose id is on its line: the last one before the name, else the first one after it. A line without an id takes the last id of the nearest line above that has one, as in a multi-line message that `cc-search --show` prints on lines of their own. A name with no id above it, or whose id is `own`, stays as it is.
pub fn qualify(text: &str, own: Option<&str>) -> Option<String> {
    if !text.contains("PIIF_SECRET_") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut carry: Option<&str> = None;
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        let ids: Vec<(usize, &str)> = uuid_pattern()
            .find_iter(line)
            .map(|m| (m.end(), m.as_str()))
            .collect();
        let mut last = 0;
        for caps in name_pattern().captures_iter(line) {
            let whole = caps.get(0).expect("match");
            let id = ids
                .iter()
                .rev()
                .find(|(end, _)| *end <= whole.start())
                .or(ids.first())
                .map(|(_, id)| *id)
                .or(carry);
            let Some(id) = id.filter(|id| Some(*id) != own) else {
                continue;
            };
            let number = caps.get(1).or(caps.get(2)).expect("number").as_str();
            out.push_str(&line[last..whole.start()]);
            out.push_str(&format!("[[piif:{}:{number}]]", &id[..8]));
            last = whole.end();
            changed = true;
        }
        out.push_str(&line[last..]);
        if let Some((_, id)) = ids.last() {
            carry = Some(id);
        }
    }
    changed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = "11111111-2222-3333-4444-555555555555";
    const OTHER: &str = "abcdef01-2222-3333-4444-555555555555";
    const THIRD: &str = "99999999-2222-3333-4444-555555555555";

    fn name(n: u32) -> String {
        format!("${}_{n}", "PIIF_SECRET")
    }

    #[test]
    fn a_name_takes_the_id_on_its_line() {
        let text = format!("2026-11-16\tproj\t3\t{OTHER}\ttoken is {}\n", name(4));
        assert_eq!(
            qualify(&text, Some(OWN)).unwrap(),
            format!("2026-11-16\tproj\t3\t{OTHER}\ttoken is [[piif:abcdef01:4]]\n")
        );
    }

    #[test]
    fn a_continuation_line_takes_the_id_above() {
        let text = format!("12:00\t{OTHER}\tfirst line\nsecond {} line\n", name(2));
        let out = qualify(&text, None).unwrap();
        assert!(out.contains("second [[piif:abcdef01:2]] line"), "{out}");
    }

    #[test]
    fn own_and_unplaced_names_stay() {
        assert_eq!(qualify(&format!("{OWN}\t{}", name(1)), Some(OWN)), None);
        assert_eq!(qualify(&format!("no id here {}", name(1)), Some(OWN)), None);
        assert_eq!(qualify("nothing", Some(OWN)), None);
    }

    #[test]
    fn the_last_id_before_the_name_wins() {
        let text = format!(
            "{THIRD} said {OTHER}: {} and ${{{}_7}}",
            name(5),
            "PIIF_SECRET"
        );
        assert_eq!(
            qualify(&text, None).unwrap(),
            format!("{THIRD} said {OTHER}: [[piif:abcdef01:5]] and [[piif:abcdef01:7]]")
        );
        let text = format!("{} before {OTHER}", name(12));
        assert_eq!(
            qualify(&text, None).unwrap(),
            format!("[[piif:abcdef01:12]] before {OTHER}")
        );
    }

    #[test]
    fn rewriting_is_stable() {
        let text = format!("{OTHER}\t{}\n", name(9));
        let once = qualify(&text, Some(OWN)).unwrap();
        assert_eq!(qualify(&text, Some(OWN)).unwrap(), once);
        assert_eq!(qualify(&once, Some(OWN)), None);
        assert!(qualified_pattern().is_match(&once));
    }
}
