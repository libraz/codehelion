//! One compilation-database entry, and the one rule for reading it.
//!
//! Two programs read the same `compile_commands.json`: the scanner, which
//! decides which translation units exist and names one of them with a
//! [`CompileCommandSelector`], and the C or C++ helper, which has to find the
//! entry that selector names. The selector carries the recorded invocation
//! word for word, and the two sides compare those words exactly — they are what
//! the database recorded and neither side may reword them.
//!
//! That only holds while one rule decides where a word ends. A database that
//! writes its invocation as one line separated by something one reader treats
//! as a space and the other does not would be split two ways, and the entry
//! would be unfindable from the side that split it differently — which is not
//! an error either side can see. So the split lives here, once, and both
//! readers call it.
//!
//! Where a recorded path is relative to is decided here for the same reason.
//! Every path a database writes — the source, the include directories, the
//! sysroot — is relative to the directory the command was to run in, which is
//! neither reader's own. A reader that resolved them somewhere else would read
//! one file while naming another, and one that left them as written would call
//! two commands that read different headers the same command.
//!
//! [`CompileCommandSelector`]: crate::protocol::CompileCommandSelector

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// One entry of a compilation database, as the format writes it.
///
/// Deserialized rather than interpreted: what a reader makes of the file and
/// the arguments is its own business, but which fields exist and what an
/// invocation's words are is shared, because that is what the two sides name
/// an entry by.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordedCommand {
    /// The translation unit's source, as this entry spells it.
    pub file: String,
    /// The directory the command was to run in, when one was recorded.
    #[serde(default)]
    pub directory: Option<String>,
    /// The invocation already split, which is the spelling that needs no
    /// guessing about quoting.
    #[serde(default)]
    pub arguments: Option<Vec<String>>,
    /// The invocation as one line, which generators still write.
    #[serde(default)]
    pub command: Option<String>,
}

impl RecordedCommand {
    /// The recorded invocation as words, or `None` when this entry records no
    /// invocation at all.
    ///
    /// A pre-split `arguments` wins over `command` wherever both are present:
    /// it is the spelling the generator did not have to quote, so it is the
    /// one that needs no reading back.
    #[must_use]
    pub fn words(&self) -> Option<Vec<String>> {
        match (&self.arguments, &self.command) {
            (Some(arguments), _) => Some(arguments.clone()),
            (None, Some(command)) => Some(split_command(command)),
            (None, None) => None,
        }
    }

    /// The translation unit's source, in the place the command reads it from.
    #[must_use]
    pub fn source(&self) -> PathBuf {
        resolve_in_directory(
            self.directory.as_deref().map(Path::new),
            Path::new(&self.file),
        )
    }
}

/// `path` as the command that recorded it reads it: made absolute against the
/// directory the command was to run in.
///
/// A relative path means nothing on its own. Read against this process's own
/// working directory it names whatever file happens to sit there, and folded
/// into a build's identity as it stands it makes two commands that reach
/// different headers under one name look like one build — the compiler
/// resolves each against its own directory, so `-Iinclude` from two build
/// directories is two include paths.
///
/// Left as written when no directory was recorded. There is nothing to resolve
/// it against, and every command in one database that records no directory
/// shares whatever base that was, so they still mean the same place as each
/// other.
#[must_use]
pub fn resolve_in_directory(directory: Option<&Path>, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    directory.map_or_else(|| path.to_path_buf(), |directory| directory.join(path))
}

/// Split a recorded command line into the words a shell would have passed.
///
/// Quoting and backslash escaping only. A database that writes its commands as
/// one string has already lost whatever the shell would have done with them,
/// and guessing at expansion here would invent arguments no compiler was given.
///
/// Words are separated by ASCII spacing, which is what a shell separates them
/// by. A space that is only a space to Unicode is left in the word: a compiler
/// given such a path was given one argument, and splitting it would name two
/// files that do not exist.
#[must_use]
pub fn split_command(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    // Kept apart from emptiness: a quoted empty argument is an argument, and
    // `-DA=` and no `-D` at all are different commands.
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            continue;
        }
        match (character, quote) {
            // A backslash hides the next character where a shell lets it:
            // outside quotation and within double quotes. Within single quotes
            // it is a character like any other.
            ('\\', None | Some('"')) => escaped = true,
            ('"' | '\'', None) => {
                quote = Some(character);
                started = true;
            }
            (_, Some(open)) if character == open => quote = None,
            (_, None) if character.is_ascii_whitespace() => {
                if started || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            _ => word.push(character),
        }
    }
    if started || !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_command_written_as_one_line_is_split_the_way_a_shell_would() {
        assert_eq!(
            split_command("clang++ -c a.cpp"),
            ["clang++", "-c", "a.cpp"]
        );
        assert_eq!(
            split_command(r#"clang++ -I"/o p/inc" -DA=\"x\" a.cpp"#),
            ["clang++", "-I/o p/inc", r#"-DA="x""#, "a.cpp"]
        );
        assert_eq!(
            split_command("cc -DTEXT='a b' -c /w/a.c"),
            ["cc", "-DTEXT=a b", "-c", "/w/a.c"]
        );
        assert_eq!(
            split_command(r#"clang++ "" a.cpp"#),
            ["clang++", "", "a.cpp"]
        );
    }

    /// The separator a reader that only knew about spaces and tabs would glue
    /// two words together over. Both readers ask this one question, so the
    /// words they compare are the same words.
    #[test]
    fn every_ascii_separator_ends_a_word() {
        assert_eq!(
            split_command("cc\t-DA\n-DB\r\n-DC\u{c}/w/a.c"),
            ["cc", "-DA", "-DB", "-DC", "/w/a.c"]
        );
    }

    /// A path containing a space that is not an ASCII space is one path. A
    /// shell hands it to the compiler whole, so splitting it here would name a
    /// file the build never compiled.
    #[test]
    fn spacing_that_is_only_spacing_to_unicode_stays_inside_a_word() {
        assert_eq!(
            split_command("cc -I/w/one\u{a0}two"),
            ["cc", "-I/w/one\u{a0}two"]
        );
    }

    #[test]
    fn a_pre_split_invocation_is_taken_as_it_stands() {
        let recorded = RecordedCommand {
            file: "/w/a.c".to_string(),
            directory: Some("/w".to_string()),
            arguments: Some(vec!["cc".to_string(), "-DA=x y".to_string()]),
            command: Some("cc -DA=other".to_string()),
        };
        assert_eq!(recorded.words(), Some(vec!["cc".into(), "-DA=x y".into()]));
    }

    #[test]
    fn an_entry_that_records_no_invocation_has_no_words() {
        let recorded = RecordedCommand {
            file: "/w/a.c".to_string(),
            directory: None,
            arguments: None,
            command: None,
        };
        assert!(recorded.words().is_none());
    }

    /// The directory a command was to run in is the only thing that says what
    /// its relative paths mean. Two builds that spell one include directory the
    /// same way and reach two different directories through it are two builds,
    /// and only the directory they ran in says so.
    #[test]
    fn a_relative_path_is_read_against_the_directory_the_command_ran_in() {
        assert_eq!(
            resolve_in_directory(Some(Path::new("/w/build")), Path::new("../include")),
            PathBuf::from("/w/build/../include")
        );
        assert_ne!(
            resolve_in_directory(Some(Path::new("/w/one")), Path::new("include")),
            resolve_in_directory(Some(Path::new("/w/two")), Path::new("include"))
        );
    }

    /// An absolute path already says where it is, and a relative one with no
    /// recorded directory has nothing here that says where it is — resolving
    /// that one against this process's own directory would answer about a file
    /// no build ever read.
    #[test]
    fn a_path_that_needs_no_directory_and_one_that_has_none_stand_as_written() {
        let absolute = if cfg!(windows) { r"C:\w\inc" } else { "/w/inc" };
        assert_eq!(
            resolve_in_directory(Some(Path::new("/w/build")), Path::new(absolute)),
            PathBuf::from(absolute)
        );
        assert_eq!(
            resolve_in_directory(None, Path::new("include")),
            PathBuf::from("include")
        );
    }

    #[test]
    fn a_source_is_read_from_where_the_command_ran() {
        let recorded = RecordedCommand {
            file: "../src/a.c".to_string(),
            directory: Some("/w/build".to_string()),
            arguments: None,
            command: Some("cc -c ../src/a.c".to_string()),
        };
        assert_eq!(recorded.source(), PathBuf::from("/w/build/../src/a.c"));
    }

    #[test]
    fn an_entry_is_read_from_what_the_format_writes() {
        let recorded: Vec<RecordedCommand> = serde_json::from_str(
            r#"[{"directory": "/w/build", "file": "../src/a.c", "command": "cc -c ../src/a.c"}]"#,
        )
        .unwrap();
        assert_eq!(recorded[0].file, "../src/a.c");
        assert_eq!(recorded[0].directory.as_deref(), Some("/w/build"));
        assert_eq!(
            recorded[0].words(),
            Some(vec!["cc".into(), "-c".into(), "../src/a.c".into()])
        );
    }
}
