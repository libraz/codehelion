# Analysis fixtures

Small projects that exist to be *read*, not to be built. A compiler helper is
judged by what it reports about a project whose answer is already known, so
each fixture here is written around one question a helper has to get right, and
kept small enough that a person can check the answer by eye.

Nothing in this directory is a workspace member. Building or testing codehelion
never compiles these, and the fixtures that could execute code — a build script,
a procedural macro — are here precisely so that a test can prove they were *not*
executed. A fixture that runs during an ordinary build would destroy the only
evidence that default settings keep the target's code from running.

## Rust

| Fixture | The question it asks |
|---|---|
| `rust/plain` | A two-crate workspace with nothing unusual in it. The baseline: a helper that cannot analyse this cannot analyse anything. |
| `rust/features` | The same source under two feature settings, where the feature changes a resolved type. Two build variants that a purely textual reading cannot tell apart. |
| `rust/dispatch` | The same method call written against a concrete type, a type parameter and a trait object, plus a call to a value rather than a name. Which body a call reaches, and whether that is decided here at all. |
| `rust/macro-rules` | One declarative macro invoked twice, beside the same shape written by hand. Expanding it runs nothing, so the two bodies are there to be reported — and they are identical, which is why what came out of a macro has to be distinguishable from what somebody typed. |
| `rust/build-script` | A crate whose `build.rs` writes a marker file into its own directory. Its presence is the evidence that something ran the build script. |
| `rust/proc-macro` | A derive macro and the crate that uses it. Expanding it means running the macro crate; declining to expand it means saying so rather than reporting the unexpanded text as the truth. |

## C / C++

| Fixture | The question it asks |
|---|---|
| `cpp/cmake` | A conventional CMake project with several translation units. The baseline for a `compile_commands.json`-driven helper. |
| `cpp/header-only` | One header compiled into two translation units under different `-D` values, producing different types from identical text. The case where a physical source location has no single meaning. |

### `compile_commands.json`

A compilation database records absolute paths, which cannot be committed. Each
C/C++ fixture therefore carries `compile_commands.json.in`, the same document
with `@DIRECTORY@` where the absolute path of the fixture belongs. Tests render
it; nobody has to have CMake installed for a helper's tests to run.

The `CMakeLists.txt` beside it is the real thing, so the database can be
regenerated when the sources change:

```sh
cmake -S fixtures/cpp/cmake -B /tmp/ch-fixture -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Running CMake configures the project, which is an execution path the tool itself
refuses by default. That is a person's command to run, deliberately, not
something a scan does.
