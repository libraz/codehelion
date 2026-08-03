use super::{
    BTreeSet, BuildConfiguration, BuildVariant, HASH_ALGORITHM, Language, Snapshot, StoreError,
    Transaction, params,
};

pub(super) fn upsert_variant(
    tx: &Transaction<'_>,
    variant: &BuildVariant,
) -> Result<i64, StoreError> {
    let languages = variant
        .languages
        .enabled()
        .into_iter()
        .map(Language::name)
        .collect::<Vec<_>>()
        .join(",");
    let headers = variant.headers.map_or("", Language::name);
    // The languages whose builds were resolved, as a set: which of them a run
    // reached first is not a fact about the tree, and the identity beside this
    // column already carries what each was told.
    let build_language = variant
        .builds
        .iter()
        .map(BuildConfiguration::language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    // `ON CONFLICT DO NOTHING` rather than `INSERT OR IGNORE`: the variant is
    // expected to be there already, but only the fingerprint clash is
    // expected. `OR IGNORE` would swallow a `CHECK` violation too and leave the
    // row absent, which surfaces later as a variant that cannot be found rather
    // than as the value that was wrong.
    tx.execute(
        "INSERT INTO build_variant
             (variant_fingerprint, canonical, analysis_mode, normalization_version,
              languages, header_language, build_language)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (variant_fingerprint) DO NOTHING",
        params![
            variant.fingerprint(),
            variant.canonical(),
            variant.mode.name(),
            variant.normalization_version,
            languages,
            headers,
            build_language,
        ],
    )?;
    let id: i64 = tx.query_row(
        "SELECT id FROM build_variant WHERE variant_fingerprint = ?1",
        params![variant.fingerprint()],
        |row| row.get(0),
    )?;
    // Describe the row even when it was already there. Equal fingerprints are
    // equal variants, so this writes back what is already written — except on a
    // row recorded before variants were described, which is the row that has
    // nothing to say and is worth filling in.
    tx.execute(
        "UPDATE build_variant
            SET languages = ?2, header_language = ?3, build_language = ?4
          WHERE id = ?1",
        params![id, languages, headers, build_language],
    )?;
    write_variant_settings(tx, id, variant)?;
    Ok(id)
}

/// Record what the compiler was told, replacing whatever the row held.
///
/// The settings are derived from the same enumeration the variant's identity
/// is, so rewriting them for an existing row restores the same values; a row
/// from before they were recorded gains them.
fn write_variant_settings(
    tx: &Transaction<'_>,
    variant_id: i64,
    variant: &BuildVariant,
) -> Result<(), StoreError> {
    tx.execute(
        "DELETE FROM build_variant_setting WHERE build_variant_id = ?1",
        params![variant_id],
    )?;
    // Written under the language whose build it came from. The two languages
    // name some of the same settings — both have a `compiler_version` — and a
    // record keyed by the name alone would have one compiler's answer standing
    // for the other's.
    for build in &variant.builds {
        for setting in build.settings() {
            for (position, value) in setting.shape.values().into_iter().enumerate() {
                tx.execute(
                    "INSERT INTO build_variant_setting
                         (build_variant_id, language, name, position, value)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        variant_id,
                        build.language(),
                        setting.name,
                        i64::try_from(position).unwrap_or(i64::MAX),
                        value
                    ],
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn upsert_fingerprint(
    tx: &Transaction<'_>,
    kind: &str,
    hash: &[u8; 16],
    snapshot: &Snapshot<'_>,
    variant_id: i64,
    language: Language,
) -> Result<i64, StoreError> {
    let frontend_version = frontend_version_for(snapshot, language);
    insert_fingerprint_row(
        tx,
        kind,
        hash,
        snapshot.variant.normalization_version,
        frontend_version,
        snapshot.variant.mode.name(),
        language.name(),
        variant_id,
    )
}

pub(super) fn upsert_group_fingerprint(
    tx: &Transaction<'_>,
    hash: &[u8; 16],
    snapshot: &Snapshot<'_>,
    variant_id: i64,
) -> Result<i64, StoreError> {
    // Group fingerprints span languages and frontends; both columns hold the
    // empty string so the UNIQUE constraint still deduplicates them.
    insert_fingerprint_row(
        tx,
        "clone_group",
        hash,
        snapshot.variant.normalization_version,
        "",
        snapshot.variant.mode.name(),
        "",
        variant_id,
    )
}

#[allow(clippy::too_many_arguments)] // one row, one call site per column set
fn insert_fingerprint_row(
    tx: &Transaction<'_>,
    kind: &str,
    hash: &[u8; 16],
    normalization_version: u32,
    frontend_version: &str,
    mode: &str,
    language: &str,
    variant_id: i64,
) -> Result<i64, StoreError> {
    let mut insert = tx.prepare_cached(
        "INSERT OR IGNORE INTO fingerprint
             (kind, hash_algo, hash, normalization_version, frontend_version,
              analysis_mode, language, build_variant_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    insert.execute(params![
        kind,
        HASH_ALGORITHM,
        hash.as_slice(),
        normalization_version,
        frontend_version,
        mode,
        language,
        variant_id,
    ])?;
    drop(insert);
    let mut select = tx.prepare_cached(
        "SELECT id FROM fingerprint
         WHERE kind = ?1 AND hash_algo = ?2 AND hash = ?3
           AND normalization_version = ?4 AND frontend_version = ?5
           AND analysis_mode = ?6 AND language = ?7 AND build_variant_id = ?8",
    )?;
    Ok(select.query_row(
        params![
            kind,
            HASH_ALGORITHM,
            hash.as_slice(),
            normalization_version,
            frontend_version,
            mode,
            language,
            variant_id,
        ],
        |row| row.get(0),
    )?)
}

/// The frontend version active for `language` in this snapshot, from the
/// declared detector versions (`frontend.<language>` component).
pub(super) fn frontend_version_for<'a>(snapshot: &'a Snapshot<'_>, language: Language) -> &'a str {
    let component = match language {
        Language::Rust => "frontend.rust",
        Language::C => "frontend.c",
        Language::Cpp => "frontend.cpp",
    };
    snapshot
        .detector_versions
        .iter()
        .find(|(c, _)| c == component)
        .map_or("unknown", |(_, v)| v.as_str())
}
