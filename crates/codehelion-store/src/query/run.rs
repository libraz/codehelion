use super::{
    BTreeMap, CloneGroupFingerprint, GroupLineageId, OptionalExtension, RunOrigin, RunSummary,
    Store, StoreError, StoredGroupSnapshot, StoredSetting, StoredVariant, params,
};

impl Store {
    /// Newest completed run for one root, analysis mode and exact build
    /// variant.
    ///
    /// All three have to agree for two runs to be about the same question:
    /// results computed under different build variants or under a different
    /// analysis mode are never compared with one another.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_run_for_variant(
        &self,
        root_path: &str,
        analysis_mode: &str,
        variant_fingerprint: &str,
    ) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 JOIN build_variant v ON v.id = r.build_variant_id
                 WHERE r.root_path = ?1
                   AND r.analysis_mode = ?2
                   AND v.variant_fingerprint = ?3
                   AND r.status = 'completed'
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                params![root_path, analysis_mode, variant_fingerprint],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// How many completed runs share one root, analysis mode and build
    /// variant, and are therefore comparable with one another.
    ///
    /// A count of one says a recorded run has nothing to be compared with, so
    /// a caller cannot report what a later run made of the same finding.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn comparable_run_count(
        &self,
        root_path: &str,
        analysis_mode: &str,
        variant_fingerprint: &str,
    ) -> Result<u64, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*)
                 FROM scan_run r
                 JOIN build_variant v ON v.id = r.build_variant_id
                 WHERE r.root_path = ?1
                   AND r.analysis_mode = ?2
                   AND v.variant_fingerprint = ?3
                   AND r.status = 'completed'",
            params![root_path, analysis_mode, variant_fingerprint],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Newest completed run recorded under the exact analysis configuration.
    ///
    /// This deliberately does not compare source files. Callers first choose
    /// a run whose configuration and build variant agree, then compare the
    /// recorded tree with the files they just discovered.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_compatible_run(
        &self,
        root_path: &str,
        config_hash: &str,
        variant_fingerprint: &str,
    ) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 JOIN build_variant v ON v.id = r.build_variant_id
                 WHERE r.root_path = ?1
                   AND r.config_hash = ?2
                   AND v.variant_fingerprint = ?3
                   AND r.status = 'completed'
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                params![root_path, config_hash, variant_fingerprint],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Group fingerprints and durable lineage identities for one completed run.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent or incomplete run, malformed persisted
    /// identifiers, or an underlying database failure.
    pub fn run_group_snapshots(&self, run_id: i64) -> Result<Vec<StoredGroupSnapshot>, StoreError> {
        self.ensure_completed_run(run_id)?;
        let mut statement = self.conn.prepare(
            "SELECT f.hash, g.lineage
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             WHERE g.scan_run_id = ?1
             ORDER BY f.hash ASC",
        )?;
        statement
            .query_map(params![run_id], |row| {
                let fingerprint = bytes16("clone_group.fingerprint", row.get(0)?)?;
                let lineage = bytes16("clone_group.lineage", row.get(1)?)?;
                Ok(StoredGroupSnapshot {
                    fingerprint: CloneGroupFingerprint::from_bytes(fingerprint),
                    lineage: Some(GroupLineageId::from_bytes(lineage)),
                })
            })?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
    /// Refuse a run that is absent or has not completed its scan invocation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RunNotFound`] for an absent row and
    /// [`StoreError::RunNotCompleted`] for any non-completed row, or an
    /// underlying database error.
    pub fn ensure_completed_run(&self, run_id: i64) -> Result<(), StoreError> {
        crate::lifecycle::ensure_completed_run(&self.conn, run_id)
    }

    /// The most recently started scan run, if any.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_run(&self) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                [],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// The newest completed scan run across all recorded roots.
    ///
    /// This is used by database-only commands whose input does not identify a
    /// repository root, such as artifact calibration.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_completed_run_any_root(&self) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 WHERE r.status = 'completed'
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                [],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// One scan run by row id, if the database holds it.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_summary(&self, run_id: i64) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 WHERE r.id = ?1",
                params![run_id],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// The files one run read, by path relative to the scan root, each with
    /// the hash of what it held.
    ///
    /// Empty for a run that recorded no files, which is every run written
    /// before the tree was recorded at all. "Read nothing" and "did not say"
    /// are not distinguishable after the fact, so a caller that needs the
    /// difference has to decide what an empty answer means to it.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_tree(&self, run_id: i64) -> Result<BTreeMap<String, String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT relative_path, content_hash FROM scanned_file
             WHERE scan_run_id = ?1
             ORDER BY relative_path",
        )?;
        let mut tree = BTreeMap::new();
        for row in stmt.query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (path, hash) = row?;
            tree.insert(path, hash);
        }
        Ok(tree)
    }

    /// Row id of the newest completed run over `root_path`, optionally
    /// narrowed to one build variant.
    ///
    /// Narrowing is what makes two runs comparable file by file; leaving it
    /// open is for the callers that read a run in order to *record* which
    /// variant it used, and so cannot name it in advance.
    fn completed_run_id(
        &self,
        root_path: &str,
        variant_fingerprint: Option<&str>,
    ) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT r.id
                 FROM scan_run r
                 JOIN build_variant v ON v.id = r.build_variant_id
                 WHERE r.root_path = ?1
                   AND (?2 IS NULL OR v.variant_fingerprint = ?2)
                   AND r.status = 'completed'
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                params![root_path, variant_fingerprint],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// How many files of each language a run read, by language name.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_language_counts(&self, run_id: i64) -> Result<BTreeMap<String, u64>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT language, count(*) FROM scanned_file
             WHERE scan_run_id = ?1 GROUP BY language ORDER BY language",
        )?;
        let mut counts = BTreeMap::new();
        for row in stmt.query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (language, count) = row?;
            counts.insert(language, u64::try_from(count).unwrap_or(0));
        }
        Ok(counts)
    }

    /// The newest completed run over `root_path`, with the identity a
    /// judgement about its results has to be qualified by.
    ///
    /// This does not narrow to a variant: the caller is reading the current
    /// snapshot in order to record what it was, so the variant is an answer
    /// rather than a question.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_completed_run(&self, root_path: &str) -> Result<Option<RunOrigin>, StoreError> {
        let Some(run_id) = self.completed_run_id(root_path, None)? else {
            return Ok(None);
        };
        self.run_origin(run_id).map(Some)
    }

    /// Every completed partition belonging to the newest scan invocation over
    /// `root_path`.
    ///
    /// The scan driver gives every partition of one invocation the same
    /// caller-owned start timestamp and promotes them together. Reading this
    /// set, rather than the single newest row, keeps a semantic baseline from
    /// silently freezing only one language or build configuration.
    ///
    /// # Errors
    ///
    /// Returns any database error or an error while reading a completed
    /// partition's origin.
    pub fn latest_completed_invocation(
        &self,
        root_path: &str,
    ) -> Result<Vec<RunOrigin>, StoreError> {
        let started_at: Option<String> = self
            .conn
            .query_row(
                "SELECT started_at FROM scan_run
                 WHERE root_path = ?1 AND status = 'completed'
                 ORDER BY started_at DESC, id DESC LIMIT 1",
                params![root_path],
                |row| row.get(0),
            )
            .optional()?;
        let Some(started_at) = started_at else {
            return Ok(Vec::new());
        };
        let mut statement = self.conn.prepare(
            "SELECT id FROM scan_run
             WHERE root_path = ?1 AND started_at = ?2 AND status = 'completed'
             ORDER BY id ASC",
        )?;
        let ids = statement
            .query_map(params![root_path, started_at], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        ids.into_iter().map(|id| self.run_origin(id)).collect()
    }

    /// The identity of one run by row id: the conditions its stable ids were
    /// computed under, which every judgement about its results is qualified
    /// by.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error, including the case of a run id
    /// this database does not hold.
    pub fn run_origin(&self, run_id: i64) -> Result<RunOrigin, StoreError> {
        self.ensure_completed_run(run_id)?;
        let mut origin = self.conn.query_row(
            "SELECT r.root_path, r.tool_version, r.config_source, r.config_path,
                    r.min_clone_tokens, r.analysis_mode, r.started_at, r.finished_at,
                    v.variant_fingerprint, v.normalization_version
             FROM scan_run r
             JOIN build_variant v ON v.id = r.build_variant_id
             WHERE r.id = ?1",
            params![run_id],
            |row| {
                Ok(RunOrigin {
                    id: run_id,
                    root_path: row.get(0)?,
                    tool_version: row.get(1)?,
                    config_source: row.get(2)?,
                    config_path: row.get(3)?,
                    min_clone_tokens: row.get(4)?,
                    analysis_mode: row.get(5)?,
                    started_at: row.get(6)?,
                    finished_at: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    variant_fingerprint: row.get(8)?,
                    normalization_version: row.get(9)?,
                    detector_versions: Vec::new(),
                })
            },
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT d.component, d.version
             FROM scan_run_detector_version rd
             JOIN detector_version d ON d.id = rd.detector_version_id
             WHERE rd.scan_run_id = ?1
             ORDER BY d.component ASC, d.version ASC",
        )?;
        origin.detector_versions = stmt
            .query_map(params![run_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(origin)
    }

    /// What the variant `fingerprint` names was analysed under, or `None` when
    /// this database holds no such variant.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn build_variant(&self, fingerprint: &str) -> Result<Option<StoredVariant>, StoreError> {
        let Some(mut variant) = self
            .conn
            .query_row(
                "SELECT id, variant_fingerprint, analysis_mode, languages,
                        header_language, build_language
                 FROM build_variant
                 WHERE variant_fingerprint = ?1",
                params![fingerprint],
                |row| {
                    Ok(StoredVariant {
                        id: row.get(0)?,
                        fingerprint: row.get(1)?,
                        analysis_mode: row.get(2)?,
                        languages: row.get(3)?,
                        header_language: row.get(4)?,
                        build_language: row.get(5)?,
                        settings: Vec::new(),
                    })
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT language, name, position, value
             FROM build_variant_setting
             WHERE build_variant_id = ?1
             ORDER BY language ASC, name ASC, position ASC",
        )?;
        variant.settings = stmt
            .query_map(params![variant.id], |row| {
                Ok(StoredSetting {
                    language: row.get(0)?,
                    name: row.get(1)?,
                    position: row.get(2)?,
                    value: row.get(3)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Some(variant))
    }
}

fn bytes16(field: &'static str, bytes: Vec<u8>) -> Result<[u8; 16], rusqlite::Error> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{field} has {} bytes; expected 16", bytes.len()),
            )),
        )
    })
}

impl Store {
    /// The completed run one run was compared with when it was recorded.
    ///
    /// A run's continuity decisions were made against the newest completed run
    /// that agreed with it on root, configuration and build variant. Resolving
    /// the same run again is what lets a later lookup explain a decision the
    /// same way the report that recorded it did.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn preceding_compatible_run(&self, run_id: i64) -> Result<Option<i64>, StoreError> {
        self.conn
            .query_row(
                "SELECT previous.id
                 FROM scan_run current
                 JOIN scan_run previous
                      ON previous.root_path = current.root_path
                     AND previous.config_hash = current.config_hash
                     AND previous.build_variant_id = current.build_variant_id
                     AND previous.status = 'completed'
                     AND (previous.started_at, previous.id) < (current.started_at, current.id)
                 WHERE current.id = ?1
                 ORDER BY previous.started_at DESC, previous.id DESC
                 LIMIT 1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }
}
