use super::{
    BTreeMap, OptionalExtension, RunOrigin, RunSummary, Store, StoreError, StoredSetting,
    StoredVariant, params,
};

impl Store {
    /// Refuse a run that is absent or has not completed its scan invocation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::RunNotFound`] for an absent row and
    /// [`StoreError::RunNotCompleted`] for any non-completed row, or an
    /// underlying database error.
    pub fn ensure_completed_run(&self, run_id: i64) -> Result<(), StoreError> {
        let status: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM scan_run WHERE id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()?;
        match status.as_deref() {
            Some("completed") => Ok(()),
            Some(_) => Err(StoreError::RunNotCompleted { run_id }),
            None => Err(StoreError::RunNotFound { run_id }),
        }
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
