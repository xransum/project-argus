# TODO

## Cleanup

- Remove orphaned `src/project_argus/api/jobs.py` -- leftover SQLite-backed jobs
  router, never imported, would ImportError if it were (db.py no longer exists)
- Remove unused `JobResultsResponse` model in `src/project_argus/models/job_models.py`
  -- defined for the old SQLite API, superseded by the DynamoDB/S3 approach

## Frontend

- Expose `progress_pct` in the UI -- the API already computes and returns it in
  `JobStatusResponse` but `app.js` ignores it and builds its own `completed/total`
  string instead
- Surface `error_samples` in the UI -- `JobStatusResponse` includes the field but
  `app.js` only reads `last_error`
