//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d --name loom-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=loom \
//!   -p 127.0.0.1:55470:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55470/loom \
//!   cargo test --test pg_store -- --nocapture
//! docker rm -f loom-testpg
//! ```
//!
//! Uses a multi-threaded runtime (matching production); the `Store` trait is async, so the
//! handlers `.await` sqlx natively with no sync-over-async bridge.

use std::sync::Arc;

use loom::model::{CommitStatus, Pat, Release, Repo, RepoDeploy};
use loom::now_secs;
use loom::store::{PgStore, Store};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

fn repo(owner: &str, name: &str, private: bool, created: i64) -> Repo {
    Repo {
        id: format!("rp_{owner}_{name}"),
        owner_sub: owner.to_string(),
        name: name.to_string(),
        description: format!("desc {name}"),
        is_private: private,
        default_branch: "main".to_string(),
        require_approval: false,
        required_approvals: 0,
        require_code_owner_reviews: false,
        protect_default_branch: false,
        forked_from_id: String::new(),
        created_at: created,
    }
}

fn commit_status(repo_id: &str, context: &str, state: &str, updated_at: i64) -> CommitStatus {
    CommitStatus {
        id: format!("cs_{}", context.replace('/', "_")),
        repo_id: repo_id.to_string(),
        commit_sha: "abc123".to_string(),
        state: state.to_string(),
        context: context.to_string(),
        description: format!("{context} {state}"),
        target_url: format!("https://ci.example/{context}"),
        created_at: 1,
        updated_at,
    }
}

fn release(id: &str, repo_id: &str, tag: &str, created_at: i64, draft: bool) -> Release {
    Release {
        id: id.to_string(),
        repo_id: repo_id.to_string(),
        tag_name: tag.to_string(),
        target_commit: format!("{tag}-commit"),
        title: format!("Release {tag}"),
        body_md: format!("notes for {tag}"),
        is_prerelease: false,
        is_draft: draft,
        created_by: "alice".to_string(),
        created_at,
        published_at: if draft { 0 } else { created_at },
    }
}

fn deploy(repo_id: &str, output_directory: &str, auto_deploy: bool, updated_at: i64) -> RepoDeploy {
    RepoDeploy {
        id: "rd1".to_string(),
        repo_id: repo_id.to_string(),
        siteflow_slug: "alice-pub".to_string(),
        siteflow_project_id: "project_alice_pub".to_string(),
        deploy_hook_token: "hook-secret".to_string(),
        deploy_hook_url: "https://siteflow.test/hook".to_string(),
        production_branch: "main".to_string(),
        output_directory: output_directory.to_string(),
        framework: "static".to_string(),
        auto_deploy,
        last_build_job_id: "job1".to_string(),
        preview_url: "https://alice-pub.sites.holdfast.internal".to_string(),
        last_deployed_sha: "abc123".to_string(),
        created_at: 1,
        updated_at,
        cistern_provisioned: false,
        cistern_slug: String::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test (needs external \
             Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Raw pool to reset the tables for a clean run.
    let raw = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    for t in [
        "issue_labels",
        "pull_labels",
        "issue_comments",
        "pull_preview_comments",
        "pr_review_comments",
        "pr_reviews",
        "pr_thread_resolved",
        "pr_file_viewed",
        "repo_deploy",
        "commit_statuses",
        "releases",
        "issues",
        "pulls",
        "labels",
        "milestones",
        "pats",
        "repos",
    ] {
        sqlx::query(&format!("DELETE FROM {t}"))
            .execute(&raw)
            .await
            .unwrap();
    }

    let store: Arc<dyn Store> = Arc::new(pg);
    let now = now_secs();

    // --- repos: create + uniqueness + visibility ---------------------------
    assert!(store
        .create_repo(&repo("alice", "pub", false, now))
        .await
        .unwrap());
    // Duplicate (owner,name) rejected.
    assert!(!store
        .create_repo(&repo("alice", "pub", false, now + 1))
        .await
        .unwrap());
    store
        .create_repo(&repo("alice", "sec", true, now + 2))
        .await
        .unwrap();
    store
        .create_repo(&repo("bob", "bsec", true, now + 3))
        .await
        .unwrap();
    store
        .create_repo(&repo("bob", "pub", false, now + 4))
        .await
        .unwrap(); // same name, other owner

    let got = store
        .get_repo("alice", "pub")
        .await
        .unwrap()
        .expect("repo persisted");
    assert_eq!(got.description, "desc pub");
    assert!(!got.is_private);
    assert_eq!(got.default_branch, "main");

    // Editable settings (description + default branch) via the portable UPDATE.
    assert!(store
        .update_repo_settings(&got.id, "edited words", "develop", 2, true, true)
        .await
        .unwrap());
    let edited = store.get_repo("alice", "pub").await.unwrap().unwrap();
    assert_eq!(edited.description, "edited words");
    assert_eq!(edited.default_branch, "develop");
    assert!(edited.require_approval);
    assert_eq!(edited.required_approvals, 2);
    assert!(edited.require_code_owner_reviews);
    assert!(edited.protect_default_branch);
    assert!(!store
        .update_repo_settings("rp_missing", "x", "main", 0, false, false)
        .await
        .unwrap());
    // Restore for the assertions below.
    assert!(store
        .update_repo_settings(&got.id, "desc pub", "main", 0, false, false)
        .await
        .unwrap());

    let alice_view: Vec<String> = store
        .list_visible_repos("alice")
        .await
        .unwrap()
        .into_iter()
        .map(|r| format!("{}/{}", r.owner_sub, r.name))
        .collect();
    assert!(alice_view.contains(&"alice/sec".to_string())); // own private
    assert!(alice_view.contains(&"alice/pub".to_string()));
    assert!(alice_view.contains(&"bob/pub".to_string())); // other's public
    assert!(!alice_view.contains(&"bob/bsec".to_string())); // never other's private

    // --- issues: sequential numbering per repo + state ---------------------
    let repo_id = got.id.clone();
    let r1 = release("rl1", &repo_id, "v1.0.0", now + 5, false);
    let r2 = release("rl2", &repo_id, "v2.0.0", now + 6, true);
    assert_eq!(store.create_release(&r1).await.unwrap(), Some(r1.clone()));
    assert!(
        store
            .create_release(&release("rl_dup", &repo_id, "v1.0.0", now + 7, false))
            .await
            .unwrap()
            .is_none(),
        "one release per repo tag"
    );
    assert_eq!(store.create_release(&r2).await.unwrap(), Some(r2.clone()));
    assert_eq!(store.release_count(&repo_id, false).await.unwrap(), 1);
    assert_eq!(store.release_count(&repo_id, true).await.unwrap(), 2);
    let release_tags: Vec<String> = store
        .list_releases_by_repo(&repo_id)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.tag_name)
        .collect();
    assert_eq!(release_tags, vec!["v2.0.0", "v1.0.0"]);
    assert_eq!(
        store
            .get_release_by_tag(&repo_id, "v1.0.0")
            .await
            .unwrap()
            .unwrap(),
        r1
    );
    let mut edited_release = r2.clone();
    edited_release.is_draft = false;
    edited_release.published_at = now + 8;
    edited_release.title = "Release v2".to_string();
    assert!(store.update_release(&edited_release).await.unwrap());
    assert_eq!(
        store
            .get_release(&repo_id, "rl2")
            .await
            .unwrap()
            .unwrap()
            .title,
        "Release v2"
    );
    assert!(store.delete_release(&repo_id, "rl1").await.unwrap());
    assert!(store.get_release(&repo_id, "rl1").await.unwrap().is_none());

    assert!(store
        .aggregate_state_for_commit(&repo_id, "abc123")
        .await
        .unwrap()
        .is_none());
    store
        .upsert_commit_status(&commit_status(&repo_id, "ci/anvil", "pending", now + 10))
        .await
        .unwrap();
    assert_eq!(
        store
            .aggregate_state_for_commit(&repo_id, "abc123")
            .await
            .unwrap(),
        Some("pending".to_string())
    );
    let updated = store
        .upsert_commit_status(&commit_status(&repo_id, "ci/anvil", "success", now + 11))
        .await
        .unwrap();
    assert_eq!(updated.state, "success");
    assert_eq!(updated.created_at, 1);
    assert_eq!(updated.updated_at, now + 11);
    store
        .upsert_commit_status(&commit_status(&repo_id, "test", "error", now + 12))
        .await
        .unwrap();
    assert_eq!(
        store
            .aggregate_state_for_commit(&repo_id, "abc123")
            .await
            .unwrap(),
        Some("failure".to_string())
    );
    let contexts: Vec<String> = store
        .list_commit_statuses(&repo_id, "abc123")
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.context)
        .collect();
    assert_eq!(contexts, vec!["ci/anvil", "test"]);

    assert!(store.get_deploy(&repo_id).await.unwrap().is_none());
    let saved_deploy = store
        .upsert_deploy(&deploy(&repo_id, ".", false, now + 13))
        .await
        .unwrap();
    assert_eq!(saved_deploy.siteflow_project_id, "project_alice_pub");
    assert_eq!(saved_deploy.output_directory, ".");
    let edited_deploy = store
        .upsert_deploy(&deploy(&repo_id, "dist", true, now + 14))
        .await
        .unwrap();
    assert_eq!(edited_deploy.output_directory, "dist");
    assert!(edited_deploy.auto_deploy);
    assert_eq!(edited_deploy.updated_at, now + 14);

    let i1 = store
        .create_issue("is1", &repo_id, "first", "body", "alice", now)
        .await
        .unwrap();
    let i2 = store
        .create_issue("is2", &repo_id, "second", "", "bob", now + 1)
        .await
        .unwrap();
    assert_eq!(i1.number, 1);
    assert_eq!(i2.number, 2);
    assert_eq!(store.open_issue_count(&repo_id).await.unwrap(), 2);

    let fetched = store.get_issue(&repo_id, 1).await.unwrap().unwrap();
    assert_eq!(fetched.title, "first");
    assert_eq!(fetched.author_sub, "alice");
    assert!(fetched.is_open());

    assert!(store
        .set_issue_state("is1", "closed", now + 9)
        .await
        .unwrap());
    assert_eq!(store.open_issue_count(&repo_id).await.unwrap(), 1);
    // Closing stamps updated_at.
    assert_eq!(
        store
            .get_issue(&repo_id, 1)
            .await
            .unwrap()
            .unwrap()
            .updated_at,
        now + 9
    );

    let listed: Vec<i64> = store
        .list_issues(&repo_id)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.number)
        .collect();
    assert_eq!(listed, vec![2, 1]); // newest number first

    // Filter + pagination via the portable SQL path.
    assert_eq!(store.count_issues(&repo_id, "", "", "").await.unwrap(), 2);
    assert_eq!(
        store.count_issues(&repo_id, "open", "", "").await.unwrap(),
        1
    );
    assert_eq!(
        store
            .count_issues(&repo_id, "closed", "", "")
            .await
            .unwrap(),
        1
    );
    let open_only: Vec<i64> = store
        .list_issues_page(&repo_id, "open", "", "", 10, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.number)
        .collect();
    assert_eq!(open_only, vec![2]); // is1 (#1) is closed
    let first_page: Vec<i64> = store
        .list_issues_page(&repo_id, "", "", "", 1, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.number)
        .collect();
    assert_eq!(first_page, vec![2]); // newest first, limit 1

    // Labels/milestones attach to issues and PRs through portable relation tables.
    let label = store
        .create_label("lb1", &repo_id, "bug", "dc2626", now + 10)
        .await
        .unwrap()
        .unwrap();
    let milestone = store
        .create_milestone("ms1", &repo_id, "v1", "2026-08-01", now + 11)
        .await
        .unwrap()
        .unwrap();
    assert!(store
        .set_issue_metadata(
            "is2",
            "alice",
            &milestone.id,
            std::slice::from_ref(&label.id)
        )
        .await
        .unwrap());
    assert_eq!(
        store.issue_labels("is2").await.unwrap(),
        vec![label.clone()]
    );
    let filtered_issue_numbers: Vec<i64> = store
        .list_issues_page(&repo_id, "", &label.id, &milestone.id, 10, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|i| i.number)
        .collect();
    assert_eq!(filtered_issue_numbers, vec![2]);

    // Comments: chronological thread + last-activity bump on the parent issue.
    store
        .create_comment("ic1", "is2", "alice", "first note", now + 20)
        .await
        .unwrap();
    store
        .create_comment("ic2", "is2", "bob", "second note", now + 21)
        .await
        .unwrap();
    let thread: Vec<String> = store
        .list_comments("is2")
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.body)
        .collect();
    assert_eq!(
        thread,
        vec!["first note".to_string(), "second note".to_string()]
    );
    assert_eq!(
        store
            .get_issue(&repo_id, 2)
            .await
            .unwrap()
            .unwrap()
            .updated_at,
        now + 21
    );

    // --- pulls: sequential numbering + state + merge guard -----------------
    let pr1 = store
        .create_pull(
            "pl1", &repo_id, "add x", "body", "main", "feat", "alice", false, now,
        )
        .await
        .unwrap();
    let pr2 = store
        .create_pull(
            "pl2",
            &repo_id,
            "add y",
            "",
            "main",
            "fix",
            "bob",
            true,
            now + 1,
        )
        .await
        .unwrap();
    assert_eq!(pr1.number, 1);
    assert_eq!(pr2.number, 2);
    assert!(!pr1.is_draft);
    assert!(pr2.is_draft);
    assert_eq!(store.open_pull_count(&repo_id).await.unwrap(), 2);

    let listed_pulls: Vec<i64> = store
        .list_pulls(&repo_id)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.number)
        .collect();
    assert_eq!(listed_pulls, vec![2, 1]); // newest number first

    let open_feat: Vec<i64> = store
        .list_open_pulls_by_head(&repo_id, "feat")
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.number)
        .collect();
    assert_eq!(open_feat, vec![1]);

    store
        .upsert_pull_preview_comment(
            &pr1.id,
            "build_1",
            "building",
            "",
            "deadbeefcafebabe",
            "building",
            now + 2,
        )
        .await
        .unwrap();
    store
        .upsert_pull_preview_comment(
            &pr1.id,
            "build_2",
            "ready",
            "https://preview.example",
            "deadbeefcafebabe",
            "ready",
            now + 3,
        )
        .await
        .unwrap();
    let preview = store
        .get_pull_preview_comment(&pr1.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preview.build_job_id, "build_2");
    assert_eq!(preview.deployment_status, "ready");
    assert_eq!(preview.preview_url, "https://preview.example");

    assert!(!store.merge_pull("pl2", now + 4).await.unwrap());
    assert!(store.set_pull_draft("pl2", false).await.unwrap());
    assert!(!store.get_pull(&repo_id, 2).await.unwrap().unwrap().is_draft);
    assert!(store.set_pull_state("pl2", "closed").await.unwrap());
    assert!(store.merge_pull("pl1", now + 5).await.unwrap());
    let merged = store.get_pull(&repo_id, 1).await.unwrap().unwrap();
    assert!(merged.is_merged());
    assert_eq!(merged.merged_at, now + 5);
    // The merge guard refuses a second merge (already non-open).
    assert!(!store.merge_pull("pl1", now + 6).await.unwrap());
    assert_eq!(store.open_pull_count(&repo_id).await.unwrap(), 0);

    assert!(store
        .set_pull_metadata(
            "pl2",
            "bob",
            "carol",
            &milestone.id,
            std::slice::from_ref(&label.id),
        )
        .await
        .unwrap());
    let assigned_pull = store.get_pull(&repo_id, 2).await.unwrap().unwrap();
    assert_eq!(assigned_pull.assignee_sub, "bob");
    assert_eq!(assigned_pull.reviewer_sub, "carol");
    assert_eq!(store.pull_labels("pl2").await.unwrap(), vec![label.clone()]);
    assert_eq!(
        store
            .list_pulls_filtered(&repo_id, &label.id, &milestone.id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(store
        .create_pull_review("rv1", "pl2", "alice", "approve", "ok", now + 30)
        .await
        .is_ok());
    assert!(store
        .create_pull_review_comment(
            "rc1",
            "pl2",
            "rv1",
            "file.txt",
            2,
            "alice",
            "note",
            now + 31
        )
        .await
        .is_ok());
    assert!(store
        .create_pending_pull_review_comment(
            "rc2",
            "pl2",
            "src/lib.rs",
            4,
            "alice",
            "draft note",
            now + 32
        )
        .await
        .is_ok());
    assert!(store
        .create_pending_pull_review_comment(
            "rc3",
            "pl2",
            "src/lib.rs",
            6,
            "bob",
            "other draft",
            now + 33
        )
        .await
        .is_ok());
    assert_eq!(store.list_pull_reviews("pl2").await.unwrap().len(), 1);
    assert_eq!(
        store.list_pull_review_comments("pl2").await.unwrap().len(),
        1
    );
    assert_eq!(
        store
            .list_pull_review_comments_for_viewer("pl2", "alice")
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store
            .list_pull_review_comments_for_viewer("pl2", "carol")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .pending_pull_review_comment_count("pl2", "alice")
            .await
            .unwrap(),
        1
    );
    let (_review, published) = store
        .create_pull_review_with_pending_comments(
            "rv2",
            "pl2",
            "alice",
            "request_changes",
            "finish",
            now + 34,
        )
        .await
        .unwrap();
    assert_eq!(published, 1);
    assert_eq!(store.list_pull_reviews("pl2").await.unwrap().len(), 2);
    assert_eq!(
        store.list_pull_review_comments("pl2").await.unwrap().len(),
        2
    );
    assert_eq!(
        store
            .pending_pull_review_comment_count("pl2", "bob")
            .await
            .unwrap(),
        1
    );
    let viewed = store
        .set_pr_file_viewed("pl2", "alice", "file.txt", true, now + 35)
        .await
        .unwrap();
    assert!(viewed.viewed);
    assert_eq!(viewed.updated_at, now + 35);
    let updated_viewed = store
        .set_pr_file_viewed("pl2", "alice", "file.txt", false, now + 33)
        .await
        .unwrap();
    assert!(!updated_viewed.viewed);
    assert_eq!(
        store
            .list_pr_file_viewed_for_pr("pl2", "alice")
            .await
            .unwrap(),
        vec![updated_viewed]
    );
    store
        .set_pr_file_viewed("pl2", "bob", "file.txt", true, now + 34)
        .await
        .unwrap();
    assert_eq!(
        store
            .list_pr_file_viewed_for_pr("pl2", "bob")
            .await
            .unwrap()
            .len(),
        1
    );
    let resolved = store
        .set_pr_thread_resolved("pl2", "file.txt:2", true, "alice", now + 36)
        .await
        .unwrap();
    assert!(resolved.resolved);
    assert_eq!(resolved.resolved_by, "alice");
    let reopened = store
        .set_pr_thread_resolved("pl2", "file.txt:2", false, "bob", now + 37)
        .await
        .unwrap();
    assert!(!reopened.resolved);
    assert_eq!(
        store.list_pr_thread_resolved("pl2").await.unwrap(),
        vec![reopened]
    );

    // --- pats: hash lookup + ownership-scoped revoke -----------------------
    store
        .create_pat(&Pat {
            id: "pt1".into(),
            owner_sub: "alice".into(),
            name: "laptop".into(),
            token_hash: "abc123hash".into(),
            created_at: now,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .find_pat_by_hash("abc123hash")
            .await
            .unwrap()
            .unwrap()
            .owner_sub,
        "alice"
    );
    assert!(store.find_pat_by_hash("missing").await.unwrap().is_none());
    assert!(!store.revoke_pat("pt1", "bob").await.unwrap()); // wrong owner
    assert!(store.revoke_pat("pt1", "alice").await.unwrap());
    assert!(store
        .find_pat_by_hash("abc123hash")
        .await
        .unwrap()
        .is_none());

    // --- raw count sanity (portable SQL path is live) ----------------------
    let row = sqlx::query("SELECT count(*) AS n FROM repos")
        .fetch_one(&raw)
        .await
        .unwrap();
    let n: i64 = row.try_get("n").unwrap();
    assert_eq!(n, 4);

    for t in [
        "issue_labels",
        "pull_labels",
        "issue_comments",
        "pr_review_comments",
        "pr_reviews",
        "pr_thread_resolved",
        "pr_file_viewed",
        "issues",
        "pulls",
        "labels",
        "milestones",
        "pats",
        "repos",
    ] {
        sqlx::query(&format!("DELETE FROM {t}"))
            .execute(&raw)
            .await
            .unwrap();
    }
    eprintln!("pg_store integration test passed.");
}
