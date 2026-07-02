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

use loom::model::{Pat, Repo};
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
        protect_default_branch: false,
        forked_from_id: String::new(),
        created_at: created,
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
        "pr_review_comments",
        "pr_reviews",
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
        .update_repo_settings(&got.id, "edited words", "develop", true, true)
        .await
        .unwrap());
    let edited = store.get_repo("alice", "pub").await.unwrap().unwrap();
    assert_eq!(edited.description, "edited words");
    assert_eq!(edited.default_branch, "develop");
    assert!(edited.require_approval);
    assert!(edited.protect_default_branch);
    assert!(!store
        .update_repo_settings("rp_missing", "x", "main", false, false)
        .await
        .unwrap());
    // Restore for the assertions below.
    assert!(store
        .update_repo_settings(&got.id, "desc pub", "main", false, false)
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
            "pl1", &repo_id, "add x", "body", "main", "feat", "alice", now,
        )
        .await
        .unwrap();
    let pr2 = store
        .create_pull("pl2", &repo_id, "add y", "", "main", "fix", "bob", now + 1)
        .await
        .unwrap();
    assert_eq!(pr1.number, 1);
    assert_eq!(pr2.number, 2);
    assert_eq!(store.open_pull_count(&repo_id).await.unwrap(), 2);

    let listed_pulls: Vec<i64> = store
        .list_pulls(&repo_id)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.number)
        .collect();
    assert_eq!(listed_pulls, vec![2, 1]); // newest number first

    assert!(store.set_pull_state("pl2", "closed").await.unwrap());
    assert!(store.merge_pull("pl1", now + 5).await.unwrap());
    let merged = store.get_pull(&repo_id, 1).await.unwrap().unwrap();
    assert!(merged.is_merged());
    assert_eq!(merged.merged_at, now + 5);
    // The merge guard refuses a second merge (already non-open).
    assert!(!store.merge_pull("pl1", now + 6).await.unwrap());
    assert_eq!(store.open_pull_count(&repo_id).await.unwrap(), 0);

    assert!(store
        .set_pull_metadata("pl2", &milestone.id, std::slice::from_ref(&label.id))
        .await
        .unwrap());
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
    assert_eq!(store.list_pull_reviews("pl2").await.unwrap().len(), 1);
    assert_eq!(
        store.list_pull_review_comments("pl2").await.unwrap().len(),
        1
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
