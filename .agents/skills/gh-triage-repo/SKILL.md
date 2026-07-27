---
name: gh-triage-repo
description: Triage and maintain this GitHub repository with the GitHub CLI. Use when asked to fetch or review recent issues or pull requests, identify duplicates, ask the maintainer for a disposition on each item, post comments, add labels, close issues or PRs, merge approved PRs, or prepare repository changes under protected-main rules.
---

# GitHub Repository Triage

Use `gh` to turn the repository's current issues and pull requests into explicit maintainer decisions, then apply only the approved actions.

## Authenticate Safely

1. Run `gh auth status` before GitHub operations.
2. Prefer an existing authenticated session or a `GH_TOKEN` already exported by the user.
3. Never request that a token be pasted into chat, place a token in a command line, print it, or write it to repository files. If authentication is missing, ask the user to run `gh auth login` or export `GH_TOKEN` in their terminal.
4. Resolve the repository from `git remote get-url origin`; do not assume an owner or repository name.

## Discover Current Work

Start read-only. Preserve unrelated working-tree changes.

```sh
git status -sb
gh issue list --limit 10 --state open --json number,title,author,createdAt,updatedAt,url,labels,body
gh pr list --limit 10 --state open --json number,title,author,createdAt,updatedAt,url,labels,body,headRefName,baseRefName,isDraft,mergeStateStatus,reviewDecision
```

For each likely issue duplicate, inspect comments and search all states before choosing a canonical item:

```sh
gh issue view NUMBER --comments --json number,title,body,comments,state,labels,url
gh issue list --state all --search "DISTINCTIVE TERMS" --json number,title,state,url,labels
gh label list --limit 100 --json name,description
```

For each PR, inspect the actual patch and checks rather than relying on its description:

```sh
gh pr view NUMBER --comments --json number,title,body,comments,files,commits,statusCheckRollup,mergeStateStatus,reviewDecision,url,author,headRefName,baseRefName,isDraft
gh pr diff NUMBER --patch
gh pr checks NUMBER
```

## Ask for Disposition

Summarize each item in the user's language, but draft public GitHub comments in English unless requested otherwise. Ask for a decision per item before any GitHub write.

Offer only relevant choices, such as:

- Issue: investigate/fix, request logs, documentation answer, duplicate, wontfix, or close as resolved.
- PR: verify and merge, request changes/tests, wait for draft completion, superseded/close, or manually adopt selected changes.

State the proposed canonical issue or fixing PR for every duplicate. Do not mark symptomatically similar reports as duplicates without evidence from bodies, comments, logs, or code history.

## Apply Approved Actions

Re-read item state immediately before mutation so concurrent updates are not missed.

For a confirmed duplicate, use the existing `duplicate` label, post a concise comment linking the canonical issue or merged PR, then close:

```sh
gh issue edit NUMBER --add-label duplicate
gh issue close NUMBER --comment "Closing this as a duplicate of #CANONICAL. ..."
```

For issue guidance, state the diagnosis, exact user action, relevant documentation, and whether the issue remains open. Avoid promising unimplemented work.

For PRs:

1. Keep drafts open unless the maintainer explicitly chooses otherwise.
2. Validate the changed behavior locally in proportion to risk.
3. Preserve author attribution by merging the PR rather than recreating an equivalent commit when practical.
4. Comment before merge/close with the result and any test evidence.
5. Use the repository's accepted merge method; default to squash only when no repository convention says otherwise.

## Respect Protected Main

Never implement repository file changes directly on `main`.

1. Confirm a clean or understood worktree with `git status -sb`.
2. Fetch and create a focused branch from `origin/main`:

```sh
git fetch origin
git switch -c TYPE/SHORT-DESCRIPTION origin/main
```

3. Edit with scoped changes, validate, commit, push the branch, and open a PR.
4. Do not overwrite, stash, reset, or discard unrelated user changes. If they block branch creation, stop and explain the conflict.
5. After merge, fetch and verify local/remote status. Do not force-push protected branches.

## Verify and Report

After writes, query GitHub again and report concrete outcomes:

- Final state and labels for every changed issue.
- Final state, merge commit, and checks for every changed PR.
- Canonical item retained for duplicate groups.
- Branch and PR URL for repository changes.
- Local `git status -sb`; the worktree should be clean unless intentional changes remain.

Keep comments factual and concise. Never expose authentication material in updates or the final response.
