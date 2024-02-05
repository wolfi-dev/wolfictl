# Fork point

"Fork point" is a concept from git that wolfictl extends in some of its state comparison logic, particularly for advisory diffing and advisory validation.

To learn more about how fork points are used in _git_, see `man git-merge-base` and search for `fork-point`.

## tl;dr

A "fork point" is the specific commit in the upstream repository's main branch from which your working branch started. It's similar to a "merge base", but not the same thing, as we'll see below.

## Examples

All commit histories start at the bottom of the diagram and progress upward.

### Scenario 1

You've pulled latest from the upstream `main` branch, where the most recent commit is `B`. From `B`, you create your working branch, and you begin making changes. You commit your changes as `C` on your working branch.

```text
  C
 /
B <-- fork point
|
A
```

In this scenario, commit `B` would be the fork point.

Wolfictl can determine what you've changed from the upstream state by comparing the state you've created (e.g. commit `C`, or even just looking at your local working tree) to commit `B`.

### Scenario 2

This is similar to Scenario 1, except that after you created a new branch based on commit `B` from the upstream main branch, an additional commit was pushed/merged to the upstream main branch (`D`) that has not been added to your working branch.

```text
D
|
| C
|/
B <-- fork point
|
A
```

In this scenario, `B` is still the fork point. Although `B` is no longer representative of the current upstream state (which is now `D`), `B` was the point in the upstream branch's history from which you originally diverged to create your branch's own history.

To determine what your branch is changing about the upstream state, it's better for wolfictl to compare your state (e.g. `C`) to `B` than to `D`. If your state was semantically compared to `D`, and meaningful changes were made in `D`, any diffing performed would make it appear like your branch was removing those meaningful changes from `D`, when really, your branch's changes semantically have nothing to do with the changes in `D`.

### Scenario 3

Here we continue from scenario 2, where the only new change is that we've merged the upstream main branch (which is still at `D`) into our working branch, as merge commit `E`.

```text
  E
 /|
D |
| |
| C
|/
B <-- fork point
|
A
```

For the git nerds out there, this is the scenario that illustrates the difference between a "fork point" and a "merge base".