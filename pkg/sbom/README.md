# SBOM Generation

Wolfictl can generate SBOMs for APKs. To do this, it relies on [Syft](https://github.com/anchore/syft) to do 99% of the work, and then handles a few extra things on top in order to produce SBOMs more useful for our purposes, especially for vulnerability scanning.

## Testing

There are **integration tests** in wolfictl to guard against unexpected behaviors this Syft-based SBOM generation process. This section describes how to work with these tests.

The tests retrieve a selected set of Wolfi APK files for which to generate SBOMs. APKs are saved to "git-ignored" locations in the repository so that they can be reused in subsequent test executions without needing to fetch them again.

Each test uses a "golden file" as the ground truth, and then compare the output of wolfictl's `sbom.Generate` function to that golden file. If there is no diff, the test passes! If there is a diff, the test is failed, and the diff is reported to the user. JSON representations of the SBOM are used to make diffing easier to reason about. The JSON data uses Syft's native SBOM format.

### Running integration tests

Since these tests are long-running, they are **not run by default** by `go test`. Instead, you can include them in the executed test suite by using the build tag flag `-tags=integration`.

### What to do when a test fails

When a test fails, a diff is rendered to explain how the `Generate` function's output differed from what was expected (as codified in that test's golden file).

If a test is failing, it's failing for a notable reason. The `Generate` function's output should never change (given unchanging APK content) under normal circumstances. So when the test fails, it means that something material changed in Syft's logic, or in the remaining SBOM logic coming from wolfictl itself. It's important to determine the root cause of the diff.

The diff either indicates a bug, or it shows an intended change (e.g. by the Syft maintainers) that wolfictl maintainers should have a heads-up about, since it may have a nontrivial impact on wolfictl's supported use cases.

If the new output coming from `Generate` seems acceptable, then it's time to update the golden files to reflect the _new_ ground truth.

### Updating the golden files

**Important!** Only update the golden files after you've thoroughly examined the changes to wolfictl's SBOM generation behavior and determined they are acceptable.

When running these SBOM tests, you can pass the test flag `-update-golden-files`. Doing so will cause the tests not to check for diffs, instead saving the current output of the `Generate` function to the golden files. It's important to check these changes into the git repository, so that everyone else starts using this data as the ground truth for their test executions.

### Updating the list of APKs used for testing

The set of APK packages used during testing should be diverse, in order to give us a fair chance at identifying inbound impactful changes from Syft. One dimension that warrants diversity in particular is "language ecosystem".

The set of packages used in testing has been intentionally chosen to provide this diversity without being excessively large (costing more test execution time and storage).

But as time goes on, it's natural for the set to need to grow or change. Changing this list should be as simple as:

1. Modifying the `testTargets` string slice as desired.
2. Running the tests with `-update-golden-files` in order to generate golden files for any new APKs.
3. Committing in the repo the changes to both of the above.
