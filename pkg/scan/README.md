# Vulnerability scanning

Wolfictl can scan APKs for known vulnerabilities. To do this, it relies on [Grype](https://github.com/anchore/grype) to do 99% of the
work. Wolfictl's own code is responsible for managing the handling of SBOM data provided to the scan, as well as vulnerability matching configuration settings, tuned to help account for vulnerabilities discovered downstream in image scans.

## Testing

There are **integration tests** in wolfictl to guard against unexpected behaviors this Grype-based vulnerability scanning
process. This section describes how to work with these tests.

### How the tests work

The tests retrieve a selected set of Wolfi APK files to scan for vulnerabilities. APKs are saved to "git-ignored"
locations in the repository so that they can be reused in subsequent test executions without needing to fetch them
again.

Each test uses a "golden file" as the ground truth, and then compare the output of wolfictl's `(*Scanner).ScanAPKs`
method to that golden file. If there is no diff, the test passes! If there is a diff, the test is failed, and the diff
is reported to the user. JSON representations of the scan results are used to make diffing easier to reason about.

#### The Grype DB

Unlike SBOM generation, vulnerability scanning actually takes **two** inputs: the target artifact to scan, and a dataset of vulnerabilities, to which the target artifact's components will be matched. Wolfictl's vulnerability scanning uses the Grype DB as its vulnerability dataset. The Grype project updates this database every day, but we want our tests to return consistent results on every run, so we've pinned to a specific build of the Grype database. Similar to the APKs used in these tests, the Grype DB used by the tests is fetched only once and stored in the repo tree, as "git-ignored" data.

### Running integration tests

Since these tests are long-running, they are **not run by default** by `go test`. Instead, you can include them in the
executed test suite by using the build tag flag `-tags=integration`.

### What to do when a test fails

When a test fails, a diff is rendered to explain how the `ScanAPK` method's output differed from what was expected (as codified in that test's golden file).

If a test is failing, it's failing for a notable reason. The `ScanAPK` method's output should never change (given
unchanging APK content and an unchanging vulnerability database) under normal circumstances. So when the test fails, it means that something material changed in Grype, Syft, or in wolfictl's wrapping of these libraries. It's important to determine the root cause of
the diff.

The diff either indicates a bug, or it shows an intended change (e.g. by the Syft/Grype maintainers) that wolfictl maintainers
should have a heads-up about, since it may have a nontrivial impact on wolfictl's supported use cases.

If the new output coming from `ScanAPK` seems acceptable, then it's time to update the golden files to reflect the
_new_ ground truth.

### Updating the golden files

**Important!** Only update the golden files after you've thoroughly examined the changes to wolfictl's vulnerability scanning
behavior and determined they are acceptable.

When running these vulnerability scanning tests, you can pass the test flag `-update-golden-files`. Doing so will cause the tests not to
check for diffs, instead saving the current output of the `ScanAPK` method to the golden files. It's important to
check these changes into the git repository, so that everyone else starts using this data as the ground truth for their
test executions.

### Updating the list of APKs used for testing

The set of APK packages used during testing should be diverse, in order to give us a fair chance at identifying inbound
impactful changes from Grype or Syft. One dimension that warrants diversity in particular is "language ecosystem".

The set of packages used in testing has been intentionally chosen to provide this diversity without being excessively
large (costing more test execution time and storage).

But as time goes on, it's natural for the set to need to grow or change. Changing this list should be as simple as:

1. Modifying the `testTargets` string slice as desired.
2. Running the tests with `-update-golden-files` in order to generate golden files for any new APKs.
3. Committing in the repo the changes to both of the above.
