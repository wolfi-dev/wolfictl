# Distro Detection

Some commands in `wolfictl` need access to the set of package build configurations for the distro you're currently working with (e.g. Wolfi). Some commands need access to the set of the distro's security advisories. **Some commands need access to both things at the same time!**

For situations like these, `wolfictl` must figure out two things:

1. Which distro you're trying to operate on
2. Where to find the package configuration files and/or advisory documents for that distro

## Using auto-detection

For commands that support distro auto-detection, you don't need to use any special flags or environment variables.

You'll see "Auto-detected distro: (distro name)" in the output to confirm which distro was identified. This means `wolfictl` was able to find all the distro-related context it needed.

**Example: Listing all packages defined in Wolfi**

```console
$ wolfictl ls
Auto-detected distro: Wolfi

7zip
R
aactl
abseil-cpp
acl
...
```

**Example: Discovering new vulnerabilities for packages in Wolfi**

```console
$ wolfictl adv discover
Auto-detected distro: Wolfi

∙∙● searching for vulnerabilities: amass

10 clean, 0 vulnerable, 1557 remaining
```

### Troubleshooting auto-detection failures

If you run a command that uses auto-detection, and the auto-detection doesn't succeed, you'll see an error message like this:

```console
FATA[0000] error during command execution: distro repo dir and/or advisories repo dir was left unspecified, and distro auto-detection failed: current directory is not a distro or advisories repository 
```

If you encounter this, please do the following and then try again:

1. Make sure you **don't** have the environment variables `WOLFICTL_DISTRO_REPO_DIR` or `WOLFICTL_ADVISORIES_REPO_DIR` set. These variables used to help with distro detection in an earlier version of `wolfictl`, but these days they tend to just get in the way.

2. Make sure your local clone of the distro repo (e.g. `wolfi-dev/os`) or the advisories repo (e.g. `wolfi-dev/advisories`) has a **git remote** configured for the upstream repo.

For example, if you run `git remote -v` from the repo directory and see something like this:

```console
$ git remote -v
origin	git@github.com:luhring/wolfi-advisories.git (fetch)
origin	git@github.com:luhring/wolfi-advisories.git (push)
```

...then auto-detection will fail, because there's no reference to the upstream repo (which would look like `git@github.com:wolfi-dev/advisories.git` in this case).

## Not using auto-detection

You can also provide the path to the local distro or advisories directory explicitly to avoid the need for auto-detection.

For commands that need to know the directory path for the distro, you can use the flag `-d`/`--distro-repo-dir <path/to/dir>`.

For commands that need to know the directory path for the advisories data set, you can use the flag `-a`/`--advisories-repo-dir <path/to/dir>`.

### Forcing auto-detection off

To avoid any chance of implicit behavior, you can force off auto-detection (at the risk of the command failing due to lack of required context) using the flag `--no-distro-detection`.
