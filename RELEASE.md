# Release Process

This document describes how to cut a release for `wolfictl` using the automated GitHub Actions workflow.

## Overview

The `wolfictl` project uses an automated release process that:

- Automatically creates weekly patch releases every Monday at 00:00 UTC
- Allows manual releases to be triggered on-demand via GitHub Actions
- Uses GoReleaser to build and publish releases
- Follows semantic versioning (SemVer) for version management
- Only creates a new release if there are changes since the last tag

## Automated Weekly Releases

The workflow automatically runs every Monday at 00:00 UTC to create patch releases. This ensures regular releases for packaging in Wolfi itself.

## Manual Release Process

### Prerequisites

1. **Permissions**: You need `write` access to the repository to trigger manual releases
2. **Changes**: Ensure there are commits since the last release (the workflow will skip if no changes exist)

### How to Cut a Manual Release

1. **Navigate to GitHub Actions**
   - Go to the [Actions tab](https://github.com/wolfi-dev/wolfictl/actions) in the repository
   - Find the "release" workflow

2. **Trigger the Workflow**
   - Click "Run workflow" on the right side
   - Configure the release parameters (see options below)
   - Click "Run workflow" to start the process

### Release Configuration Options

When manually triggering a release, you can configure the following parameters:

#### `dry_run` (boolean, default: false)
- **Purpose**: Test the release process without actually creating a release
- **When to use**: When you want to validate the release process or test changes
- **Effect**: If `true`, no git tags will be pushed and no release will be published

#### `release_type` (required, default: patch)
- **Purpose**: Determines how the version number is incremented
- **Options**:
  - `major`: For breaking changes (e.g., 1.2.3 → 2.0.0)
  - `minor`: For new features that are backward compatible (e.g., 1.2.3 → 1.3.0)
  - `patch`: For bug fixes and small improvements (e.g., 1.2.3 → 1.2.4)
  - `prerelease`: For pre-release versions (e.g., 1.2.3 → 1.2.4-alpha.1)

#### `forced_version` (optional)
- **Purpose**: Override automatic version bumping with a specific version
- **Format**: Must be SemVer2-compliant (e.g., "1.5.0", "2.0.0-beta.1")
- **Constraints**: The version must not already exist as a tag
- **When to use**: When you need to release a specific version number
