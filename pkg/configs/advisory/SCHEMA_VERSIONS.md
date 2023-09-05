# Advisory Document Schema Versions

The Chainguard advisory document schema is versioned. This article outlines the overall approach to schema versioning, explains how `wolfictl` handles schema versions, describes how to make changes to the schema, and keeps track of the history of schema versions.

## What's a "schema version"?

Schema versioning is loosely based on [SchemaVer](https://docs.snowplow.io/docs/pipeline-components-and-applications/iglu/common-architecture/schemaver/). So instead of `MAJOR.MINOR.PATCH`, we use `MODEL.REVISION.ADDITION`.

Trailing `0` values are omitted for brevity. For example: Instead of `2.0.0`, we just use `2`; and the next ADDITION would set the version to `2.0.1`; and the next REVISION after that would set the version to `2.1`.

There is currently no language-agnostic schema definition (e.g. using [JSONSchema](https://json-schema.org/)): there are only the Go types and their associated validation logic. We can introduce more schema tooling if it's valuable to users.

### The MODEL, REVISION, and ADDITION numbers

These three version segments communicate the nature of the change that was made to the schema from one version to the next.

For each new schema version, only a single version segment should be incremented. When multiple changes are made to the schema in a new version, prefer incrementing the MODEL number over the REVISION and ADDITION segments, and prefer incrementing the REVISION segment over the ADDITION segment.

#### Incrementing the MODEL number

Incrementing the MODEL number means that the schema has changed in a way that is not backwards-compatible. This means that any document written with the previous schema version is no longer valid under the new schema version.

This happens when:

- a new field is added to the schema, and it is required, and no default value can be assumed for existing data
- a field is removed from the schema (and unknown fields are not allowed)
- a field's type is changed
- new validation constraints are added to a field that could not have been satisfied before

#### Incrementing the REVISION number

Incrementing the REVISION number means that the schema has changed in a way that may break backwards-compatibility in some cases. This means that any document written with the previous schema version may or may not still be valid under the new schema version.

This happens when:

- an enum type has a value removed from it
- new validation constraints are added to a field that may have been satisfied before

#### Incrementing the ADDITION number

Incrementing the ADDITION number means that the schema has changed in a way that is guaranteed to be backwards-compatible. This means that any document written with the previous schema version is still valid under the new schema version.

This happens when:

- a field is added to the schema, and it is optional, or a default value can be used for existing data
- a field is removed from the schema (and unknown fields are allowed)
- an enum type has a new value added to it
- new validation constraints are added to a field that are known to have already been satisfied
- validation constraints are removed from a field

## How does `wolfictl` handle document schema versions?

Each release of `wolfictl` has **exactly one** builtin advisory schema version that it uses when writing to advisory documents. This version is inserted into the document as the `schema-version:` field value.

If `wolfictl` is updating an existing document, it will also set the document's schema version to the latest schema version value, since `wolfictl` may use any of the features available in the current schema during its writing.

`wolfictl` is **unable** to operate on a given advisory document when either:

1. the document's schema version is greater (i.e. newer) than `wolfictl`'s builtin advisory schema version, or
2. the document's schema version's _MODEL number_ is less than `wolfictl`'s builtin advisory schema version's MODEL number.

## How to make changes to the schema

As time goes on, and we learn more about what users need from the advisory document schema, we will need to make changes to the schema. This section describes how to make those changes correctly and safely.

### Figure out the changes associated with the new schema version

The first step is to understand what changes will be part of the new schema version. This may take some time as you're developing a new feature locally. Ultimately, you'll have made changes to the Go types and validation logic that comprise the schema itself, and it then becomes time to stamp this new state as its own schema iteration.

### Determine the new version number

Use the guidance on [The MODEL, REVISION, and ADDITION numbers](#the-model-revision-and-addition-numbers) to decide which of the three version segments will be incremented to create the new schema version number.

For example: If the latest schema version is "2", and you add a new optional field, and you add an enum value to an existing field, you would be making two changes that fall into the "ADDITION" category; so, the new schema version would be called "2.0.1".

### Finalize the code changes

Make sure the test coverage for your changes is as complete as possible.

Make sure the operations in the [advisory](../../advisory) package can operate on existing data as one would expect. Non-breaking/minor schema upgrades can be made as part of the advisory operation itself. Breaking changes should be given special consideration, and they are ideally given a purpose-built "migration" operation.

### Record the new version in the history

Log the new schema version in this document, at the top of the section [Version History](#version-history), so that versions are sorted "newest to oldest". Briefly describe the changes made as bullet points.

## Version History

`(vNext goes here)`
- (list what was changed)

`v2`
- The first officially versioned advisory document schema. ("v1" refers to the prior document format derived from OpenVEX, although these documents were never explicitly given a schema version.)
- Advisory documents now declare their schema version.
- Each document has a list of advisories.
- Each advisory has an ID, which for now is an existing vulnerability ID, preferably a CVE ID.
- Each advisory has a list of aliases.
- Each advisory has a list of events.
- Each event has a "type". These types are an extensible, enumerated set of values which describe the data shape of the rest of the event. These data shapes may further use their own sets of "types" to nest structured data hierarchically.