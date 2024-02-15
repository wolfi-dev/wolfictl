# Advisory Guide Flow

This document outlines the flow of the `wolfictl adv guide` command.

Yellow diamonds are decisions for the **user**.

Green diamonds are decisions for the **program**.

```mermaid
flowchart TD
    start["Run `wolfictl adv guide`"] --> selectBuild{Select a package build}

    selectBuild --> scan[Scan origin and any subpackages]

    scan --> anyUnaddressedFindings{Any unaddressed vulnerabilities found?}

    anyUnaddressedFindings -- No --> advisoryPRNeeded{"Does the local advisory data need to be merged?"}

    advisoryPRNeeded -- No --> done[All done!]

    advisoryPRNeeded -- Yes --> openPR[Offer to open a PR on behalf of the user]

    anyUnaddressedFindings -- Yes --> selectFinding{Select a vulnerability finding to resolve}

    selectFinding --> hasTriageRecommendation{"Is a triaging recommendation available immediately?\n(see [Triaging recommendations])"}

    hasTriageRecommendation -- Yes --> triageRecommendationPrompt{Does this recommendation look right?}

    hasTriageRecommendation -- No --> beginManualTriaging[Begin user questioning]

    triageRecommendationPrompt -- No --> beginManualTriaging

    triageRecommendationPrompt -- Yes --> persistTriageResponse[Save the triage response to local advisory data]

    persistTriageResponse --> anyUnaddressedFindings

    beginManualTriaging --> fpIndication{"Any obvious indication of false positive?\n(w/ docs link)"}

    fpIndication -- Yes --> fpType{"Why is this a false positive?\n(See [FP reasons])"}

    fpType --> fpReasonCriteriaMet{FP reason criteria met?}

    fpReasonCriteriaMet -- No --> fpIndication

    fpReasonCriteriaMet -- Yes --> persistTriageResponse

    fpIndication -- No --> notSupportedIndication{"Is this package unsupported?\n(w/ docs link)"}

    notSupportedIndication -- Yes --> persistTriageResponse

    notSupportedIndication -- No --> fixAttempted{"Have you tried to fix the vulnerability yet?"}

    fixAttempted -- "No, I need help" --> ecosystemSpecificGuidance

    fixAttempted -- "Yes, please do the scan over again" --> scan

    fixAttempted -- "Yes, but I don't think fixing this is possible" --> nontrivialFixType{"What's the problem you're facing?"}

    classDef userDecision fill:#9c7514,stroke:#333,stroke-width:2px
    class selectBuild,selectFinding,triageRecommendationPrompt,fpIndication,fpType,fixAttempted,nontrivialFixType userDecision

    classDef programDecision fill:#278019,stroke:#333,stroke-width:2px
    class advisoryPRNeeded,anyUnaddressedFindings,hasTriageRecommendation,fpReasonCriteriaMet,notSupportedIndication programDecision
```

## Triaging recommendations

We could identify cases where the user shouldn't have to make any decisions, such as:

1. The fix required is not allowed by the package's version stream constraints --> `fix-not-planned` with auto-generated `note`.
1. The NVD record is marked "disputed" --> `false-positive-determination` with auto-generated `note`.
1. Govulncheck triaging confirms a false positive
1. etc...


## FP reasons

- The maintainers of the component disagree that this is a security problem.
    - Criteria: a web link for evidence
- This vulnerability is specific to another distro and not ours.
    - Don't offer FP reason if: no distro name found in CVE description
    - Criteria: select distro name that appears in the CVE description; otherwise don't allow this FP reason
- This vulnerability has already been fixed upstream.
    - Don't offer FP reason if: version range intact in vuln record
    - Criteria: a reference to a version or commit upstream for where the fix was introduced

## Nontrivial fix types

- A step of the Melange pipeline is failing
    - Criteria:
        - specify which exact step in the local package configuration file
        - provide a relevant excerpt of the error message
- A step I inserted or modified isn't having the effect I expected on the scanner results
    - Criteria: ?
