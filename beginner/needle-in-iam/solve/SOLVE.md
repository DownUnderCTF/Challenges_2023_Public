The user is trying to access the descripition of a single role. Typically you would do this with a DESCRIBE API, and that's exactly what they have tried. Unfortunately, they lack permissions to do this and hence are unable to view the descripition.

```bash
gcloud iam roles describe ComputeOperator --project=<PROJECT>
```

However, DESCRIBE isn't the only API which returns this information. There is the LIST API which will return details of a range of roles, including their descriptions in a list form. The difference here is that LIST returns less information about each role but shows more, whilst DESCRIBE is very detailed about one particular role. Since the description is in both, for our purposes they can be used interchangably.

To speed things up, we can also include a filter for the description so we only get the one relevant result.

```bash
gcloud iam roles list --project=<PROJECT> --filter="description:DUCTF"
```

This is not a security flaw with the cloud provider, but an intentional design choice developers on this platform must be aware of.