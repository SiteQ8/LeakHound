# Roadmap

These are directions for LeakHound, roughly in order. Nothing here is a promise,
and pull requests that move any of it forward are welcome.

## Near term

* A configuration file, so rules, excludes, and thresholds can live in the repo.
* A baseline mode that records current findings and then reports only new ones.
* More provider rules: Azure, GCP service accounts, Twilio, Datadog, and others.
* Verified mode that checks whether a found key is still live, opt in only.

## Later

* Per rule allow lists by fingerprint.
* Richer git history reporting that names the commit that introduced a secret.
* A summary that groups findings by rule and by author.
* Optional parallel scanning for very large repositories.

## Out of scope for now

* Hosting or a web service. LeakHound is a local tool by design.
* Automatic remediation. It reports, and a human decides what to do.

Have an idea that is not here? Open an issue and start the conversation.
