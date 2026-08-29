# Contributing to LeakHound

Thanks for helping. LeakHound aims to stay small, fast, and dependency free, so
contributions that keep it that way are the most welcome.

## Getting set up

```bash
git clone https://github.com/SiteQ8/LeakHound.git
cd LeakHound
python -m unittest discover -s tests -v
```

There is nothing to install. The whole project runs on the Python standard
library.

## Good first contributions

* Add a rule for a secret format that is not covered yet.
* Reduce a false positive you ran into, and add a test that proves it.
* Improve the wording of a finding or the help text.
* Expand the test suite.

## Adding a rule

Rules live in `leakhound/rules.py`. Each rule needs an id, a name, a severity,
a short description, and a compiled pattern. If your pattern captures the secret
in a group, set the group number. If the rule is heuristic rather than a precise
format, set a `min_entropy` so that only random looking matches are reported.

Please add a test in `tests/test_rules.py` that shows the rule catching a fake
secret, and, where it helps, a case that shows a safe value is not flagged. Use
fake values only. Never commit a real secret, even in a test.

## Before you open a pull request

1. Run the tests and make sure they pass.
2. Run `python -m leakhound scan .` and make sure the project is still clean.
3. Keep changes focused, and describe what you changed and why.

## Reporting a bug

Open an issue with the command you ran, what you expected, and what happened.
A small sample that reproduces the problem, using fake secrets, helps a lot.
