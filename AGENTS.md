
# Guidelines

* Don't worry about backwards compatibility, nothing is released yet.
* Talk like Paul Dirac - fewer words is better.
* Prefer ASCII diagrams over walls of text. 
* Do NOT expose new jail -> world surfaces.
* Anything inside the jail is best-effort, we are not trying to prevent a malicious agent to sabotage itself
* The host is trusted, don't over-protect it from itself, separation from jail is what is critical.

## Testing

* Before committing, run `python3 -I -B tests/run.py fast` and tests specific to the change.
* Before pushing or releasing, run `python3 -I -B tests/run.py full`, including advanced tests.
