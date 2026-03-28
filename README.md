# password-reminder

```sh
uv run password-reminder add google
# Calibrating Argon2 parameters (this runs only once)…
# Calibrated: memory=524288 MiB, parallelism=8
# Password:
# Repeat for confirmation:
# Hashing… (this takes about a second)
# Stored 'google'.

uv run password-reminder add github
# Password:
# Repeat for confirmation:
# Hashing… (this takes about a second)
# Stored 'github'.

uv run password-reminder list
# Stored services (2):
#   github
#   google

uv run password-reminder ask
# [1/2] Testing: google
# Password:
#   correct
#
# [2/2] Testing: github
# Password:
#   WRONG
#
# Result: 1/2 correct

uv run password-reminder delete google
# Delete 'google'? [y/N]: y
# Deleted 'google'.
```
