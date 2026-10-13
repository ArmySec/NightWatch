# Detection Logic

## 1. Overview

NightWatch detects repeated SSH login failures from the same source IP address within a defined time window.

The current detection rule uses a threshold of three failed login attempts within five minutes.

## 2. Detection Criteria

An alert is generated when all the following conditions are met:

- The event type is `login_failure`.
- The events originate from the same source IP address.
- At least three failed login attempts occur within five minutes.

The current alert severity is `medium`.

## 3. Investigation Workflow

When an alert is generated, an analyst should:

1. Review the source IP address and the number of failed attempts.
2. Examine the first and last timestamps of the detected activity.
3. Review the event timeline for relevant authentication activity.
4. Check for successful logins and other potentially related events.
5. Correlate the findings with additional logs before drawing conclusions.

## 4. Interpreting the Alert

Repeated login failures may indicate:

- A user entering an incorrect password.
- An automated authentication attempt.
- Possible brute-force activity.

The alert alone does not prove that an account was compromised.

Analysts should investigate the surrounding context before deciding whether the activity is malicious.

## 5. Current Limitations

- The project currently uses synthetic training data.
- Detection is limited to the event fields and conditions implemented in the Python engine.
- Events from different source IP addresses are not automatically treated as related.
- The current rule does not independently establish whether a login attempt was malicious.
- The Sigma rule documents the base event selection, while the Python engine applies the three-attempt threshold within five minutes.

## 6. Future Improvements

Potential improvements include:

- Detecting successful logins following repeated failures.
- Supporting configurable detection thresholds.
- Adding unit tests for edge cases and malformed events.
- Enriching alerts with additional investigation context.
- Supporting more authentication log formats.
