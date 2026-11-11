# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on the repository
page open **Security → Report a vulnerability**. Do not open a public issue
or pull request for them.

Include the version (`kubectl capybara version`, the agent image tag), what
an attacker needs (network access to a node, a pod in the cluster, RBAC
permissions) and what they gain. You will get an answer as soon as the report
has been looked at; fixes are released as a new version and credited to the
reporter unless you prefer otherwise.

Only the latest release is supported with security fixes.

## What to know before deploying

The agent is a **privileged** DaemonSet with `hostPID` and (by default)
`hostNetwork`: it loads eBPF programs and reads `/proc` and the cgroup
filesystem of the node. Treat its image and its namespace like any other node
level component.

* **Agent API.** `/v1/*` returns process command lines, DNS names, peer
  addresses and, with `--l7`, request lines and normalized SQL statements. It
  requires the token of the `capybara-agent-token` Secret in the
  `X-Capybara-Token` header; the Helm chart generates it. Without a token the
  API is open to anyone who can reach the port, and with `hostNetwork` that
  port is open on every node. `/healthz` and `/metrics` are always open.
* **Who can read the data.** `kubectl capybara` reads the token with the
  caller's own RBAC and reaches the agents through the API server proxy, so
  access is granted by `get` on that Secret plus `pods/proxy` (or
  `services/proxy` for the hub) in the agent namespace. The data is cluster
  wide: someone allowed to query the agents sees every namespace.
* **Secrets in command lines.** Values of arguments that look like secrets
  (`--password=…`, `TOKEN=…`, `--api-key …`) are masked before they are
  stored. This is a heuristic: a secret passed under an unusual name is
  recorded as is.
* **Metrics.** `/metrics` carries HTTP paths, statement shapes and file
  paths as label values (IDs in paths and literals in SQL are replaced), and
  is not authenticated.
* **Profiling.** `/v1/profile` and `/v1/counters` run perf events on the
  node for up to two minutes per request; they are behind the same token.
* **State on disk.** With `persistence.enabled` the agent keeps its history
  and crash reports in `/var/lib/capybara` on the node, in a file only root
  can read.
* **Hub and controller** run unprivileged with a read-only root filesystem.
  The hub answers with the same token and can read cluster metadata; the
  controller can create, update and delete `CapyFinding` objects in every
  namespace and sends finding titles and details to the configured webhooks.

The eBPF programs only observe: the cgroup skb programs always allow the
packet and no program modifies data.
