# Rust WOC Agent follows wx-cli's daemon shape

The WOC Agent is implemented as a Rust single-binary daemon inside each WeChat Instance, following wx-cli's shape of a long-lived local service that owns key state, cache state, and message queries close to the WeChat data. Rust matches the upstream reference direction and keeps the runtime footprint small in the instance image, while the Panel remains a thin authorization proxy.

For local message reads the agent embeds the wx-cli-derived scanner, SQLCipher page decrypt, WAL replay, cache, and new-message query flow instead of shelling out to a bundled `wx` binary. Instance containers still need `SYS_PTRACE` plus `seccomp=unconfined` so the agent can inspect the WeChat process during `/agent/init`. Init is only accepted as successful when at least one DB key is extracted; the explicit DB-to-key mapping is persisted under the Instance Data Volume and reused on later starts.

Text send is not provided by wx-cli. The first implementation requires callers to pass the stable internal conversation id returned by polling, resolves that id exactly through the local contact database, then uses local desktop automation inside the WeChat Instance and reports only that the send action was accepted.

**Considered Options**

- Use Python for the agent. This is quick to prototype but adds a scripting runtime to the instance image and diverges from wx-cli's daemon/cache model.
- Use Rust for the agent. This keeps a single deployable binary, aligns with wx-cli's implementation style, and lets WOC own SQLCipher cache, cursor semantics, and memory-scanner behavior directly.
