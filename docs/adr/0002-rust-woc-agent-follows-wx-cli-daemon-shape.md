# Rust WOC Agent follows wx-cli's daemon shape

The WOC Agent is implemented as a Rust single-binary daemon inside each WeChat Instance, following wx-cli's shape of a long-lived local service that owns key state, cache state, and message queries close to the WeChat data. Rust matches the upstream reference direction and keeps the runtime footprint small in the instance image, while the Panel remains a thin authorization proxy.

For local message reads the agent uses bundled `wx-cli` first. Instance containers need `SYS_PTRACE` plus `seccomp=unconfined` so wx-cli can inspect the WeChat process. The agent is started by a root `cont-init` hook, with the Panel also able to restart it as root on demand; it is not started from the desktop `autostart` script because that runs as the app user. `wx init` is only accepted as successful when `all_keys.json` contains at least one extracted key; an empty `{}` is treated as init failure because polling cannot decrypt message DBs.

Text send is not provided by wx-cli. The first implementation uses local desktop automation inside the WeChat Instance and reports only that the send action was accepted.

**Considered Options**

- Use Python for the agent. This is quick to prototype but adds a scripting runtime to the instance image and diverges from wx-cli's daemon/cache model.
- Use Rust for the agent. This keeps a single deployable binary, aligns with wx-cli's implementation style, and gives a stronger base for later SQLCipher cache and memory-scanner work.
