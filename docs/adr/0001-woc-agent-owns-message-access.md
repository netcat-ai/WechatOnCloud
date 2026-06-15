# WOC Agent owns message access

Message access is owned by the WOC Agent inside each WeChat Instance, while the Panel only authenticates users, checks instance permissions, selects the target instance, and forwards requests. This keeps Message Keys, message cursors, local message caches, and WeChat-local state scoped to the instance that owns them instead of turning the Panel into a cross-instance message runtime.

Message access requests through the Panel must explicitly name the target WeChat Instance. The Panel must not infer a default instance, even when the caller can access only one instance, because Message Access acts on a real WeChat Session and an implicit target can send or read messages from the wrong session.

**Considered Options**

- Put message access in the Panel. This would simplify the first HTTP routes but would mix Docker lifecycle control with WeChat-local state and make the Panel a holder of sensitive per-instance message data.
- Put message access in the WOC Agent. This keeps the control plane and instance runtime separate, and lets the send implementation change without changing the external Panel API.
