# WechatOnCloud

WechatOnCloud lets multiple browser users share and operate isolated WeChat desktop sessions that run on a NAS or server. Its language distinguishes the control plane that manages access from the per-instance WeChat runtime that owns a session and its local data.

## Language

**Panel**:
The external entry point for users. It owns user login, instance permissions, and lifecycle management for WeChat instances.
_Avoid_: Admin app, dashboard, frontend

**Panel User**:
A person who can log in to the Panel. A Panel User is not a WeChat account.
_Avoid_: WeChat user, account

**WeChat Instance**:
An isolated runtime for one WeChat desktop session. Each WeChat Instance has its own persisted data and can be shared by authorized Panel Users.
_Avoid_: Client, desktop, container

**WeChat Session**:
The logged-in WeChat identity and desktop state inside a WeChat Instance. Multiple Panel Users entering the same WeChat Instance share the same WeChat Session.
_Avoid_: Login, account

**Instance Data Volume**:
The persistent storage owned by one WeChat Instance. It contains the WeChat Session state, local message data, installed WeChat files, and instance-scoped WOC data.
_Avoid_: Data folder, config, disk

**WOC Agent**:
The instance-scoped service responsible for message access inside a WeChat Instance. It owns WeChat-local state that should not live in the Panel.
_Avoid_: Daemon, bot, worker

**Message Access**:
Programmatic reading and sending of WeChat messages for a WeChat Instance. It is separate from browser-based desktop operation of the same WeChat Session.
_Avoid_: Chat API, bot API

**Message Key**:
The secret that allows Message Access to read encrypted local WeChat message data for a WeChat Instance. It belongs to the WeChat Instance, follows the lifecycle of its Instance Data Volume, and must be treated as sensitive session data.
_Avoid_: Password, token, credential

**Message Cursor**:
An opaque position returned by Message Access after polling messages. Callers pass it back to continue from the last observed message position.
_Avoid_: Offset, checkpoint, sequence
