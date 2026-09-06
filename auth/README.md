# Background authentication services

After initializing and pairing the appropriate identity, install its user service explicitly:

```sh
chromesync auth service install --role executor
# On the separately paired daily driver:
chromesync auth service install --role approver
```

The executor and approver use separate service names from cookie synchronization. macOS uses login LaunchAgents `io.chromesync.auth.executor` and `io.chromesync.auth.approver`. Linux uses `chromesync-auth-executor.service` and `chromesync-auth-approver.service` under the user's systemd manager. These are user services; the installer does not enable Linux linger, install a system service, or configure OS login.

The executor must run on a trusted host outside the agent's OS and filesystem authority. Provider credentials stay in the existing authentication credential store. Service definitions contain only executable paths, the role, and the parent ChromeSync state directory. `CHROMESYNC_HOME` points to the parent of the authentication directory because the CLI appends `/authentication` itself. Both output streams are discarded; service definitions and logs contain no provider secrets.

The approver's loopback inbox trusts local clients, including shell processes. Running it under a different ordinary OS user or state directory does not by itself exclude local agents. Keep agent workloads outside its host loopback, Keychain, files and desktop authority, for example inside a suitably isolated VM. The local inbox must not be exposed through a public proxy.

Run `chromesync auth inbox` to locate the current local approval inbox through its private discovery record. The foreground commands `chromesync auth executor` and `chromesync auth approvals` also display their current inbox URL; stop the corresponding service before starting a foreground instance. A background service does not remove 1Password unlock or passkey presence/verification requirements, and the dedicated receiver may need a logged-in graphical desktop session.

Remove only the selected background service with:

```sh
chromesync auth service uninstall --role executor
chromesync auth service uninstall --role approver
```

Uninstallation stops/removes the service definition and preserves authentication state, enrollment, and the dedicated receiver profile. Nothing is installed merely by importing the service module or generating a definition. Tests use temporary home directories and a fake service-manager runner; they do not register real services.
