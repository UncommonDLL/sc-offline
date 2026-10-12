# Linux / Wine

Modified play/install are disabled until sc-offline supports a verified host isolation adapter. The Windows firewall APIs emulated by Wine and an EAC download-host entry do not provide the required contract.

`sc-offline.sh status`, `help`, and `update` remain available where Wine supports the launcher. The wrapper rejects play/install and native-policy restoration. Recover an existing managed Windows transaction through its native Windows launcher and preserved recovery store. Do not remove blocking rules or journals to clear unknown state.

See [launcher isolation and recovery](launcher.md) for configuration, legacy conflicts, and validation limits.
