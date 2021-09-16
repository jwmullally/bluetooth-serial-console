# bluetooth-serial-console

System login console for Bluetooth Serial Port Profile connections.

## Description

Works with BlueZ >= 5.x over DBUS, with BlueZ's default settings. No bluetoothd
--compat, hciconfig, sdptool or rfcomm needed. Those were needed for earlier
BlueZ <= 4.x.

Pairing occurs with headless Bluetooth SSP authentication. To allow open
connections from any device, "--discoverable" must be set. If you have already
paired your chosen devices and don't want to allow new connections from other
unknown devices, you can restart without this flag.

With Bluetooth SSP (enabled by default in BlueZ >= 5) random PINs are used, and
it is not possible to have a fixed PIN on the agent side for use as a password,
however the login shell should provide secure authentication.

Incoming Serial Port connections are connected directly to a login process. When
the connection is broken from the client, the host-side login process is closed.
(Use screen or tmux to preserve sessions). Any other programs can be used
inplace of a terminal login.

This script normally requires root to run to control Bluetooth and create PTYs
for login. If systemd machinectl is present and the user has permissions to
control Bluetooth (i.e. during a desktop session), the script can be run as
non-root.


## Requirements

* BlueZ >= 5.x
* dbus-python
* Python 3


## Usage

    usage: bluetooth-serial-console.py [-h] [--discoverable]
                                      [--whitelist WHITELIST]
                                      [--auth-cmd AUTH_CMD] [--verbose]
                                      [--version]
                                      [cmd ...]

    positional arguments:
      cmd                   Command to run on serial connection. The bluetooth
                            connection will be connected to STDIN, STDOUT and
                            STDERR of this process. If the command has arguments,
                            prefix the command with " -- " to pass them through.
                            (default: ['/usr/bin/machinectl', 'login'])

    optional arguments:
      -h, --help            show this help message and exit
      --discoverable        Enable discoverability and pairing. If this is left
                            disabled, only previously paired devices will be able
                            to connect. (default: False)
      --whitelist WHITELIST
                            Optional Bluetooth Address whitelist. Comma seperated.
                            If no whitelist is specified, allow connections from
                            any address. Note, previously paired addresses will
                            still be able to reconnect. E.g.
                            "AA:BB:CC:11:22:33,DD:EE:FF:44:55:66" (default: None)
      --auth-cmd AUTH_CMD   Optional command to authorize pairing requests. Will
                            be invoked like: "$AUTH-CMD ADDRESS [pin]". Return 0
                            for success, non-zero for fail. (default: None)
      --verbose
      --version             show program's version number and exit


## Installing

To install this script and a systemd service unit to automatically start it on
boot, do the following:

    make install
    systemctl enable bluetooth-serial-console


## Contact

Copyright (C) 2021 Joseph Mullally

License: MIT

Project: <https://github.com/jwmullally/bluetooth-serial-console>