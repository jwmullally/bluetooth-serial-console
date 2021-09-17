## Description

This repository provides a Bluetooth Serial Port Profile console compatible with BlueZ >= 5.x. It also provides a headless automatic Bluetooth pairing agent. Together, these enable Bluetooth serial console access to a system without keyboard or display. If you don't want to leave access open, you can do `systemctl disable bluetooth-automatic-pairing` to disable discoverability and new pairings, and existing pairings will continue to have access to the serial console. You can also supply address whitelists or an authorization program to only allow certain connections through.


## Commands

### bluetooth-serial-console

System login console for Bluetooth Serial Port Profile connections.

Works with BlueZ >= 5.x over DBUS, with BlueZ's default settings. No bluetoothd
--compat, hciconfig, sdptool or rfcomm needed. Those were needed for earlier
BlueZ <= 4.x.

Incoming Serial Port connections are connected directly to a login process. When
the connection is broken from the client, the host-side login process is closed.
(Use screen or tmux to preserve sessions). Any other program can be used
instead of a terminal login.

This script normally requires root to run to control Bluetooth and create PTYs
for login. If systemd machinectl is present and the user has permissions to
control Bluetooth (i.e. during a desktop session), the script can be run as
non-root.

    usage: bluetooth-serial-console.py [-h] [--verbose] [--version] [cmd ...]

    positional arguments:
      cmd                   Command to run on serial connection. The bluetooth
                            connection will be connected to STDIN, STDOUT and
                            STDERR of this process. If the command has arguments,
                            prefix the command with " -- " to pass them through.
                            (default: ['/usr/bin/machinectl', 'login'])

    optional arguments:
      -h, --help            show this help message and exit
      --verbose
      --version             show program's version number and exit


### bluetooth-automatic-pairing

Bluetooth Automatic Pairing Agent.

Works with BlueZ >= 5.x over DBUS, with BlueZ's default settings.

This script turns on Bluetooth discoverability (required for SSP pairing) and
automatically processes incoming pairing requests. This enables headless
bluetooth pairing for hosts without input or display.

By default, all authorization requests are accepted. Optionally, an address
whitelist can be used, or an external authorization program can be called. When
allowing all incoming connections, care should be taken that the available
Bluetooth services either provide extra authentication (e.g. a login shell) or
do not expose sensitive information.

With Bluetooth SSP (enabled by default in BlueZ >= 5) random PINs are used, and
it is not possible to have a fixed PIN on the agent side for use as a password.
The generated pin is logged for validation purposes.

    usage: bluetooth-automatic-pairing.py [-h] [--whitelist WHITELIST]
                                          [--auth-cmd AUTH_CMD] [--verbose]
                                          [--version]

    optional arguments:
      -h, --help            show this help message and exit
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


## Requirements

* BlueZ >= 5.x
* dbus-python
* Python 3


## Installing

To install these scripts and systemd services to automatically start them on
boot, do the following:

    make install
    systemctl enable bluetooth-automatic-pairing
    systemctl enable bluetooth-serial-console


## Contact

Copyright (C) 2021 Joseph Mullally

License: MIT

Project: <https://github.com/jwmullally/bluetooth-serial-console>