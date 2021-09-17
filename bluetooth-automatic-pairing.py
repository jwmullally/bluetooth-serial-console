#!/usr/bin/env python3
'''
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
'''
__author__ = 'Joe Mullally'
__contact__ = 'https://github.com/jwmullally/bluetooth-serial-console'
__license__ = 'MIT'
__version__ = '1.0'
__date__ = '2021'


import argparse
import logging
import os
import sys
import subprocess
from typing import Optional

import dbus
import dbus.types
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib


class Rejected(dbus.DBusException):
	_dbus_error_name = 'org.bluez.Error.Rejected'


class PairingAgent(dbus.service.Object):
	def __init__(self, *args, **kwargs):
		self.mainloop: GLib.MainLoop = kwargs.pop('glib_mainloop')
		self.whitelist: list[str] = kwargs.pop('whitelist', None)
		self.auth_command: str = kwargs.pop('auth_command', None)
		self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
		super().__init__(*args, **kwargs)

	def trust_device(self, device_path, pin: Optional[str] = None):
		props = dbus.Interface(self.connection.get_object('org.bluez', device_path), 'org.freedesktop.DBus.Properties')
		address = str(props.Get("org.bluez.Device1", "Address"))

		if self.whitelist or self.auth_command:
			trusted = False

			if self.whitelist:
				if address in self.whitelist:
					self.logger.info(f'{address}: In whitelist')
					trusted = True
				else:
					self.logger.info(f'{address}: Not in whitelist')

			if self.auth_command and not trusted:
				auth_cmd = [self.auth_command, address]
				if pin:
					auth_cmd.append(pin)
				self.logger.info(f'{address}: Calling auth-cmd: {auth_cmd}')
				auth_result = subprocess.run(auth_cmd, capture_output=True)
				self.logger.info(f'{address}: auth-cmd returncode: {auth_result.returncode}, stdout: {auth_result.stdout}, stderr: {auth_result.stderr}')
				if auth_result.returncode == 0:
					trusted = True
					self.logger.info(f'{address}: Authorized by auth-cmd')
				else:
					self.logger.info(f'{address}: Rejected by auth-cmd')

			if not trusted:
				raise Rejected(f'{address}: Not authorized to connect')

		props.Set('org.bluez.Device1', 'Trusted', True)
		self.logger.info(f'{address}: Trusted. Name="{props.Get("org.bluez.Device1", "Name")}"')

	@dbus.service.method('org.bluez.Agent1', in_signature='', out_signature='')
	def Release(self):
		self.logger.info('Release()')
		self.mainloop.quit()

	@dbus.service.method('org.bluez.Agent1', in_signature='os', out_signature='')
	def DisplayPinCode(self, device: str, pincode: str):
		self.logger.info(f'DisplayPinCode("{device}", "{pincode}")')
		self.trust_device(device, pin=pincode)

	@dbus.service.method('org.bluez.Agent1', in_signature='ou', out_signature='')
	def RequestConfirmation(self, device: str, passkey: int):
		self.logger.info(f'RequestConfirmation("{device}", {passkey})')
		self.trust_device(device, pin=str(passkey))

	@dbus.service.method('org.bluez.Agent1', in_signature='o', out_signature='')
	def RequestAuthorization(self, device: str):
		self.logger.info(f'RequestAuthorization("{device}")')
		self.trust_device(device)


def main(args: argparse.Namespace):
	logger = logging.getLogger('main')
	logger.info('Starting Bluetooth Automatic Pairing Agent.')
	logger.info(f'Arguments: {args}')

	dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
	mainloop = GLib.MainLoop()
	bus = dbus.SystemBus()

	agents = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.AgentManager1')

	bluez_objects = dbus.Interface(bus.get_object('org.bluez', '/'), 'org.freedesktop.DBus.ObjectManager').GetManagedObjects()
	adapter_paths = [path for path, values in bluez_objects.items() if dbus.String('org.bluez.Adapter1') in values]
	adapters = [dbus.Interface(bus.get_object('org.bluez', path), 'org.freedesktop.DBus.Properties') for path in adapter_paths]
	logger.info(f'Found Bluetooth adapters: {[str(adapter.object_path) for adapter in adapters]}')

	try:
		agent = PairingAgent(bus, '/bluetooth_automatic_pairing/PairingAgent', glib_mainloop=mainloop, whitelist=args.whitelist, auth_command=args.auth_cmd)
		agents.RegisterAgent(agent._object_path, 'DisplayYesNo')
		agents.RequestDefaultAgent(agent._object_path)
		logger.info('PairingAgent registered')

		for adapter in adapters:
			adapter.Set('org.bluez.Adapter1', 'Discoverable', dbus.Boolean(1))
			adapter.Set('org.bluez.Adapter1', 'DiscoverableTimeout', dbus.UInt32(0))
			logger.info(f'{adapter.object_path}: Discoverable on')

		mainloop.run()
	except Exception as e:
		logger.exception(f'Exception: {e}')
	finally:
		logger.info('Cleaning up...')
		for adapter in adapters:
			try:
				adapter.Set('org.bluez.Adapter1', 'Discoverable', dbus.Boolean(0))
				adapter.Set('org.bluez.Adapter1', 'DiscoverableTimeout', dbus.UInt32(180))
				logger.info(f'{adapter.object_path}: Discoverable off')
			except:
				logger.exception(f'Exception while disabling Discoverable')
		try:
			agents.UnregisterAgent(agent._object_path)
			logger.info('PairingAgent unregistered')
		except:
			logger.exception(f'Exception while unregistering PairingAgent')
		logger.info('Exiting Bluetooth Automatic Pairing Agent.')
	return


def parse_args(argv: list[str]) -> argparse.Namespace:
	class ArgFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
		pass

	parser = argparse.ArgumentParser(formatter_class=ArgFormatter, description=__doc__)
	parser.add_argument('--whitelist', default=os.environ.get('BLUETOOTH_SERIAL_CONSOLE_WHITELIST'),
			help='Optional Bluetooth Address whitelist. Comma seperated. If no whitelist is specified, allow connections from any address. Note, previously paired addresses will still be able to reconnect. E.g. "AA:BB:CC:11:22:33,DD:EE:FF:44:55:66"')
	parser.add_argument('--auth-cmd',
			help='Optional command to authorize pairing requests. Will be invoked like: "$AUTH-CMD ADDRESS [pin]". Return 0 for success, non-zero for fail.')
	parser.add_argument('--verbose', dest='loglevel', action='store_const', const=logging.DEBUG, default=logging.INFO)
	parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
	args = parser.parse_args(argv[1:])

	if args.whitelist:
		args.whitelist = args.whitelist.split(',')

	return args


def cli():
	args = parse_args(sys.argv)
	logging.basicConfig(level=args.loglevel, format='%(levelname)s %(name)s: %(message)s')
	main(args)


if __name__ == '__main__':
	cli()