#!/usr/bin/env python3
'''
System login console for Bluetooth Serial Port Profile connections.

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
'''
__author__ = 'Joe Mullally'
__email__ = 'jwmullally@gmail.com'
__contact__ = 'https://github.com/jwmullally/bluetooth-serial-console'
__license__ = 'MIT'
__version__ = '1.0'
__date__ = '2021'


import argparse
import logging
import os
import signal
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


class SerialProfile(dbus.service.Object):
	def __init__(self, *args, **kwargs):
		self.cmdline: list[str] = kwargs.pop('cmdline')
		self.mainloop: GLib.MainLoop = kwargs.pop('glib_mainloop')
		self.processes: tuple[str, subprocess.Popen, int] = []
		self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
		super().__init__(*args, **kwargs)
	
	def reap_processes(self, close_all: bool = False):
		self.logger.info('Called reap')
		running = []
		for address, process, con_fd in self.processes:
			if close_all:
				original_handler = signal.getsignal(signal.SIGCHLD)
				signal.signal(signal.SIGCHLD, signal.SIG_IGN)
				process.kill()
				signal.signal(signal.SIGCHLD, original_handler)
			if process.poll() != None:
				os.close(con_fd)
				self.logger.info(f'{address}: Process PID {process.pid} finished with returncode {process.returncode}. Bluetooth connection fd {con_fd} closed')
			else:
				running.append((address, process, con_fd))
		self.processes = running
		return True

	@dbus.service.method('org.bluez.Profile1', in_signature='', out_signature='')
	def Release(self):
		self.logger.info(f'Release()')
		self.reap_processes(close_all=True)
		self._mainloop.quit()

	@dbus.service.method('org.bluez.Profile1', in_signature='oha{sv}', out_signature='')
	def NewConnection(self, device: str, fd: dbus.types.UnixFd, fd_properties: dbus.types.Dictionary):
		self.logger.info(f'NewConnection("{device}", {fd}, {fd_properties})')
		props = dbus.Interface(self.connection.get_object('org.bluez', device), 'org.freedesktop.DBus.Properties')
		address = str(props.Get("org.bluez.Device1", "Address"))
		con_fd = fd.take()
		self.logger.info(f'{address}: Starting command {self.cmdline} with Bluetooth connection fd {con_fd}')
		try:
			process = subprocess.Popen(self.cmdline, stdin=con_fd, stdout=con_fd, stderr=con_fd)
		except:
			self.logger.exception('Error starting command')
		self.processes.append((address, process, con_fd))
		self.logger.info(f'{address}: Command started, PID: {process.pid}')

	@dbus.service.method('org.bluez.Profile1', in_signature='o', out_signature='')
	def RequestDisconnection(self, device: str):
		self.logger.info('RequestDisconnection(%s)' % device)


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
	logger.info('Starting Bluetooth Serial Console.')
	logger.info(f'Arguments: {args}')

	dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
	mainloop = GLib.MainLoop()
	bus = dbus.SystemBus()

	profiles = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.ProfileManager1')
	agents = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.AgentManager1')

	bluez_objects = dbus.Interface(bus.get_object('org.bluez', '/'), 'org.freedesktop.DBus.ObjectManager').GetManagedObjects()
	adapter_paths = [path for path, values in bluez_objects.items() if dbus.String('org.bluez.Adapter1') in values]
	adapters = [dbus.Interface(bus.get_object('org.bluez', path), 'org.freedesktop.DBus.Properties') for path in adapter_paths]
	logger.info(f'Found Bluetooth adapters: {[str(adapter.object_path) for adapter in adapters]}')

	try:
		profile = SerialProfile(bus, '/bluetooth_serial_console/SerialProfile', glib_mainloop=mainloop, cmdline=args.cmd)
		signal.signal(signal.SIGCHLD, lambda signum, frame: profile.reap_processes())
		profiles.RegisterProfile(profile._object_path, '00001101-0000-1000-8000-00805f9b34fb', {
			'AutoConnect': True,
			'Role': 'server',
			'Channel': dbus.UInt16(1),
			'Name': 'SerialPort'
			})
		logger.info('SerialProfile registered')

		if args.discoverable:
			agent = PairingAgent(bus, '/bluetooth_serial_console/PairingAgent', glib_mainloop=mainloop, whitelist=args.whitelist, auth_command=args.auth_cmd)
			agents.RegisterAgent(agent._object_path, 'DisplayYesNo')
			agents.RequestDefaultAgent(agent._object_path)
			logger.info('Automatic PairingAgent registered')

			for adapter in adapters:
				adapter.Set('org.bluez.Adapter1', 'Discoverable', dbus.Boolean(1))
				adapter.Set('org.bluez.Adapter1', 'DiscoverableTimeout', dbus.UInt32(0))
				logger.info(f'{adapter.object_path}: Discoverable on')
		else:
			logger.info('Discoverability and automatic pairing off.')

		
		logger.info('Waiting for connections...')
		mainloop.run()
	except Exception as e:
		logger.exception(f'Exception: {e}')
	finally:
		logger.info('Cleaning up...')
		if args.discoverable:
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
		try:
			signal.signal(signal.SIGCHLD, signal.SIG_DFL)
			profile.reap_processes(close_all=True)
			profiles.UnregisterProfile(profile._object_path)
			logger.info('SerialProfile unregistered')
		except:
			logger.exception(f'Exception while unregistering SerialProfile')
		logger.info('Exiting Bluetooth Serial Console.')
	return


def parse_args(argv: list[str]) -> argparse.Namespace:
	class ArgFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
		pass

	parser = argparse.ArgumentParser(formatter_class=ArgFormatter, description=__doc__)

	if os.path.exists('/usr/bin/machinectl'):
		default_login_command = ['/usr/bin/machinectl', 'login']
	else:
		if os.getuid() != 0:
			raise PermissionError('Program must be run as root to allocate PTYs')
		default_login_command = ['/usr/sbin/runuser', '--login' , '--pty', '--shell', '/usr/sbin/agetty', '--command=-']

	parser.add_argument('cmd', nargs='*', default=default_login_command, type=str,
			help='Command to run on serial connection. The bluetooth connection will be connected to STDIN, STDOUT and STDERR of this process. If the command has arguments, prefix the command with " -- " to pass them through.')
	parser.add_argument('--discoverable', action='store_true', default=False,
			help='Enable discoverability and pairing. If this is left disabled, only previously paired devices will be able to connect.')
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