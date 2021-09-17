#!/usr/bin/env python3
'''
System login console for Bluetooth Serial Port Profile connections.

Works with BlueZ >= 5.x over DBUS, with BlueZ's default settings. No bluetoothd
--compat, hciconfig, sdptool or rfcomm needed. Those were needed for earlier
BlueZ <= 4.x, and most are now deprecated.

Incoming Serial Port connections are connected directly to a login process. When
the connection is broken from the client, the host-side login process is closed.
(Use screen or tmux to preserve sessions). Any other program can be used
instead of a terminal login.

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

import dbus
import dbus.types
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib


class SerialProfile(dbus.service.Object):
	def __init__(self, *args, **kwargs):
		self.cmdline: list[str] = kwargs.pop('cmdline')
		self.mainloop: GLib.MainLoop = kwargs.pop('glib_mainloop')
		self.processes: tuple[str, subprocess.Popen, int] = []
		self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)
		super().__init__(*args, **kwargs)
	
	def reap_processes(self, close_all: bool = False):
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


def main(args: argparse.Namespace):
	logger = logging.getLogger('main')
	logger.info('Starting Bluetooth Serial Console.')
	logger.info(f'Arguments: {args}')

	dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
	mainloop = GLib.MainLoop()
	bus = dbus.SystemBus()
	profiles = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.ProfileManager1')

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
		logger.info('Waiting for connections...')
		mainloop.run()
	except Exception as e:
		logger.exception(f'Exception: {e}')
	finally:
		logger.info('Cleaning up...')
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
	if os.path.exists('/usr/bin/machinectl'):
		default_login_command = ['/usr/bin/machinectl', 'login']
	else:
		if os.getuid() != 0:
			raise PermissionError('Program must be run as root to allocate PTYs')
		default_login_command = ['/usr/sbin/runuser', '--login' , '--pty', '--shell', '/usr/sbin/agetty', '--command=-']

	class ArgFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
		pass

	parser = argparse.ArgumentParser(formatter_class=ArgFormatter, description=__doc__)
	parser.add_argument('cmd', nargs='*', default=default_login_command, type=str,
			help='Command to run on serial connection. The bluetooth connection will be connected to STDIN, STDOUT and STDERR of this process. If the command has arguments, prefix the command with " -- " to pass them through.')
	parser.add_argument('--verbose', dest='loglevel', action='store_const', const=logging.DEBUG, default=logging.INFO)
	parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
	args = parser.parse_args(argv[1:])

	return args


def cli():
	args = parse_args(sys.argv)
	logging.basicConfig(level=args.loglevel, format='%(levelname)s %(name)s: %(message)s')
	main(args)


if __name__ == '__main__':
	cli()