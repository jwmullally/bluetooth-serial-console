#!/usr/bin/env python3
'''
Simple Bluetooth Serial Port Profile client.
'''
__author__ = 'Joe Mullally'
__contact__ = 'https://github.com/jwmullally/bluetooth-serial-console'
__license__ = 'MIT'
__version__ = '1.0'
__date__ = '2021'


import argparse
import logging
import select
import socket
import sys


def main(args: argparse.Namespace):
	logger = logging.getLogger('main')
	logger.info('Starting Bluetooth Serial Console.')
	logger.info(f'Arguments: {args}')

	client = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
	client.connect((args.address, args.port))
	logger.info(f'Connected.')
	connections = [client, sys.stdin]

	while True:
		readable, _, _ = select.select(connections, [], [])
		for con in readable:
			if con == client:
				message = client.recv(4096)
				sys.stdout.write(message.decode('iso-8859-1'))
				sys.stdout.flush()
			elif con == sys.stdin:
				message = sys.stdin.readline()
				client.sendall(message.encode('iso-8859-1'))


def parse_args(argv: list[str]) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--address', required=True,
		help='Address of the Bluetooth device to connect to.')
	parser.add_argument('--port', type=int, required=True,
		help='SPP port number')
	parser.add_argument('--verbose', dest='loglevel', action='store_const', const=logging.DEBUG, default=logging.ERROR)
	parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
	args = parser.parse_args(argv[1:])
	return args


def cli():
	args = parse_args(sys.argv)
	logging.basicConfig(level=args.loglevel, format='%(levelname)s %(name)s: %(message)s')
	main(args)


if __name__ == '__main__':
	cli()