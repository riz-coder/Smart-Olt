"""Configure the tenant's private namespace, then run the app as its DB owner."""
import ipaddress
import os
import subprocess
import sys


def run(*args):
    subprocess.run(list(args), check=True)


def main():
    uid, gid = map(int, os.environ['OPTIVERSE_RUN_USER'].split(':'))
    address = ipaddress.ip_interface(os.environ['OPTIVERSE_VPN_ADDRESS'])
    routes = [ipaddress.ip_network(item) for item in os.environ['OPTIVERSE_VPN_ROUTES'].split(',') if item]
    run('ip', 'link', 'add', 'wg0', 'type', 'wireguard')
    run('wg', 'setconf', 'wg0', '/run/optiverse/wg0.conf')
    run('ip', 'address', 'add', str(address), 'dev', 'wg0')
    run('ip', 'link', 'set', 'wg0', 'mtu', '1420', 'up')
    for route in routes:
        run('ip', 'route', 'add', str(route), 'dev', 'wg0', 'src', str(address.ip))
    # Stop the application changing routes even if its existing DB is root-owned.
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if uid == 0:
        os.execvp('setpriv', ['setpriv', '--bounding-set=-all', '--inh-caps=-all',
                            '--ambient-caps=-all', '--no-new-privs', *sys.argv[1:]])
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()
