# Daemon
# ======
#
# The daemon is responsible for issuing commands to all other containers. As
# such, the daemon is essentially just running a bunch of docker exec's.
#
# The daemon is created before all other containers, so it starts to listen for
# container startup events in order to set up the following clients and routers.
#
# When a router starts up, the daemon will examine its labels and exec a network
# emulation command in the router based on those labels. The router takes care
# of configuring the network to fit our targets, and will run a speedtest to
# find the achieved conditions. The labels for the router will be updated to
# match the achieved conditions.
#
# When a container starts up, the daemon will examine its labels and exec
# commands to establish a vpn connection, run automated browsing, and collect
# network-stats. To properly name the network-stats output file with the current
# network conditions, a speed test is run prior to launching the behavior and
# running network-stats.
#
# After a little bit of time, the daemon will stop listening to docker startup
# events and start listening for an interrupt signal. When received, the daemon
# will teardown all clients and routers gracefully by interrupting all processes
# and waiting until the interrupts are complete before shutting down the
# containers. Then the daemon will exit itself.
#
# NOTE: Due to the way the self-timeout in implemented, any currently running
# functions seem to likewise get interrupted. Therefore it is advisable to set
# a very generous self-timeout in the function call within main.
#
# TODO: The setup for each router and client should be non-blocking.
#

import asyncio
import docker
import json
import time
import logging
import re
import signal
import sys

# Docker logs only show stdout of PID 1 -- so we'll write directly to that!
logger = logging.basicConfig(
    filename='/proc/1/fd/1', # stdout of PID 1 -- Docker logs only show this!
    filemode='a',
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
    level=logging.INFO
)

# Establish a global uncaught exception handler to log the exception
def log_exception(exc_type, exc_value, exc_traceback):
    logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_exception

def redirect_to_out(command):
    """
    Reformats a command for docker exec so that the command output is redirected
    to the stdout of PID 1 (in order to show up in the docker log).
    """
    return f'sh -c "{command} >> /proc/1/fd/1"'
    # return f'{command} >> /proc/1/fd/1'

PROJECT_NAME = 'dane'
LABEL_PREFIX = 'com.dane.'

# The DOCKER_HOST environment variable should already be defined
API = docker.from_env()

# We'll do the setup for each container as it is created. To do this, we'll
# listen for docker 'start' events, and use a callback.
def setup_lossem(lossem, router):
    
    logging.info(f'[+] Setting up lossem `{lossem.name}`')

    ## Networking configuration

    latency = lossem.labels.get(LABEL_PREFIX+'lossem.latency')
    loss = lossem.labels.get(LABEL_PREFIX+'lossem.loss')
    random = lossem.labels.get(LABEL_PREFIX+'lossem.random')
    later_latency = lossem.labels.get(LABEL_PREFIX+'lossem.later_latency')
    later_loss = lossem.labels.get(LABEL_PREFIX+'lossem.later_loss')

    service_name = lossem.labels['com.docker.compose.service']
    # Setup tun interface and activate lossem.py script
    exitcode, output = lossem.exec_run(
        ['/scripts/lossem/network-setup.sh', service_name, latency, loss, random, later_latency, later_loss]
    )

    if exitcode != 0:
        raise Exception(f'Network configuration failed for lossem `{lossem.name}`.\n{output}')

    # Set default route of lossem to router
    router_networks = set(router.attrs['NetworkSettings']['Networks'].keys())
    lossem_networks = set(lossem.attrs['NetworkSettings']['Networks'].keys())
    # Find the network that router and lossem have in common
    router_lossem_network = lossem_networks.intersection(router_networks).pop()
    router_IP = router.attrs['NetworkSettings']['Networks'][router_lossem_network]['IPAddress']
    
    exitcode, output = lossem.exec_run(
        ['sh', '-c', f"ip route replace default via {router_IP}"]
    )
    if exitcode != 0:
        raise Exception(f'Set lossem default route failed for lossem `{lossem.name}.\n{output}')

    logging.info(f'Network setup for `{lossem.name}` complete.')

def teardown_lossem(lossem):
    logging.info(f'[-] Tearing down `{lossem.name}`.')
    lossem.stop()
    logging.info(f'`{lossem.name}` stopped.')

def setup_router(router):
    logging.info(f"[+] Setting up router `{router.name}`")
    exitcode, output = router.exec_run(
        ['sh', '-c', "iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE"]
    )

    if exitcode != 0:
        raise Exception(f'Set NAT configuration failed for router `{router.name}`.\n{output}')

    logging.info(f"Network setup for `{router.name}` complete.")

    router.exec_run(
        redirect_to_out("iperf -s"),
        detach=True
    )

    logging.info(f"Iperf2 daemon started on `{router.name}`")

def teardown_router(router):
    logging.info(f'[-] Tearing down `{router.name}`.')
    router.stop()
    logging.info(f'`{router.name}` stopped.')

def setup_client(client, router, lossems):
    exitcode, output = client.exec_run(
        ['sh', '-c', "ip addr | grep eth0 | cut -d ' ' -f6 | cut -d '/' -f1 | tail -n 1"]
    )
    if exitcode != 0:
        raise Exception(f'Get network configuration failed for router `{router.name}`.\n{output}')

    client_addr_to_lossem = output.decode().strip()
    logging.info(f"Got client_addr: {client_addr_to_lossem}")

    client_network = list(client.attrs['NetworkSettings']['Networks'].keys())[0]
    # By convention, network between lossem and router has same name as network between client and lossem, except with router instead of client
    router_network = client_network.replace("client","router")
    # Look for lossem that shares network with this client
    lossem = next(filter(lambda l: client_network in l.attrs['NetworkSettings']['Networks'], lossems))
    
    lossem_addr_to_client = lossem.attrs['NetworkSettings']['Networks'][client_network]['IPAddress']
    lossem_addr_to_router = lossem.attrs['NetworkSettings']['Networks'][router_network]['IPAddress']
    router_addr_to_lossem = router.attrs['NetworkSettings']['Networks'][router_network]['IPAddress']

    logging.info(f"ip route replace default via {lossem_addr_to_client}")
    exitcode, output = client.exec_run(
        ['sh', '-c', f"ip route replace default via {lossem_addr_to_client}"]
    )
    if exitcode != 0:
        raise Exception(f'Set client default route failed for `{client.name}`.\n{output}')

    
    exitcode, output = router.exec_run(
        ['sh', '-c', f"ip route add {client_addr_to_lossem}/32 via {lossem_addr_to_router}"]
    )
    if exitcode != 0:
        raise Exception(f'Set client route failed for router `{router.name}`.\n{output}')

    behavior = client.labels.get(LABEL_PREFIX+'behavior')
    ## Network-stats collection

    # # We'll use the lossem's network condition labels in the filename.
    latency = lossem.labels.get(LABEL_PREFIX+'lossem.latency')
    loss = lossem.labels.get(LABEL_PREFIX+'lossem.loss')
    random = lossem.labels.get(LABEL_PREFIX+'lossem.random')
    later_latency = lossem.labels.get(LABEL_PREFIX+'lossem.later_latency')
    later_loss = lossem.labels.get(LABEL_PREFIX+'lossem.later_loss')

    details = f'{latency}-{loss}-{random}-{later_latency}-{later_loss}-{behavior.replace("/", ".")}'

    exitcode, output = client.exec_run(
            ['sh', '-c', f"ethtool -K eth0 gso off tso off sg off gro off lro off"]
    )

    if exitcode != 0:
        raise Exception(f'Disable offloads failed for client `{client.name}`.\n{output}')

    network_stats_command = f"python scripts/client/collection.py '{details}'"

    client.exec_run(
        redirect_to_out(network_stats_command),
        detach=True
    )

    logging.info(f'Network stats on `{client.name}` running as {details}.')
    
    # Start test behavior
    behavior_command = None
    if behavior == 'ping' or behavior == 'test':
        behavior_command = 'ping -i 3 8.8.8.8'
    elif behavior == 'none' or behavior == 'sleep':
        pass # Continue to sleep
    elif behavior == 'streaming':
        # This syntax needs to be used in order to run a single file as a
        # *module* so it can still utilize imports from its parent package.
        behavior_command = 'python scripts/client/starter-scripts/streaming/endless_youtube.py'
    elif behavior == 'browsing':
        behavior_command = 'python scripts/client/starter-scripts/browsing/endless_twitter.py'
    elif behavior == 'iperf':
        behavior_command = f'iperf -i 60 -t 300 -c {router_addr_to_lossem}'

    # We allow custom scripts to be run when behavior is `custom/<filename.py>`,
    # in which case we tell the client to pip install any requirements and run
    # that file.
    elif behavior.startswith('custom/'):
        path_to_script = f'scripts/{behavior}'
        path_to_requirements = 'scripts/custom/requirements.txt'

        behavior_command = f'pip install -r {path_to_requirements}; python {path_to_script}'

    elif behavior is None:
        logging.warning(f'Target behavior for `{client.name}` not found; will sleep.')
        pass
    else:
        logging.warning(f'Target behavior for `{client.name}` not recognized; will sleep.')
        pass

    logging.info(f"Running on {client.name}: {behavior_command}")
    client.exec_run(
        redirect_to_out(behavior_command),
        detach=True
    )
    logging.info(f"Finished on {client.name}: {behavior_command}")

    logging.info(f'Behavior script for `{client.name}` running.')


def teardown_client(client):
    """
    To be used with callback to daemon interrupt listener. Runs, in order:
    1. Interrupt network-stats collection
    2. Interrupt behavior
    3. Stop container
    """

    logging.info(f'[-] Tearing down `{client.name}`.')

    # Interrupt all processes except for the main sleep. It is important that
    # we interrupt rather than kill, otherwise the network-stats data will not
    # be written to the file!
    #
    # We don't detach here because we want to wait for the interrupt to succeed.
    client.exec_run('pkill --signal SIGINT -f network-stats')
    logging.info('Network-stats interrupted.')
    client.exec_run('pkill -f --inverse "sleep infinity" --signal SIGINT')
    logging.info('All other tasks interrupted.')

    # After the client has been fully interrupted, it can be stopped.
    client.stop()
    logging.info(f'`{client.name}` stopped.')

# The daemon doesn't need to wait forever for setup. Also, after setup is
# complete, the containers should run for a set amount of time then be
# interrupted and cleaned up.
def listen_for_container_startup(timeout=15):
    """

    Returns a list of clients that have been set up.
    """

    # Register the alarm signal to send a timeout error
    def alarm_handler(signum, frame):
        raise TimeoutError('Stop listening for events!')
    signal.signal(signal.SIGALRM, alarm_handler)
    # Raise the timeout error after n seconds
    signal.alarm(timeout)

    logging.info(f'Listening for docker startup events. Will stop listening after {timeout} seconds.')

    router = None
    lossems = []
    clients = []

    # Listen to docker events and handle client container setup when they start.
    # If we see a TimeoutError though, then we'll halt and return.
    #
    # /\/\/\/\/\
    # TODO: To avoid race conditions where a container is able to start up
    # before this listener is started, we should first check the existing
    # containers.
    #
    # Everything should be non-blocking.
    # \/\/\/\/\/
    #
    # /\/\/\/\/\/\/\/\
    # TODO: Probably a better approach overall would be to wait a short amount
    # of time until all containers are started, then loop through -- setting up
    # routers first, then clients.
    # \/\/\/\/\/\/\/\/
    try:
        for event in API.events(
                # We're only looking at containers that were started from our
                # docker compose project.
                filters={
                    'event': 'start',
                    'type': 'container',
                    'label': f'com.docker.compose.project={PROJECT_NAME}'
                },
                decode=True
            ):
            labels = event['Actor']['Attributes']

            container_type = labels.get('com.dane.type')

            if container_type == 'router':
                router = API.containers.get(event['id'])
                setup_router(router)
            elif container_type == 'lossem':
                lossem = API.containers.get(event['id'])
                lossems.append(lossem)
                setup_lossem(lossem,router)
            elif container_type == 'client':
                client = API.containers.get(event['id'])
                clients.append(client)
                setup_client(client, router, lossems)
            elif container_type == 'daemon':
                pass
            else:
                logging.warning(f'Unknown container type `{container_type}` seen for {labels.get("com.docker.compose.service")}. Ignoring.')

    except TimeoutError:
        logging.info('Timeout seen.')

    logging.info('No longer listening for docker events.')
    return router, lossems, clients

def handle_interrupt(router, lossems, clients):

    logging.info('Daemon interrupted!')

    for client in clients:
        teardown_client(client)

    logging.info('All clients stopped.')

    for lossem in lossems:
        teardown_lossem(lossem)

    teardown_router(router)

    logging.info('All container stopped, Daemon will now exit.')
    logging.info('Check `/data` for the network-stats output. Thanks for using this tool!')
    exit(0)

def listen_for_interrupt(handler, timeout=None):
    """

    Parameters
    ----------
    handler : function
        Expects a function with no arguments.
    timeout : seconds, optional
        If present, will automatically trigger interrupt after this amount of
        time.
    """

    logging.info('Listening for daemon interrupt.')
    logging.warning('\n\
========\n\
Please run `make stop` or `docker kill -s SIGINT dane_daemon_1` to stop\n\
this tool. Failure to do so will result in data loss.\n\
========')

    # TODO: If a timeout has been specified, halt after that amount of time

    # If an Interrupt has been seen, run teardown for all of the clients.
    signal.signal(signal.SIGINT, lambda signum, frame: handler())

if __name__ == "__main__":

    # Timeout needs to be sufficiently large to allow for all containers to be
    # connected to VPN, sequentially.
    #
    # TODO: Make event listener for startup non-blocking.
    router, lossems, clients = listen_for_container_startup(timeout=60)

    listen_for_interrupt(handler=lambda: handle_interrupt(router, lossems, clients))
    
    # While we're waiting for some signal the daemon can just chill out!
    signal.pause()
