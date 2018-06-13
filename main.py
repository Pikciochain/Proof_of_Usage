import logging
import sys
import threading
import time
from random import Random

from pikciopou import crypto
from pikciopou.config import Config
from pikciopou.context import LocalContext, RemoteContext
from pikciopou.transactions import TYPE_GENESIS


def create_shares(count):
    """Creates percentages to share an asset.

    :param count: The number of shares to create, so that sum(shares) = 1
    :type count: int
    :return: A list of all the shares, as floats between 0 and 1.
    :rtype: list[float]
    """
    weights = [crypto.random_positive_int(100) for _ in range(count)]
    total_weight = sum(weights)
    return [weight / total_weight for weight in weights]


def make_random_transaction(ctx, consumers, total_assets):
    """Generates and commits a random transaction between two different
    consumers.

    :param ctx: The context used to broadcast the transaction.
    :type ctx: Context
    :param consumers: Options to pick consumers.
    :type consumers: list[ConsumerNode]
    :param total_assets: The amount of initial assets that has been shared.
    :type total_assets: float
    """
    candidates = consumers.copy()
    random = Random()
    sender = random.choice(candidates)
    candidates.remove(sender)
    recipient = random.choice(candidates)

    amount = total_assets / len(consumers) * (random.random() / 10)
    tx = sender.create_transaction(recipient.id, amount)
    ctx.broadcast_transaction_to_masters(sender.id, tx)


def dispatch_assets(ctx, node_0, other_nodes):
    """Dispatches genesis assets between all the nodes.

    :param ctx: Context where the node 0 exists.
    :type ctx: Context
    :param node_0: The consumer that owns all the assets at first.
    :type node_0: Node
    :param other_nodes: The other nodes.
    :type other_nodes: lsit[ConsumerNode]
    """
    cfg = Config.app_config()
    logging.info('Posting genesis transaction...')
    tx = node_0.create_transaction(node_0.id, cfg.total_assets, TYPE_GENESIS)
    ctx.broadcast_transaction_to_masters(node_0.id, tx)

    # Create an altered transaction to test master nodes.
    tx = node_0.create_transaction(other_nodes[0].id, 2 * cfg.total_assets)
    tx.content.amount = 3345
    ctx.broadcast_transaction_to_masters(node_0.id, tx)

    # Create a transaction causing overdraft to test master nodes.
    tx = node_0.create_transaction(other_nodes[0].id, 2 * cfg.total_assets)
    ctx.broadcast_transaction_to_masters(node_0.id, tx)

    logging.info('Randomly split genesis asset between all consumers.')
    shares = create_shares(len(other_nodes) + 1)
    for i, node in enumerate(other_nodes):
        logging.info('Giving ~{:.2f}% to {}'.format(shares[i] * 100, node.id))
        tx = node_0.create_transaction(node.id, shares[i] * cfg.total_assets)
        ctx.broadcast_transaction_to_masters(node_0.id, tx)

    # Sleep a bit to let first block be closed.
    time.sleep(Config.app_config().block_time + 5)


def make_random_transactions(ctx, consumers):
    """Creates and commits random transactions between nodes.

    :param ctx: Context where the consumers exist.
    :type ctx: Context
    :param consumers: All the consumer nodes.
    :type consumers: list[ConsumerNode]
    """
    # Make random transactions and let time go by so that several blocks are
    # closed.
    cfg = Config.app_config()
    for i in range(100):
        logging.info('Firing random transaction {}'.format(i))
        make_random_transaction(ctx, consumers, cfg.total_assets)
        time.sleep(3)


def start_local_simulation():
    """Runs a simulation to show how Pikcio Proof Of Usage works."""

    cfg = Config.app_config()

    logging.info('Creating context...')
    ctx = LocalContext(
        cfg.keystore_path,
        cfg.masternodes_folder,
        cfg.cashingnodes_folder,
        cfg.consumernodes_folder,
        cfg.block_time,
        cfg.fees_rate,
        cfg.retribute_rate
    )
    # Clean any previous run
    ctx.clear()

    # Create the nodes locally.
    for _ in range(cfg.masternodes_count):
        ctx.create_masternode()
    for _ in range(cfg.cashingnodes_count):
        ctx.create_cashingnode()
    consumers = [
        ctx.create_consumernode()
        for _ in range(cfg.consumernodes_count)
    ]

    dispatch_assets(ctx, consumers[0], consumers[1:])

    ctx.start()
    make_random_transactions(ctx, consumers)
    ctx.stop()


def start_remote_simulation_master(i):
    """Runs a remote simulation for a single master."""
    cfg = Config.app_config()
    ctx_i = RemoteContext(
        cfg.keystore_path,
        cfg.masternodes_folder,
        cfg.cashingnodes_folder,
        cfg.consumernodes_folder,
        cfg.block_time,
        cfg.fees_rate,
        cfg.retribute_rate,
        5000 + i
    )
    node = ctx_i.create_masternode()
    logging.info('Created master {} (127.0.0.1:{})'.format(node.id, 5000 + i))
    ctx_i.start()


def start_remote_simulation():
    """Runs a remote simulation forthe consumers."""
    cfg = Config.app_config()

    logging.info('Creating local context...')
    ctx = RemoteContext(
        cfg.keystore_path,
        cfg.masternodes_folder,
        cfg.cashingnodes_folder,
        cfg.consumernodes_folder,
        cfg.block_time,
        cfg.fees_rate,
        cfg.retribute_rate,
        3000
    )

    # Create the nodes locally.
    for _ in range(cfg.cashingnodes_count):
        ctx.create_cashingnode()
    consumers = [
        ctx.create_consumernode()
        for _ in range(cfg.consumernodes_count)
    ]

    # Starts the context in background not to get blocked.
    threading.Thread(target=lambda: ctx.start(client_only=True)).start()

    # Register remote nodes
    logging.info('Scanning network...')
    for port in range(5000, 5000 + cfg.masternodes_count):
        remote_nodes = ctx.describe_remote_context('127.0.0.1', port)
        masters = remote_nodes.get('masters', [])
        for master_id in masters:
            ctx.register_remote_masternode(master_id)

    dispatch_assets(ctx, consumers[0], consumers[1:])
    make_random_transactions(ctx, consumers)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    cfg_ = Config.app_config()
    if cfg_.local_test:
        start_local_simulation()
    elif cfg_.remote_master is not None:
        start_remote_simulation_master(cfg_.remote_master)
    else:
        start_remote_simulation()
