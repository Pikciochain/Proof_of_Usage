"""Handles communication between nodes. This module should encapsulate the
actual communication between nodes, might they be in the same process, in
different processes or on remote machines.
"""
import logging
import os
import shutil
import threading

import requests
import flask

from pikciopou import crypto
from pikciopou.blocks import Block
from pikciopou.keystore import KeyStore
from pikciopou.nodes import MasterNode, ConsumerNode, CashingNode, RefNode, \
    Node
from pikciopou.pou import ProofOfUsageAlgorithm
from pikciopou.transactions import Transaction


class LocalContext(object):
    """Keeps track of the current state of the network (nodes, keys...) and let
    actors interact with each other.
    """

    def __init__(self, keystore_path, masternodes_folder, cashingnodes_folder,
                 consumernodes_folder, block_time, fees_rate, retribute_rate):
        """Initialises a new Context.

        :param: keystore_path: Path to the folder on this machine to store the
            keys. It will be created if missing.
        :type keystore_path: str

        :param masternodes_folder: Folder path on this machine where created
            master nodes should save their data.
        :type masternodes_folder: str
        :param cashingnodes_folder: Folder path on this machine where created
            cashing nodes should save their data.
        :type cashingnodes_folder: str
        :param consumernodes_folder: Folder path on this machine where created
            consumer nodes should save their data.
        :type consumernodes_folder: str
        :param block_time: Seconds between each block creation.
        :type block_time: int
        :param fees_rate: Percentage of each transaction amount taken out as a
            fee.
        :type fees_rate: float
        :param retribute_rate: Percentage of each transaction fee that the
            master node closing a block can keep for itself.
        """
        self._keystore = KeyStore(keystore_path)
        self.masternodes_folder = masternodes_folder
        self.cashingnodes_folder = cashingnodes_folder
        self.consumernodes_folder = consumernodes_folder
        self.fees_rate = fees_rate
        self.retribute_rate = retribute_rate
        self._pou_algo = ProofOfUsageAlgorithm(1 - retribute_rate)
        self._create_block_timer = lambda: threading.Timer(
            block_time,
            self._block_timer_tick
        )
        self._block_timer = self._create_block_timer()
        self.next_block_seed = crypto.get_hash('0')
        self.started = False

        self.masternodes = {}
        self.consumernodes = {}
        self.cashingnodes = {}

    @property
    def masters_ids(self):
        """Returns an iterable of all the masters ids"""
        return self.masternodes.keys()

    @property
    def consumers_ids(self):
        """Returns an iterable of all the consumers ids"""
        return self.consumernodes.keys()

    @property
    def cashings_ids(self):
        """Returns an iterable of all the cashing nodes ids"""
        return self.cashingnodes.keys()

    def _block_timer_tick(self):
        """Triggered when it is time to close a block."""
        try:
            self.fire_close_block()
        except KeyboardInterrupt:
            return
        except Exception as e:
            logging.error(str(e))
        self._block_timer = self._create_block_timer()
        self._block_timer.start()

    def register_node(self, node, public_key):
        """Registers a node.

        This method should only be called if the node already exists somewhere.
        To create a node, rather use appropriate "create_" methods.

        :param node: The node to register. It will become publicly accessible
            by its id.
        :type node: Node
        :param public_key: The public key of the node.
        :type public_key: str
        """
        dct = (
            self.masternodes if isinstance(node, MasterNode) else
            self.cashingnodes if isinstance(node, CashingNode) else
            self.consumernodes if isinstance(node, ConsumerNode) else
            None
        )
        if dct is None:
            raise RuntimeError("Node of type '{}' can't be registered.".format(
                type(node)
            ))
        dct[node.id] = node
        self._keystore.register_public_key(node.id, public_key)

    def fire_close_block(self):
        """Sends a poke to all master nodes registered to this context to
        tell them it is time to close a block.
        """
        logging.info('Time is up for closing a block.')
        for node in self.masternodes.values():
            node.request_close_block()

    def clear(self):
        """Clean this context state and the folders on disk."""
        self._keystore.clear()
        for dct in self.masternodes, self.consumernodes, self.cashingnodes:
            dct.clear()
        for folder in (
                self.masternodes_folder,
                self.consumernodes_folder,
                self.cashingnodes_folder
        ):
            if os.path.exists(folder):
                shutil.rmtree(folder)
            os.makedirs(folder)

    def create_masternode(self):
        """Creates a master node and returns it.

        :return: The created master node.
        :rtype: MasterNode
        """
        logging.debug('Creating master {}'.format(len(self.masternodes)))
        return MasterNode(self, self.masternodes_folder, self._pou_algo)

    def create_consumernode(self):
        """Creates a consumer node and returns it.

        :return: The created consumer node.
        :rtype: ConsumerNode
        """
        logging.debug('Creating consumer {}'.format(len(self.consumernodes)))
        return ConsumerNode(self, self.consumernodes_folder)

    def create_cashingnode(self):
        """Creates a cashing node and returns it.

        :return: The cashing node.
        :rtype: CashingNode
        """
        # No cashing type at the moment.
        logging.debug('Creating cashing {}'.format(len(self.cashingnodes)))
        return CashingNode(self, self.cashingnodes_folder)

    def poll_cashing_node_id(self):
        """Finds the next cashing node to redistribute fees to.

        :return: The id of the cashing node to use.
        :rtype: str
        """
        return next(iter(self.cashings_ids))

    def get_public_key(self, node_id):
        """Returns the public key of the provided node, if that node is
        registered.

        :param node_id: The id of the node to get public key for.
        :type node_id: str
        :return: The public key of the node or None if no public key was found.
        :rtype: str
        """
        return self._keystore.public_key(node_id) or ''

    def broadcast_block_to_masters(self, sender_id, block):
        """Forwards the block in parameter to all the master nodes (except the
        sender) so that they can verify it and add it to their own chain.

        :param sender_id: Id of node (supposedly master) sending this block.
        :type sender_id: str
        :param block: Block to forward. It must be complete.
        :type block: Block
        """
        for node_id in self.masters_ids:
            if node_id != sender_id:
                self.send_block_to_master(node_id, block)

    def broadcast_transaction_to_masters(self, sender_id, transaction):
        """Forwards the transaction in parameter to all the master nodes so
        that they can verify it and add it to their own transaction stack.

        :param sender_id: Id of node (supposedly master) sending this block.
        :type sender_id: str
        :param transaction: Transaction to forward. It must have content and
            sender's signature.
        :type transaction: Transaction
        """
        for node_id in self.masters_ids:
            if node_id != sender_id:
                self.send_transaction_to_master(node_id, transaction)

    def get_lucky_signature(self, recipient_id, block):
        """Asks for a lucky stakeholder to sign header of provided block, if he
        agrees with the fees redistribution. Stakeholders have to be reachable,
        as they may be deprived from their prize if they do not answer in time.

        :param recipient_id: Id of stakeholder to send the block for signature.
        :type recipient_id: str
        :param block: The block to sign.
        :type block: Block
        :return: The signature of the block by the stakeholder or None if the
            node was unreachable or failed to sign.
        :rtype: str
        """
        consumernode = self.consumernodes.get(recipient_id)
        return consumernode.sign_block(block.header) if consumernode else None

    def send_block_to_master(self, master_id, block):
        """Forwards the block in parameter to the specified master nodes it
        can verify it and add it to its own chain.

        :param block: Block to forward. It must be complete.
        :type block: Block
        :param master_id: The id of the node to send the block to.
        :type master_id: str
        """
        masternode = self.masternodes.get(master_id)
        if masternode:
            masternode.receive_block(block)

    def send_transaction_to_master(self, master_id, transaction):
        """Forwards the transaction in parameter to the specified masternode so
        that it can verify it and add it to its own transaction stack.

        :param transaction: Transaction to forward. It must have content and
            sender's signature.
        :type transaction: Transaction
        :param master_id: The id of the node to send the transaction to.
        :type master_id: str
        """
        masternode = self.masternodes.get(master_id)
        if masternode:
            masternode.receive_transaction(transaction)

    def start(self):
        """Starts the context. Depends on the context implementation."""
        if self.started:
            return

        self.started = True
        self._block_timer.start()
        logging.info('Context started.')

    def stop(self):
        """Stops the context."""
        if not self.started:
            return

        self._block_timer.cancel()
        self.started = False
        logging.info('Context stopped.')


class RemoteContext(LocalContext):
    """Stands for a context where at least some nodes exist outside on the
    network.
    """

    class RemoteContextServer(object):
        """Lightweight server exposing entrypoints to interact with a context.
        """

        def __init__(self, remote_context, port):
            """Creates a new RemoteContextServer.

            :param remote_context: an object exposing appropriate callbacks
            :type remote_context: RemoteContextServer
            """
            self._app = flask.Flask(__name__)
            self._route(remote_context, self._app)
            self.port = port
            self.ip_address = '127.0.0.1'

        def start(self):
            """Starts this server. Never returns."""
            self._app.run('0.0.0.0', self.port)

        @staticmethod
        def _route(context, app):
            @app.route('/masters/<node_id>/blocks', methods=['POST'])
            def _post_block(node_id):
                block = Block.from_json(flask.request.json)
                context.send_block_to_master(node_id, block)
                return 'OK'

            @app.route('/masters/<node_id>/transactions', methods=['POST'])
            def _post_transaction(node_id):
                transaction = Transaction.from_json(flask.request.json)
                context.send_transaction_to_master(node_id, transaction)
                return 'OK'

            @app.route('/consumers/<node_id>/sign_block', methods=['POST'])
            def _sign_block(node_id):
                block = Block.from_json(flask.request.json)
                return context.get_lucky_signature(node_id, block)

            @app.route('/describe', methods=['GET'])
            def _describe():
                return flask.jsonify({
                    'masters': [
                        node.id for node in context.masternodes.values()
                        if isinstance(node, MasterNode)
                    ],
                    'consumers': [
                        node.id for node in context.consumernodes.values()
                        if isinstance(node, ConsumerNode)
                    ],
                    'cashings': [
                        node.id for node in context.cashingnodes.values()
                        if isinstance(node, CashingNode)
                    ]
                })

    def __init__(self, keystore_path, masternodes_folder, cashingnodes_folder,
                 consumernodes_folder, block_time, fees_rate, retribute_rate,
                 port):
        """Creates a new Remote context listening ont his host and given port.

        :param: keystore_path: Path to the folder on this machine to store the
            keys. It will be created if missing.
        :type keystore_path: str
        :param masternodes_folder: Folder path on this machine where created
            master nodes should save their data.
        :type masternodes_folder: str
        :param cashingnodes_folder: Folder path on this machine where created
            cashing nodes should save their data.
        :type cashingnodes_folder: str
        :param consumernodes_folder: Folder path on this machine where created
            consumer nodes should save their data.
        :type consumernodes_folder: str
        :param block_time: Seconds between each block creation.
        :type block_time: int
        :param fees_rate: Percentage of each transaction amount taken out as a
            fee.
        :type fees_rate: float
        :param retribute_rate: Percentage of each transaction fee that the
            master node closing a block can keep for itself.
        :type port: The port number to reach out to the node in the context.
        :type port: int
        """
        super().__init__(keystore_path, masternodes_folder,
                         cashingnodes_folder, consumernodes_folder,
                         block_time, fees_rate, retribute_rate)
        self._server = self.RemoteContextServer(self, port)

    @staticmethod
    def _save_host_info(node, ip_address, port):
        """Creates a file to save address of provided remote node.

        :param node: The node to save address for.
        :type node: Node
        :param ip_address: IP Address of context where this node belongs.
        :type ip_address: str
        :param port: Port number of context where this node belongs.
        :type port: int
        """
        with open(os.path.join(node.node_folder, 'host'), 'w') as fd:
            fd.write('{}:{}'.format(ip_address, port))

    @staticmethod
    def _get_host_info(node_host_file_path):
        """Fetches address and port of node which host file is at provided
        location.

        :param node_host_file_path: Path to the node host file.
        :type node_host_file_path: str
        :return: Its IP address and port.
        :rtype: tuple[str, str]
        """
        with open(node_host_file_path, 'r') as fd:
            return fd.read().split(':')

    def _get_node_host_base_url(self, node_root_folder, node_id):
        """Builds the base url to reach out to a node's remote context.

        :param node_root_folder: Folder containing the node's details.
        :type node_root_folder: str
        :param node_id: Id of the node to reach.
        :type node_id: str
        :return: The base url, which must be completed to build the endpoint.
        :rtype: str
        """
        host_filepath = os.path.join(node_root_folder, node_id, 'host')
        return 'http://{}:{}/'.format(*self._get_host_info(host_filepath))

    def get_master_base_endpoint(self, node_id):
        """Builds the url to reach out to a masternode's remote context.

        :param node_id: Id of the master node to reach.
        :type node_id: str
        :return: The base url, which must be completed to build the endpoint.
        :rtype: str
        """
        base = self._get_node_host_base_url(self.masternodes_folder, node_id)
        return base + 'masters/{}'.format(node_id)

    def get_consumer_base_endpoint(self, node_id):
        """Builds the url to reach out to a consumer's remote context.

        :param node_id: Id of the consumer node to reach.
        :type node_id: str
        :return: The base url, which must be completed to build the endpoint.
        :rtype: str
        """
        base = self._get_node_host_base_url(self.consumernodes_folder, node_id)
        return base + 'consumers/{}'.format(node_id)

    def register_remote_masternode(self, node_id):
        """Registers a remote masternode exists on distant host.

        :param node_id: The node id.
        :type node_id: str
        """
        self.masternodes[node_id] = RefNode(node_id)

    @staticmethod
    def describe_remote_context(ip_address, port):
        """Returns a dictionary of the nodes living in the context at provided
        address and port.

        :param ip_address: IP address of remote node.
        :type ip_address: str
        :param port: Port number oh distant host.
        :type port: int
        :return: A dictionary of masters, consumers and cashings.
        :rtype: dict
        """
        url = 'http://{}:{}/describe'.format(ip_address, port)
        return requests.get(url).json()

    # LocalContext override

    @property
    def masters_ids(self):
        """Masters ids are all under the master folder."""
        return os.listdir(self.masternodes_folder)

    @property
    def consumers_ids(self):
        """Consumer ids are all under the master folder."""
        return os.listdir(self.consumernodes_folder)

    @property
    def cashings_ids(self):
        """Cashing ids are all under the master folder."""
        return os.listdir(self.cashingnodes_folder)

    def create_masternode(self):
        """Overrides the default behavior to also save the node's address."""
        node = super().create_masternode()
        self._save_host_info(node, self._server.ip_address, self._server.port)
        return node

    def create_cashingnode(self):
        """Overrides the default behavior to also save the node's address."""
        node = super().create_cashingnode()
        self._save_host_info(node, self._server.ip_address, self._server.port)
        return node

    def create_consumernode(self):
        """Overrides the default behavior to also save the node's address."""
        node = super().create_consumernode()
        self._save_host_info(node, self._server.ip_address, self._server.port)
        return node

    def start(self, client_only=False):
        """Starts the context. Depends on the context implementation.

        :param client_only: If true, The block closure won't be triggered
            regularly.
            :type client_only: bool
        """
        if self.started:
            return

        if not client_only:
            super().start()
        logging.info('Context started.')
        self._server.start()

    def stop(self):
        """Stops the context."""
        if not self.started:
            return

        super().stop()
        logging.info('Context stopped.')

    def send_block_to_master(self, master_id, block):
        """Sends a request to a remote node for it to push given block.

        :param block: The block to push
        :type block: Block
        :param master_id: The id of node to send the block to.
        :type master_id: str
        """
        node = self.masternodes.get(master_id)
        if isinstance(node, Node):
            super().send_block_to_master(master_id, block)
        else:
            url = self.get_master_base_endpoint(master_id) + '/blocks'
            requests.post(url, json=block.to_json())

    def send_transaction_to_master(self, master_id, transaction):
        """Sends a request to a remote node for it to push given transaction.

        :param transaction: The transaction to push
        :type transaction: Transaction
        :param master_id: The id of node to send the transaction to.
        :type master_id: str
        """
        node = self.masternodes.get(master_id)
        if isinstance(node, Node):
            super().send_transaction_to_master(master_id, transaction)
        else:
            url = self.get_master_base_endpoint(master_id) + '/transactions'
            requests.post(url, json=transaction.to_json())

    def get_lucky_signature(self, recipient_id, block):
        """Sends a request to a remote node to ask for its block signature.

        :param block: The block to sign.
        :type block: Block
        :param recipient_id: The id oft the remote node to contact.
        :type recipient_id: str
        :return: The signature
        :rtype str
        """
        node = self.consumernodes.get(recipient_id)
        if isinstance(node, Node):
            return super().get_lucky_signature(recipient_id, block)
        else:
            url = self.get_consumer_base_endpoint(recipient_id) + '/sign_block'
            return requests.post(url, json=block.to_json()).text
