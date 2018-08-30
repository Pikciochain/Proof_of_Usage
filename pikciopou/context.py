"""Handles communication between nodes. This module should encapsulate the
actual communication between nodes, might they be in the same process, in
different processes or on remote machines.
"""
import os
import shutil
import logging
import threading

import flask
import requests

from pikciosc.models import ContractInterface
from pikciosc.quotations import Quotation

from pikciopou import crypto
from pikciopou.blocks import Block
from pikciopou.keystore import KeyStore
from pikciopou.nodes import MasterNode, ConsumerNode, CashingNode, RefNode, \
    TrustedNode, SCBundle
from pikciopou.pou import ProofOfUsageAlgorithm
from pikciopou.transactions import Transaction


class LocalContext(object):
    """Keeps track of the current state of the network (nodes, keys...) and let
    actors interact with each other.
    """

    def __init__(self, keystore_path, masternodes_folder, cashingnodes_folder,
                 consumernodes_folder, trustednodes_folder, block_time,
                 fees_rate, retribute_rate):
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
        :param trustednodes_folder: Folder path on this machine where created
            trusted nodes should save their data.
        :type trustednodes_folder: str
        :param block_time: Seconds between each block creation.
        :type block_time: int
        :param fees_rate: Percentage of each transaction amount taken out as a
            fee.
        :type fees_rate: float
        :param retribute_rate: Percentage of each transaction fee that the
            master node closing a block can keep for itself.
        """
        self.trustednodes_folder = trustednodes_folder
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
        self.trustednodes = {}

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

    @property
    def trusteds_ids(self):
        """Returns an iterable of all the cashing nodes ids"""
        return self.trustednodes.keys()

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
            self.trustednodes if isinstance(node, TrustedNode) else
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
        node_registers = (
            self.masternodes, self.consumernodes, self.cashingnodes,
            self.trustednodes
        )
        for dct in node_registers:
            dct.clear()
        for folder in (
                self.masternodes_folder,
                self.consumernodes_folder,
                self.cashingnodes_folder,
                self.trustednodes_folder,
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
        logging.debug('Creating cashing {}'.format(len(self.cashingnodes)))
        return CashingNode(self, self.cashingnodes_folder)

    def create_trustednode(self):
        """Creates a trusted node and returns it.

        :return: The trusted node.
        :rtype: TrustedNode
        """
        # No cashing type at the moment.
        logging.debug('Creating trusted {}'.format(len(self.trustednodes)))
        return TrustedNode(self, self.trustednodes_folder)

    def poll_cashing_node_id(self):
        """Finds the next cashing node to redistribute fees to.

        :return: The id of the cashing node to use.
        :rtype: str
        """
        # TODO: Introduce some random
        return next(iter(self.cashings_ids))

    def poll_trusted_node_id(self):
        """Finds the next trusted node to ask a certificate to.

        :return: The id of the trusted node to use.
        :rtype: str
        """
        # TODO: Introduce some random
        return next(iter(self.trusteds_ids))

    def poll_master_node_id(self, hash_id):
        """Finds the next master node to contact for a request.

        :param hash_id: Id of a related item, to help in the decision process.
        :type hash_id: str
        :return: The id of the master node to use.
        :rtype: str
        """
        return crypto.get_closest_hash_to(hash_id, list(self.masters_ids))

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
        :return: A list of the non empty responses from the masternodes.
        :rtype: list[str]
        """
        results = [
            self.send_transaction_to_master(node_id, transaction)
            for node_id in self.masters_ids
            if node_id != sender_id
        ]
        return list(filter(None, results))

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
        :return: True if the node was found and the block was sent.
        :rtype: bool
        """
        masternode = self.masternodes.get(master_id)
        if masternode:
            masternode.receive_block(block)
        return masternode is not None

    def send_transaction_to_master(self, master_id, transaction):
        """Forwards the transaction in parameter to the specified masternode so
        that it can verify it and add it to its own transaction stack.

        :param transaction: Transaction to forward. It must have content and
            sender's signature.
        :type transaction: Transaction
        :param master_id: The id of the node to send the transaction to.
        :type master_id: str
        :return: Any string result possibly returned by the masternode.
        :rtype: str
        """
        masternode = self.masternodes.get(master_id)
        if masternode:
            return masternode.receive_transaction(transaction)
        return None

    def get_certificate(self, trusted_id, sender_id):
        """Request a certificate for the sender from specified trusted node.

        :param trusted_id: Id of trusted node to request certificate from.
        :type trusted_id: str
        :param sender_id: Id of sender requesting the certificate.
        :type sender_id: str
        :return: The certificate or None if the node was unreachable or failed
            to deliver the certificate.
        """
        trustednode = self.trustednodes.get(trusted_id)
        return (
            trustednode.deliver_certificate_for(sender_id) if trustednode
            else None
        )

    def get_sc_submit_quotation_from_master(self, sc_bundle, master_id):
        """Request a quotation from a masternode for executing the provided
        bundled smart contract.

        :param sc_bundle: The smart contract to request a quotation for
        :type sc_bundle: SCBundle
        :param master_id: Id of the master to contact.
        :type master_id: str
        :return: The quotation or None if an error occured.
        :rtype: Quotation
        """
        masternode = self.masternodes.get(master_id)
        return (
            masternode.get_sc_submit_quotation(sc_bundle) if masternode
            else None
        )

    def get_sc_submit_quotation(self, sc_bundle):
        """Request a quotation from any masternode for submitting
        the provided bundled smart contract.

        :param sc_bundle: The smart contract to request a quotation for
        :type sc_bundle: SCBundle
        :return: The quotation or None if an error occured.
        :rtype: Quotation
        """
        return self.get_sc_submit_quotation_from_master(
            sc_bundle,
            self.poll_master_node_id(sc_bundle.id)
        )

    def get_sc_invoke_quotation_from_master(self, sc_id, invoker_id,
                                            master_id, endpoint_name):
        """Request a quotation from a masternode for executing the provided
        smart contract.

        :param sc_id: Id of contract to execute.
        :type sc_id: str
        :param invoker_id: Id of Node requesting invocation.
        :type invoker_id: str
        :param master_id: Id of the master to contact.
        :type master_id: str
        :param endpoint_name: Name of executed endpoint.
        :type endpoint_name: str
        :return: The quotation or None if an error occured.
        :rtype: Quotation
        """
        masternode = self.masternodes.get(master_id)
        return (
            None if not masternode else
            masternode.get_sc_invoke_quotation(sc_id, invoker_id,
                                               endpoint_name)
        )

    def get_sc_invoke_quotation(self, sc_id, invoker_id, endpoint_name):
        """Request a quotation from any masternode for executing the provided
        bundled smart contract.

        :param sc_id: Id of contract to execute.
        :type sc_id: str
        :param invoker_id: Id of Node requesting invocation.
        :type invoker_id: str
        :param endpoint_name: Name of executed endpoint.
        :type endpoint_name: str
        :return: The quotation or None if an error occured.
        :rtype: Quotation
        """
        return self.get_sc_invoke_quotation_from_master(
            sc_id, invoker_id, self.poll_master_node_id(sc_id), endpoint_name
        )

    def get_sc_abi_from_master(self, sc_id, master_id):
        """Request a quotation from a masternode for the provided bundled smart
        contract.

        :param sc_id: Id of smart contract to request the ABI for.
        :type sc_id: str
        :param master_id: Id of the master to contact.
        :type master_id: str
        :return: The contract interface, if any.
        :rtype: ContractInterface
        """
        masternode = self.masternodes.get(master_id)
        return masternode.get_abi(sc_id) if masternode else None

    def get_sc_abi(self, sc_id):
        """Requests ABI for provided smart contract id.

        :param sc_id: Id of the contract to retrieve interface for.
        :type sc_id: str
        :return: The contract interface, if any.
        :rtype: ContractInterface
        """
        return self.get_sc_abi_from_master(
            sc_id, self.poll_master_node_id(sc_id)
        )

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

            @app.route('/trusted/<node_id>/certify/<other_id>')
            def _certify_node(node_id, other_id):
                return context.get_certificate(node_id, other_id)

            @app.route('/masters/<node_id>/sc/quotation')
            def _get_sc_submit_quote(node_id):
                bundle = SCBundle.from_json(flask.request.json)
                return context\
                    .get_sc_submit_quotation_from_master(bundle, node_id)\
                    .to_json()

            @app.route('/masters/<node_id>/sc/<sc_id>/abi')
            def _get_sc_abi(node_id, sc_id):
                return context\
                    .get_sc_abi_from_master(sc_id, node_id)\
                    .to_json()

            @app.route('/masters/<node_id>/sc/<sc_id>'
                       '/<endpoint>/quotation/<invoker_id>')
            def _get_sc_invoke_quote(node_id, sc_id, endpoint, invoker_id):
                return context.get_sc_invoke_quotation_from_master(
                    sc_id, invoker_id, node_id, endpoint
                ).to_json()

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
                    ],
                    'trusteds': [
                        node.id for node in context.trustednodes.values()
                        if isinstance(node, TrustedNode)
                    ]
                })

    def __init__(self, keystore_path, masternodes_folder, cashingnodes_folder,
                 consumernodes_folder, trustednodes_folder, block_time,
                 fees_rate, retribute_rate, port):
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
        :param trustednodes_folder: Folder path on this machine where created
            trusted nodes should save their data.
        :type trustednodes_folder: str
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
                         trustednodes_folder, block_time, fees_rate,
                         retribute_rate)
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

    def master_url(self, node_id):
        """Builds the url to reach out to a masternode's remote context.

        :param node_id: Id of the master node to reach.
        :type node_id: str
        :return: The base url, which must be completed to build the endpoint.
        :rtype: str
        """
        base = self._get_node_host_base_url(self.masternodes_folder, node_id)
        return base + 'masters/{}'.format(node_id)

    def consumer_url(self, node_id):
        """Builds the url to reach out to a consumer's remote context.

        :param node_id: Id of the consumer node to reach.
        :type node_id: str
        :return: The base url, which must be completed to build the endpoint.
        :rtype: str
        """
        base = self._get_node_host_base_url(self.consumernodes_folder, node_id)
        return base + 'consumers/{}'.format(node_id)

    def trusted_url(self, node_id):
        """Builds the url to reach out to a trusted node's remote context.

        :param node_id: Id of the trusted node to reach.
        :type node_id: str
        :return: The base url, which must be completed to build the endpoint.
        :rtype: str
        """
        base = self._get_node_host_base_url(self.trustednodes_folder, node_id)
        return base + 'trusted/{}'.format(node_id)

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
        """Returns an iterable of all the masters ids"""
        return os.listdir(self.masternodes_folder)

    @property
    def consumers_ids(self):
        """Returns an iterable of all the consumers ids"""
        return os.listdir(self.consumernodes_folder)

    @property
    def cashings_ids(self):
        """Returns an iterable of all the cashing nodes ids"""
        return os.listdir(self.cashingnodes_folder)

    @property
    def trusteds_ids(self):
        """Returns an iterable of all the cashing nodes ids"""
        return os.listdir(self.trustednodes_folder)

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

    def create_trustednode(self):
        """Overrides the default behavior to also save the node's address."""
        node = super().create_trustednode()
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
        return (
                super().send_block_to_master(master_id, block) or
                requests.post(
                    self.master_url(master_id) + '/blocks',
                    json=block.to_json()
                ) is not None
        )

    def send_transaction_to_master(self, master_id, transaction):
        """Sends a request to a remote node for it to push given transaction.

        :param transaction: The transaction to push
        :type transaction: Transaction
        :param master_id: The id of node to send the transaction to.
        :type master_id: str
        """
        return (
                super().send_transaction_to_master(master_id, transaction) or
                requests.post(
                    self.master_url(master_id) + '/transactions',
                    json=transaction.to_json()
                ).text
        )

    def get_lucky_signature(self, recipient_id, block):
        """Sends a request to a remote node to ask for its block signature.

        :param block: The block to sign.
        :type block: Block
        :param recipient_id: The id oft the remote node to contact.
        :type recipient_id: str
        :return: The signature
        :rtype str
        """
        return (
                super().get_lucky_signature(recipient_id, block) or
                requests.post(
                    self.consumer_url(recipient_id) + '/sign_block',
                    json=block.to_json()
                ).text
        )

    def get_certificate(self, trusted_id, sender_id):
        """Request a certificate for the sender from specified trusted node.

        :param trusted_id: Id of trusted node to request certificate from.
        :type trusted_id: str
        :param sender_id: Id of sender requesting the certificate.
        :type sender_id: str
        :return: The certificate or None if the node was unreachable or failed
            to deliver the certificate.
        """
        return (
                super().get_certificate(trusted_id, sender_id) or
                requests.get(
                    self.trusted_url(trusted_id) + '/certify/' + sender_id
                ).text
        )

    def get_sc_submit_quotation_from_master(self, bundle, master_id):
        """Request a quotation from a masternode for the provided bundled smart
        contract.

        :param bundle: The smart contract to request a quotation
            for
        :type bundle: SCBundle
        :param master_id: Id of the master to contact.
        :type master_id: str
        :return: The quotation or None if an error occured.
        :rtype: Quotation
        """
        return (
            super().get_sc_submit_quotation_from_master(bundle, master_id) or
            Quotation.from_dict(requests.post(
                self.master_url(master_id) + '/sc/quotation',
                json=bundle.to_json()
            ).json())
        )

    def get_sc_invoke_quotation_from_master(self, sc_id, invoker_id,
                                            master_id, endpoint_name):
        """Request a quotation from a masternode for executing the provided
        smart contract.

        :param sc_id: Id of contract to execute.
        :type sc_id: str
        :param invoker_id: Id of Node requesting invocation.
        :type invoker_id: str
        :param master_id: Id of the master to contact.
        :type master_id: str
        :param endpoint_name: Name of executed endpoint.
        :type endpoint_name: str
        :return: The quotation or None if an error occured.
        :rtype: Quotation
        """
        return (
            super().get_sc_invoke_quotation_from_master(
                sc_id, invoker_id, master_id, endpoint_name
            ) or Quotation.from_dict(requests.get(
                self.master_url(master_id) +
                '/sc/{}/quotation/{}'.format(sc_id, invoker_id),
            ).json())
        )

    def get_sc_abi_from_master(self, sc_id, master_id):
        """Request a quotation from a masternode for the provided bundled smart
        contract.

        :param sc_id: Id of smart contract to request the ABI for.
        :type sc_id: str
        :param master_id: Id of the master to contact.
        :type master_id: str
        :return: The contract interface, if any.
        :rtype: ContractInterface
        """
        return (
                super().get_sc_abi_from_master(sc_id, master_id) or
                ContractInterface.from_dict(requests.get(
                    self.master_url(master_id) + '/sc/{}/abi'.format(sc_id)
                ).json())
        )
