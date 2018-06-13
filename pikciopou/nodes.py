"""Defines all kinds of nodes involved in the process."""
import logging
import os
import shutil

from pikciopou import crypto
from pikciopou.blocks import Block, BlockStamp
from pikciopou.pou import ProofOfUsageAlgorithm
from pikciopou.transactions import Transaction, TransactionStamp, \
    TransactionContent, TYPE_CASHBACK, TYPE_CASHING, TYPE_TX_FEES, TYPE_TX, \
    TYPE_GENESIS


class Chain(object):
    """Manages a chain of objects (transactions, blocks). Objects are saved
    on disk.
    """

    def __init__(self, folder, from_json_func, to_json_func):
        """Creates a new Chain. The transaction will be stored under
        the provided directory that must exist.

        :param folder: The folder to store the objects on disk.
        :type folder: str
        :param from_json_func: Function to convert JSON to a model object.
        :type from_json_func: callable
        :type to_json_func: callablen to convert a model object to JSON.
        :type to_json_func: callable
        """
        self._folder = folder
        self._from_json = from_json_func
        self._to_json = to_json_func

    def __iter__(self):
        for i in range(len(self)):
            yield self.get(i)

    def __reversed__(self):
        """Returns a reversed iterator on this chain's objects.

        :return: An iterator on this chain's objects.
        :rtype: iterator
        """
        for i in reversed(range(len(self))):
            yield self.get(i)

    def _check_folder(self):
        """Ensures the directory used by this Chain exists"""
        if not os.path.isdir(self._folder):
            os.makedirs(self._folder)

    def __len__(self):
        self._check_folder()
        return len(os.listdir(self._folder))

    def clear(self):
        """Removes all objects in this chain."""
        if os.path.isdir(self._folder):
            shutil.rmtree(self._folder)

    def _get_path(self, index):
        """Gives object file name depending of its index in the chain.

        :param index: The index of the object in the chain.
        :type index: int
        :return: File path to create or retrieve an object.
        :rtype: str
        """
        return os.path.join(self._folder, '{}.json'.format(index))

    def get(self, index):
        """Returns object in the chain with provided chain index.

        :param index: Index of the object in the chain.
        :type index: int
        :return: The object at the index or None in case object is corrupted.
        """
        count = len(self)
        if index < 0 or index >= count:
            raise IndexError('Invalid chain index {} on {}'.format(
                index, count
            ))
        with open(self._get_path(index), 'r') as txfile:
            return self._from_json(txfile.read())

    def push(self, obj):
        """Puts provided object on the chain.

        :param obj: object to push on top of this chain.
        :type obj: object
        """
        self._check_folder()
        with open(self._get_path(len(self)), 'w') as txfile:
            txfile.write(self._to_json(obj))

    def push_all(self, objs):
        """Shortcut for pushing a list of objects.

        :param objs: objects to push on top of this chain.
        :type objs: iterable
        """
        for obj in objs:
            self.push(obj)


class RefNode(object):
    """The simplest definition of a node part of the application."""

    def __init__(self, node_id):
        """Creates a new RefNode

        :param node_id: Id of this node. Should be a SHA256
        :type node_id: str
        """
        self.id = node_id


class Node(RefNode):
    """Defines common behavior for nodes created in the process.
    This class is not meant to be instantiated.
    """

    def __init__(self, context, nodes_folder):
        """Creates a new Node.

        :param context: The running context that is required to interact with
            the node network.
        :type context: Context
        :param nodes_folder: Root folder for nodes of this type.
        :type nodes_folder: str
        """
        super().__init__(crypto.get_hash())
        self.node_folder = os.path.join(nodes_folder, self.id)

        self.context = context
        keys = crypto.generate_encryption_keys(self.id)
        self.private_key = keys.private_key
        context.register_node(self, keys.public_key)

        os.makedirs(self.node_folder)

    def get_public_key(self, node_id):
        """Requests and returns the public key of the provided node, if that
        node is registered.

        :param node_id: The id of the node to get public key for.
        :type node_id: str
        :return: The public key of the node or None if no public key was found.
        :rtype: str
        """
        return self.context.get_public_key(node_id)


class CashingNode(Node):
    """Stands for a node accumulating non redistributed fees before sharing
    them with the community."""


class ConsumerNode(Node):
    """Stands for a node who is using the blockchain, creating transactions
    and consuming assets.
    """

    def _sign(self, payload):
        """Signs any payload.

        :param payload: The payload to sign.
        :type payload: str
        :return: The resulting signature
        :rtype: str
        """
        return crypto.sign(payload, self.private_key, self.id)

    def sign_transaction(self, transaction_content):
        """Signs the provided transaction with this node's private key.

        :param transaction_content: the transaction to sign.
        :type transaction_content: TransactionContent
        :return: The resulting signature
        :rtype: str
        """
        return self._sign(transaction_content.to_json())

    def sign_block(self, block_header):
        """Signs the provided block header with this node's private key.

        :param block_header: the header of the block to sign.
        :type block_header: BlockHeader
        :return: The resulting signature
        :rtype: str
        """
        return self._sign(block_header.to_json())

    def create_transaction(self, recipient_id, amount, tx_type=TYPE_TX):
        """Creates a transaction from this node to another and signs it.

        The resulting transaction is ready t be sent to a master node to get a
            stamp.

        :param recipient_id: The recipient of this transaction.
        :type: str
        :param amount: The amount to send.
        :type: Union[int,float]
        :param tx_type: Optional. Overrides default transaction type.
        :type tx_type: str
        :return: a Transaction signed by this node.
        :rtype: Transaction
        """
        tx_content = TransactionContent(
            sender_id=self.id,
            recipient_id=recipient_id,
            amount=amount,
            tx_type=tx_type
        )
        signature = self.sign_transaction(tx_content)
        return Transaction(tx_content, signature)


class MasterNode(ConsumerNode):
    """Stands for a trusted node whose role is to verify transactions and close
    blocks.
    """

    def __init__(self, context, master_nodes_folder, pou_algo):
        """Creates a new MasterNode along with its working environment.

        :param context: The running context that is required to interact with
            the node network.
        :type context: Context
        :param master_nodes_folder: Root folder of the master nodes.
        :type master_nodes_folder: str
        """
        super().__init__(context, master_nodes_folder)

        self._pou_algo = pou_algo
        self._next_block_seed = context.next_block_seed
        self._tx_stack = Chain(
            os.path.join(self.node_folder, 'transactions'),
            lambda json_tx: Transaction.from_json(json_tx),
            lambda tx: tx.to_json()
        )
        self._blockchain = Chain(
            os.path.join(self.node_folder, 'blocks'),
            lambda json_block: Block.from_json(json_block),
            lambda block: block.to_json()
        )

        self._reset_logger()
        self._logger.info('I am {}'.format(self.id))

    def _reset_logger(self):
        """Creates a new logger for this node with a file output."""
        fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler = logging.FileHandler(
            os.path.join(self.node_folder, 'log.txt')
        )
        handler.setFormatter(fmt)

        self._logger = logging.getLogger(self.id)
        self._logger.addHandler(handler)
        # self._logger.propagate = False  # Do not forward to root logger.

    def _make_transaction_stamp(self, transaction_content):
        """Creates a TransactionStamp for provided TransactionContent.

        :param transaction_content: Content to create a stamp for.
        :type transaction_content: TransactionContent
        :return: A stamp to put in the transaction related to that content.
        :rtype: TransactionStamp
        """
        fees = transaction_content.compute_fees(self.context.fees_rate)
        return TransactionStamp(fees, self.id)

    def _create_stamped_transaction(self, recipient_id, amount,
                                    tx_type=TYPE_TX):
        """Creates a stamped and signed transaction from this node to another.

        :param recipient_id: The recipient of this transaction.
        :type: str
        :param amount: The amount to send.
        :type: Union[int,float]
        :param tx_type: Optional. Overrides default transaction type.
        :type tx_type: str
        :return: a Transaction signed and stamped by this node.
        :rtype: Transaction
        """
        transaction = self.create_transaction(recipient_id, amount, tx_type)
        transaction.stamp = self._make_transaction_stamp(transaction.content)
        return transaction

    @staticmethod
    def _find_funds(transactions, node_id, amount):
        """Browses backward a list of transactions to verify the required
        funds are available to the provided node id.

        :param transactions: List of transactions to browse.
        :type transactions: iterable[Transaction]
        :param node_id: id of node requiring the amount.
        :type node_id: str
        :param amount: The amount required.
        :return: The available funds if they are too short, or amount itself.
        :rtype: float
        """
        available = 0
        for transaction in reversed(transactions):
            available += transaction.delta_for(node_id)
            if available >= amount:
                return amount
        return available

    def _provokes_overdraft(self, sender_id, amount):
        """Returns true if validating provided transaction would cause sender
        to go overdraft.

        :param sender_id: id of sender spending the amount.
        :type sender_id: str
        :param amount: The amount sender is spending.
        :type amount: float
        :return: True if spending causes overdraft, False otherwise.
        :rtype: bool
        """
        # First find funds in stacked transactions.
        amount -= self._find_funds(self._tx_stack, sender_id, amount)
        if amount <= 0:
            return False

        # If it is not enough, browse the chain backwards.
        for block in reversed(self._blockchain):
            amount -= self._find_funds(block.transactions, sender_id, amount)
            if amount <= 0:
                return False
        return True

    def _shall_close_current_block(self, block_seed):
        """Checks whether this node should be the one to close the current
        block. The choice is made based on nodes hashes distance.

        :param block_seed: The seed of the block about to be closed.
        :type block_seed: str
        :return: True if this node should close the current block.
        :rtype: bool
        """
        master_hashes = self.context.masters_ids
        chosen_hash = crypto.get_closest_hash_to(block_seed, master_hashes)
        self._logger.info(
            'I will close this block.' if chosen_hash == self.id else
            '{} will close this block.'.format(chosen_hash)
        )
        return chosen_hash == self.id

    def _create_cashbacks_transactions(self, cashbacks):
        """Creates transactions to retribute lucky stakeholders.

        :param cashbacks: The cashbacks decided py the PoU algorithm.
        :type cashbacks: list[POUCashbacklist]
        :return: list of transactions built upon provided cashbacks.
        :rtype: list[Transaction]
        """
        for cb in cashbacks:
            self._logger.info("{}... will get {:.3f} PKC cashback".format(
                cb.node_id[:8], cb.amount
            ))
        return [
            self._create_stamped_transaction(
                cb.node_id, cb.amount, TYPE_CASHBACK
            )
            for cb in cashbacks
        ]

    def _create_cashing_transaction(self, cashing):
        """Creates transaction to give cashing amount to a cashing node.

        :param cashing: amount to give to a cashing node.
        :type cashing: float
        :return: transaction built upon provided cashing.
        :rtype: Transaction
        """
        cashing_node_id = self.context.poll_cashing_node_id()
        self._logger.info("Cashing node {}... will get {:.3f} PKC".format(
            cashing_node_id[:8], cashing
        ))

        return self._create_stamped_transaction(
            cashing_node_id, cashing, TYPE_CASHING
        )

    def _create_return_transactions(self, transactions, block_seed):
        """Proceeds to a redistribution of the transaction fees collected in
        the block about to be closed.

        The transaction fees are dispatched to the 'lucky stakeholders', that
        is to say nodes that have sent assets in at least a transaction of this
        block.

        :param transactions: The transactions in the block about to be closed.
        :type transactions: list[Transaction]
        :param block_seed: The seed of the block about to be closed.
        :type block_seed: str
        :return:
        """
        # Remove genesis transaction: There is no redistribution on that one.
        txs = [tx for tx in transactions if tx.content.type != TYPE_GENESIS]
        if not txs:
            return []
        cashing, cashbacks = self._pou_algo.compute(txs, block_seed)
        return self._create_cashbacks_transactions(cashbacks) + \
            [self._create_cashing_transaction(cashing)]

    def _create_fees_collection_transaction(self, transactions):
        """Creates a transaction to give this master node all the fees in
        provided transactions.

        :param transactions: The transaction to collect fees from.
        :type: transactions: list[Transaction]
        :return: A new transaction to give this node all the transaction fees.
        :type: Transaction
        """
        fees = sum(tx.stamp.fees for tx in transactions)
        self._logger.info("Collected {:.3f} PKC fees".format(fees))
        return self._create_stamped_transaction(self.id, fees, TYPE_TX_FEES)

    def _push_block(self, block):
        """Pushes provided block in the block chain of this node.

        :param block: The block to append to the chain.
        :type block: Block
        """
        self._blockchain.push(block)
        self._next_block_seed = block.header.merkle_root

    def _collect_transactions_for_block_closure(self, block_seed):
        """Collects stacked transactions and add the fees and cashback ones.

        :param block_seed: The seed of the block about to be closed.
        :type block_seed: str
        :return: All the transactions to include in the block.
        :rtype: list[Transaction]
        """
        base_transactions = list(iter(self._tx_stack))
        if not base_transactions:
            self._logger.warning('No transaction to close block. Aborting.')
            return []

        # To the normal transactions we add one to give all the fees to the
        # masternode and some others to redistribute part of those fees.
        return base_transactions + \
            [self._create_fees_collection_transaction(base_transactions)] + \
            self._create_return_transactions(base_transactions, block_seed)

    def _make_block_stamp(self, block):
        """Creates and returns a stamp for provided block. The stamp contains
        the master and lucky stakeholders signatures.

        :param block: THe block to stamp.
        :type: Block
        :return: A stamp to put in the block.
        :rtype: BlockStamp
        """
        master_signature = self.sign_block(block.header)
        lucky_signatures = {
            node_id: self.context.get_lucky_signature(node_id, block)
            for node_id in block.lucky_stakeholders
        }
        return BlockStamp(self.id, master_signature, lucky_signatures)

    def _close_block(self, block_seed):
        """Closes a block from current stacked transactions, redistribute the
        fees and broadcasts the block to other master nodes.

        :param block_seed: The seed of the block about to be closed.
        :type block_seed: str
        """
        self._logger.info('Closing block with seed {}...'.format(block_seed))
        transactions = self._collect_transactions_for_block_closure(block_seed)
        if not transactions:
            return

        block = Block(transactions).close(
            self.context.retribute_rate,
            block_seed
        )

        block.stamp = self._make_block_stamp(block)
        self._logger.info("Lucky stakeholders signed the transaction.")

        self.context.broadcast_block_to_masters(self.id, block)
        self._logger.info("Block shared with all master nodes.")

        self._push_block(block)
        self._logger.info("Block saved.")
        self._tx_stack.clear()

    @staticmethod
    def _verify_proof_of_usage(block, seed):
        """Recomputes the proof of usage for provided block to check that it is
        authentic and has not been hacked.

        :param block: The block which proof of usage has to be checked.
        :type block: Block
        :param seed: The SHA256 seed used to compute the proof of usage.
        :type seed: str
        """
        pou = ProofOfUsageAlgorithm(1 - block.header.retribution_rate)
        cashing, cashbacks = pou.compute(block.regular_transactions, seed)

        if block.cashing_amount != cashing:
            raise Exception('Cashing of this block could not be recomputed.')

        expected_cashback = sum(cashback.amount for cashback in cashbacks)
        if block.cashback_amount != expected_cashback:
            raise Exception('Cashback of this block could not be recomputed.')

        expected_stakeholders = set(cashback.node_id for cashback in cashbacks)
        if set(block.lucky_stakeholders) != expected_stakeholders:
            raise Exception('Lucky stakeholders could not be recomputed.')

    def _reset_transaction_stack_after_block_check(self, transactions):
        """Clears this node's transaction stack and push provided transactions
        inside in the right order.

        :param transactions: The remaining transactions in the stack
        :type transactions: iterable[Transaction]
        """
        # Sort them by emission date as it is required for overdraft checking.
        self._tx_stack.clear()
        self._tx_stack.push_all(sorted(
            transactions,
            key=lambda tx: tx.content.emission_time
        ))

    def _verify_block_against_transaction_stack(self, transactions):
        """Compares the transactions received from a block with those in the
        current stack.

        Transactions in the stack but not in the block will remain until next
        block closure. Transactions in the block but not in the stack will be
        verified on the fly.

        Finally, a new stack is created with the remaining transactions only.

        :param transactions: The transactions to compare to the stack.
        :type transactions: list[Transaction]
        """
        remaining_txs = {tx.content.tx_id: tx for tx in self._tx_stack}
        for tx in transactions:
            if tx.content.tx_id in remaining_txs:
                del remaining_txs[tx.content.tx_id]
            else:
                tx.verify(self.get_public_key(tx.content.sender_id))

        self._reset_transaction_stack_after_block_check(remaining_txs.values())

    def receive_transaction(self, transaction):
        """Records provided transaction. A stamp is added to the transaction
        and the result is stacked waiting for the time to close the block.

        :param transaction: The transaction to record.
        :type transaction: Transaction
        """
        try:
            content = transaction.content
            stamp = self._make_transaction_stamp(content)
            self._logger.info('Received transaction {}'.format(content.tx_id))
            transaction.verify(self.get_public_key(content.sender_id))
            if content.sender_id != content.recipient_id:
                # Sender has to pay amount + fees
                if self._provokes_overdraft(
                        content.sender_id, content.amount + stamp.fees
                ):
                    raise Exception('Sender does not have sufficient funds.')

            transaction.stamp = stamp
            self._logger.info(transaction)
            self._tx_stack.push(transaction)
        except Exception as e:
            self._logger.error('Transaction rejected: {}'.format(str(e)))

    def receive_block(self, block):
        """Records provided block. The block is verified and added to the chain
        in case the verification succeeds.

        :param block: The block to record.
        :type block: Block
        """
        self._logger.info('Received block {}'.format(block.header.merkle_root))
        try:
            block.verify(self.get_public_key)
            self._verify_proof_of_usage(block, self._next_block_seed)
            self._verify_block_against_transaction_stack(block.transactions)
            self._push_block(block)
        except Exception as e:
            self._logger.error('Block rejected: {}'.format(str(e)))

    def request_close_block(self):
        """Requests this node to close current block. The closing will only be
        performed if this node is the one that should actually close it.
        """
        self._logger.info('Block closure requested...')
        if self._shall_close_current_block(self._next_block_seed):
            self._close_block(self._next_block_seed)
