"""Defines all kinds of nodes involved in the process."""
import logging
import os

import itertools
from pikciosc import quotations, abi
from pikciosc.invoke import invoke

from pikciopou import crypto
from pikciopou.blocks import Block, BlockStamp
from pikciopou.pou import ProofOfUsageAlgorithm
from pikciopou.serialization import JSONSerializable, Chain, SCEnvironment
from pikciopou.transactions import Transaction, TransactionStamp, \
    TransactionContent, TYPE_CASHBACK, TYPE_CASHING, TYPE_TX_FEES, TYPE_TX, \
    TYPE_GENESIS, ContractSubmissionContent, ContractInvocationContent, \
    ContractExecutionContent


class SCBundle(JSONSerializable):
    """Packaging of a Smart Contract, ready to be sent to a Master Node for
    quotation.
    """

    def __init__(self, source_b64, signature, emitter_id):
        """Creates a SCBundle from provided parameters.

        :param source_b64: The base 64 encoded source code of the contract.
        :param signature: The signature of the b64 source code by the emitter.
        :param emitter_id: The node that emits that bundle.
        """
        self.id = crypto.get_hash()
        self.source_b64 = source_b64
        self.signature = signature
        self.emitter_id = emitter_id

    def verify(self, public_key_getter):
        """Verifies signature of this smart contract bundle.

        :param public_key_getter: Callable return a public key from a node id.
        :type public_key_getter: callable
        :return True if the bundle is authentic, False otherwise.
        :rtype: bool
        """
        public_key = public_key_getter(self.emitter_id)
        return crypto.verify(self.source_b64, self.signature, public_key)

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        return cls(json_dct['source_b64'], json_dct['signature'],
                   json_dct['emitter_id'])

    def __eq__(self, other):
        return isinstance(other, SCBundle) and all(
            (self.id == other.id,
             self.source_b64 == other.source_b64,
             self.signature == other.signature,
             self.emitter_id == other.emitter_id)
        )


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

    def sign(self, payload):
        """Signs any payload.

        :param payload: The payload to sign.
        :type payload: str
        :return: The resulting signature
        :rtype: str
        """
        return crypto.sign(payload, self.private_key, self.id)


class CashingNode(Node):
    """Stands for a node accumulating non redistributed fees before sharing
    them with the community."""


class TrustedNode(Node):
    """Stands for a trusted authority allowed to deliver certificates."""

    def deliver_certificate_for(self, node_id):
        """Creates and returns a certificate to assert that provided node is
        trusted.

        :param node_id: Id of the node that requires the certificate.
        :type node_id: str
        :return: The generated certificate for the provided node.
        :rtype: str
        """
        return self.sign(node_id)


class ConsumerNode(Node):
    """Stands for a node who is using the blockchain, creating transactions
    and consuming assets.
    """

    def sign_transaction(self, transaction_content):
        """Signs the provided transaction with this node's private key.

        :param transaction_content: the transaction to sign.
        :type transaction_content: TransactionContent
        :return: The resulting signature
        :rtype: str
        """
        return self.sign(transaction_content.to_json())

    def sign_block(self, block_header):
        """Signs the provided block header with this node's private key.

        :param block_header: the header of the block to sign.
        :type block_header: BlockHeader
        :return: The resulting signature
        :rtype: str
        """
        return self.sign(block_header.to_json())

    def create_sc_bundle(self, source_code):
        """Creates a SCBundle encapsulating provided contract.

        The bundle will be signed by this node.

        :param source_code: The smart contract code to include.
        :return: The generated bundle, ready to be sent to a master node.
        :rtype: SCBundle
        """
        source_b64 = crypto.base64_encode(source_code)
        return SCBundle(source_b64, self.sign(source_b64), self.id)

    def _package_transaction_content(self, tx_content):
        """Creates a Transaction out of provided transaction content.

        :param tx_content: The content to wrap
        :type tx_content: TransactionContent
        :return: The created Transaction
        :rtype: Transaction
        """
        return Transaction(tx_content, self.sign_transaction(tx_content))

    def create_transaction(self, recipient_id, amount, tx_type=TYPE_TX):
        """Creates a transaction from this node to another and signs it.

        The resulting transaction is ready t be sent to a master node to get a
            stamp.

        :param recipient_id: The recipient of this transaction.
        :type: str
        :param amount: The amount to send.
        :type: float
        :param tx_type: Optional. Overrides default transaction type.
        :type tx_type: str
        :return: a Transaction signed by this node.
        :rtype: Transaction
        """
        return self._package_transaction_content(
            TransactionContent(
                sender_id=self.id,
                recipient_id=recipient_id,
                amount=amount,
                tx_type=tx_type
            )
        )

    def create_sc_submit_transaction(self, amount, certificate, source_b64):
        """Creates a contract submission transaction for provided contract.

        The resulting transaction is ready t be sent to a master node to get a
            stamp.

        :param amount: The amount to send to pay for the contract
        :type: float
        :param certificate: The certificate required to submit the contract.
        :type: str
        :param source_b64: The code source of the contract, base64 encoded.
        :type source_b64: str
        :return: a Transaction signed by this node.
        :rtype: Transaction
        """
        content = ContractSubmissionContent(
            sender_id=self.id,
            recipient_id="",
            amount=amount,
            certificate=certificate,
            source_b64=source_b64
        )
        content.recipient_id = self.context.poll_master_node_id(content.tx_id)
        return self._package_transaction_content(content)

    def create_sc_invoke_transaction(self, amount, sc_id, abi_call):
        """Creates a contract invocation transaction for provided contract.

        The resulting transaction is ready t be sent to a master node to get a
            stamp.

        :param amount: The amount to send to pay for the contract
        :type: float
        :param sc_id: The id of the contract to execute.
        :type: str
        :param abi_call: The encoded call using contract ABI.
        :type abi_call: str
        :return: a Transaction signed by this node.
        :rtype: Transaction
        """
        content = ContractInvocationContent(
            sender_id=self.id,
            recipient_id="",
            amount=amount,
            sc_id=sc_id,
            abi_call=abi_call
        )
        content.recipient_id = self.context.poll_master_node_id(content.tx_id)
        return self._package_transaction_content(content)


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
            Transaction.from_json,
        )
        self._blockchain = Chain(
            os.path.join(self.node_folder, 'blocks'),
            Block.from_json,
        )
        self.sc_env = SCEnvironment(
            os.path.join(self.node_folder, 'smart-contracts')
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

    def _all_transactions(self):
        """Returns a generator over all transactions known by this node.

        The first group contains the current stacked transactions. The
        following ones are the blocks ones, starting by the most recent one.

        :rtype: iterable[list[Transaction]]
        """
        block_transactions = (
            block.transactions
            for block in reversed(self._blockchain)
        )
        return itertools.chain(self._tx_stack, *block_transactions)

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
        for tx_group in self._all_transactions():
            amount -= self._find_funds(list(tx_group), sender_id, amount)
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
        chosen_hash = self.context.poll_master_node_id(block_seed)
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
        return (
                self._create_cashbacks_transactions(cashbacks) +
                [self._create_cashing_transaction(cashing)]
        )

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
        return (
                base_transactions +
                [self._create_fees_collection_transaction(base_transactions)] +
                self._create_return_transactions(base_transactions, block_seed)
        )

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
                total_amount = content.amount + stamp.fees
                if self._provokes_overdraft(content.sender_id, total_amount):
                    raise Exception('Sender does not have sufficient funds.')

            # Check if content has to be somehow processed.
            return_value = self.process_transaction_content(content)
            transaction.stamp = stamp
            self._logger.info(transaction)
            self._tx_stack.push(transaction)
            return return_value or ''
        except Exception as e:
            self._logger.error('Transaction rejected: {}'.format(str(e)))

    def commit_transaction(self, transaction):
        """Saves and broadcast provided transaction among all masternodes.

        :param transaction: The transaction to save then broadcast.
        :type transaction: Transaction
        """
        self.receive_transaction(transaction)
        self.context.broadcast_transaction_to_masters(self.id, transaction)

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

    def _verify_certificate(self, certificate, certified_id, trusted_id):
        """Checks that provided certificate is authentic.

        :param certificate: Certificate to verify authenticity for.
        :type certificate: str
        :param certified_id: Id of node certified by the certificate.
        :type certified_id: str
        :param trusted_id: Id of trusted node delivering the certificate.
        :type trusted_id: str
        :return: True if the certificate is authentic.
        :rtype: bool
        """
        return crypto.verify(certified_id, certificate,
                             self.get_public_key(trusted_id))

    def get_sc_submit_quotation(self, bundle):
        """Obtains a quotation for submitting contract embedded into provided
        bundle.

        :param bundle: The bundle to give a quotation for.
        :type bundle: SCBundle
        :return: the quotation
        :rtype: Quotation
        """
        self._logger.info('SC submit quotation requested...')
        if not bundle.verify(self.context.get_public_key):
            raise Exception('Failed to verify SC bundle {}'.format(bundle.id))
        source = crypto.base64_decode(bundle.source_b64)
        return quotations.get_submit_quotation(source)

    def get_sc_invoke_quotation(self, sc_id, invoker_id, endpoint_name):
        """Obtains a quotation for executing contract represented by its id.

        :param sc_id: The contract id to quet a quotation for.
        :type sc_id: str
        :param invoker_id: Id of Node requesting invocation.
        :type invoker_id: str
        :param endpoint_name: Name of executed endpoint.
        :type endpoint_name: str
        :return: the quotation
        :rtype: Quotation
        """
        self._logger.info('SC invoke quotation requested...')
        if not self.sc_env.is_execution_granted(sc_id, invoker_id):
            raise ValueError(
                '{} is not allowed to execute {}'.format(invoker_id, sc_id)
            )
        bin_path = self.sc_env.get_bin(sc_id)
        return quotations.get_exec_quotation(bin_path, endpoint_name)

    def get_contract_abi(self, sc_id):
        """Obtains ABI for provided smart contract id.

        :param sc_id: Id of the contract to retrieve interface for.
        :type sc_id: str
        :return: The contract interface, if any.
        :rtype: ContractInterface
        """
        self._logger.info('SC ABI requested...')
        return self.sc_env.get_abi(sc_id)

    def process_transaction_content(self, tx_content):
        """Checks if provided transaction content requires further process. If
        it is the case, the content is processed.

        :param tx_content: TransactionContent to process.
        :type tx_content: TransactionContent
        """
        if isinstance(tx_content, ContractSubmissionContent):
            self.process_sc_submission(tx_content)
        if isinstance(tx_content, ContractInvocationContent):
            return self.process_sc_invocation(tx_content)
        if isinstance(tx_content, ContractExecutionContent):
            self.sc_env.cache_last_exec(tx_content.sc_id, tx_content.exec_info)

    def _create_sc_exec_transaction(self, sc_id, exec_info):
        """Creates a contract execution transaction for provided contract.

        The resulting transaction is ready t be sent to a master node to get a
            stamp.

        :param sc_id: The id of the executed contract.
        :type: str
        :param exec_info: The resulting executionInfo
        :type exec_info: ExecutionInfo
        :return: a Transaction signed by this node.
        :rtype: Transaction
        """
        return self._package_transaction_content(
            ContractExecutionContent(sender_id=self.id, sc_id=sc_id,
                                     exec_info=exec_info)
        )

    @staticmethod
    def _find_exec_info(transactions, sc_id):
        """Look in the provded transaction list to find an execution of
        provided contract.

        :param transactions: List of transactions to browse.
        :type transactions: iterable[Transaction]
        :param sc_id: id of searched contract.
        :type sc_id: str
        :return: The execution info found, None otherwise.
        :rtype: ExecutionInfo
        """
        for tx in reversed(transactions):
            if isinstance(tx.content, ContractExecutionContent) \
                    and tx.content.sc_id == sc_id:
                return tx.content.exec_info
            if isinstance(tx.content, ContractSubmissionContent) \
                    and tx.content.tx_id == sc_id:
                raise StopIteration()
        return None

    def _get_last_exec_info(self, sc_id):
        """Look for the past transactions to find an execution of provided
        contract.

        :param sc_id: id of searched contract.
        :type sc_id: str
        :return: The execution info found, None otherwise.
        :rtype: ExecutionInfo
        """
        # Ask the SC environment in case the last execution is cached.
        last_exec = self.sc_env.get_last_exec_in_cache(sc_id)
        if last_exec:
            return last_exec

        try:
            for tx_group in self._all_transactions():
                exec_info = self._find_exec_info(list(tx_group), sc_id)
                if exec_info:
                    return exec_info
        except StopIteration:
            pass
        return None

    def process_sc_submission(self, tx_content):
        """Saves provided Smart Contract into the ledger.

        :param tx_content: The invocation content.
        :type tx_content: ContractSubmissionContent
        :return: The resulting call info, as an encoded string.
        :rtype: str
        """
        self.sc_env.add(tx_content.tx_id, tx_content.source_b64)
        # If this node is the recipient, create another transaction to transfer
        # funds to a cashingnode.
        if tx_content.recipient_id == self.id:
            tx = self._create_cashing_transaction(tx_content.amount)
            self.commit_transaction(tx)

    def process_sc_invocation(self, tx_content):
        """Executes provided smart contract invcation request.

        :param tx_content: The invocation content.
        :type tx_content: ContractInvocationContent
        :return: The resulting call info, as an encoded string.
        :rtype: str
        """
        self._logger.info('SC execution requested...')
        # Only execute contract if this node is the invokee.
        if tx_content.recipient_id != self.id:
            return

        # Decode endpoint and arguments
        sc_id = tx_content.sc_id
        sc_interface = self.sc_env.get_abi(sc_id)
        sc_abi = abi.ABI(sc_interface)
        endpoint, kwargs = sc_abi.decode_call(tx_content.abi_call)

        # Invoke the contract, providing the last execution to reload storage
        # vars.
        exec_info = invoke(self.sc_env.bin_folder, self.sc_env.abi_folder,
                           self._get_last_exec_info(sc_id), sc_id, endpoint,
                           kwargs)

        # Check if invocation failed at execution level (not normal)
        # If it fails at call level, it is probably because of the user code.
        if not exec_info.success_info.is_success:
            self._logger.error(
                "SC execution failed for contract {}. Error: {}".format(
                    sc_id, exec_info.success_info.error
                )
            )
            raise RuntimeError(
                "An unknown error occured while execution the contract {}. "
                "Please contact the team.".format(sc_id)
            )

        # Create a transaction with the result and propagate it.
        tx_exec = self._create_sc_exec_transaction(sc_id, exec_info)
        self.commit_transaction(tx_exec)

        # Encode and return the call info in that case.
        return sc_abi.encode_call_result(exec_info.call_info)
