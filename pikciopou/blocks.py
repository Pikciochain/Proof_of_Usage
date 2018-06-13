"""Contains all block related features."""
import json
from datetime import datetime

from pikciopou import crypto
from pikciopou.transactions import Transaction, TYPE_CASHBACK, \
    TYPE_CASHING, TYPE_TX


class BlockHeader(object):
    """The part of the block that is signed by the master node creating it."""

    def __init__(self, retribution_rate, previous_block_hash, merkle_root,
                 closing_time=None):
        """Creates a new BlockContent for provided transactions.

        :param retribution_rate: Percentage of the transaction fees that is
            kept by the master node as a compensation.
        :type retribution_rate: float
        :param previous_block_hash: Hash of the previous block.
        :type previous_block_hash: str
        :param merkle_root: SHA256 of previous block and transactions ordered
            by id.
        :type merkle_root: str
        :param closing_time: The time at which this block was closed.
        :type closing_time: datetime
        """
        self.retribution_rate = retribution_rate
        self.previous_block_hash = previous_block_hash
        self.merkle_root = merkle_root
        self.closing_time = closing_time or datetime.utcnow().timestamp()

    def to_json(self):
        """Provides a JSON representation of this block header."""
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_stamp):
        """Creates a new TransactionStamp from provided JSON string."""
        try:
            return cls.from_dict(json.loads(json_stamp))
        except (TypeError, json.JSONDecodeError):
            return None

    @classmethod
    def from_dict(cls, json_dct):
        try:
            return cls(
                json_dct['retribution_rate'],
                json_dct['previous_block_hash'],
                json_dct['merkle_root'],
                json_dct['closing_time'],
            )
        except KeyError:
            return None

    def __str__(self):
        """Pretty print of a block header."""
        return 'merkle: {}... at {}'.format(
            self.merkle_root[:8],
            datetime.fromtimestamp(self.closing_time).strftime('%H:%M:%S')
        )


class BlockStamp(object):
    """Stands for the security details a master node adds to a Block while
    closing it.
    """

    def __init__(self, master_id, master_signature, lucky_signatures=None):
        """Creates a new BlockStamp to add security details to a Transaction.

        :param master_id: Id of master closing this block.
        :type master_id: str
        :param master_signature: Signature of the BlockHeader by this master.
        :type master_signature: str
        :param lucky_signatures: Signature of BlockHeader by every lucky
            stakeholder. It should be a dict: node_id -> SHA256.
        :type lucky_signatures: dict[str,str]
        """
        self.master_id = master_id
        self.master_signature = master_signature
        self.lucky_signatures = lucky_signatures

    def to_json(self):
        """Provides a JSON representation of this block header."""
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_stamp):
        """Creates a new TransactionStamp from provided JSON string."""
        try:
            return cls.from_dict(json.loads(json_stamp))
        except (TypeError, json.JSONDecodeError):
            return None

    @classmethod
    def from_dict(cls, json_dct):
        try:
            return cls(
                json_dct['master_id'],
                json_dct['master_signature'],
                json_dct['lucky_signatures'],
            )
        except KeyError:
            return None

    def __str__(self):
        """Pretty print of a block header."""
        return 'Signed by: {}... - {}'.format(
            self.master_id[:8],
            'approved by stakeholders' if self.lucky_signatures else ''
        )


class Block(object):
    """Stands for a block in a blockchain, a set of transactions
    validated once for all.
    """

    def __init__(self, transactions, block_header=None, block_stamp=None):
        """Creates a new block containing specified transactions.

        :param transactions: The transactions sealed in this block.
        :type transactions: list[Transaction]
        :param block_header: Details ofthe closure: time and merkle root.
        :type block_header: BlockHeader
        :param block_stamp: Security and verification details of this block.
        :type block_stamp: BlockStamp
        """
        self.header = block_header
        self.transactions = transactions
        self.stamp = block_stamp

    def _compute_merkle_root(self, previous_block_hash):
        """Computes the merkle root of this block based on the sorted
        transactions.

        :param previous_block_hash: Hash of the previous block.
        :type previous_block_hash: str
        :return: Th merkle root hash.
        """
        sorted_tx = sorted(self.transactions)
        all_hashes = (
            (previous_block_hash,) +
            tuple(crypto.get_hash(tx.to_json()) for tx in sorted_tx)
        )
        return crypto.get_hash(''.join(all_hashes))

    def close(self, retribution_rate, previous_block_hash):
        """Closes this block. Merkle root and closure time are set.

        :param retribution_rate: Percentage of the transaction fees that is
            kept by the master node as a compensation.
        :type retribution_rate: float
        :param previous_block_hash: Hash of the previous block.
        :type previous_block_hash: str
        :return: The block itself.
        :rtype: Block
        """
        self.header = BlockHeader(
            retribution_rate,
            previous_block_hash,
            self._compute_merkle_root(previous_block_hash)
        )
        return self

    def _verify_signature(self, signature, public_key):
        """Verifies one signature of this block's header.

        :param signature: The signature to verify.
        :type signature: str
        :param public_key: The public key used to verify the signature.
        :type public_key: str
        :return: True if the signature matched the header and the public key.
        :rtype: bool
        """
        return crypto.verify(self.header.to_json(), signature, public_key)

    def _transactions_of_type(self, *tx_types):
        """Retrieves all transactions in this block with the specified type(s).

        :param tx_types: The type(s) of transactions to fetch.
        :type tx_types: tuple[str]
        :return: A generator on the filtered transactions
        :rtype: iterable[Transaction]
        """
        return (tx for tx in self.transactions if tx.content.type in tx_types)

    def verify(self, public_key_getter):
        """Checks that this block is authentic and has been signed by its
        sender.

        :param public_key_getter: A function that can be called with a node id
            to get its public key.
        :type public_key_getter: callable
        """
        if not self.stamp:
            raise Exception("Block stamp is missing.")
        if not self.header:
            raise Exception("Block header is missing.")
        prev_hash = self.header.previous_block_hash
        if self._compute_merkle_root(prev_hash) != self.header.merkle_root:
            raise Exception("Merkle tree verification failed.")

        master_key = public_key_getter(self.stamp.master_id)
        if not self._verify_signature(self.stamp.master_signature, master_key):
            raise Exception("Master signature does not match header.")

        for node_id, signature in self.stamp.lucky_signatures.items():
            public_key = public_key_getter(node_id)
            if not self._verify_signature(signature, public_key):
                raise Exception("Stakeholder signature does not match header.")

    @property
    def lucky_stakeholders(self):
        """Gets the list of lucky stakeholders who received transaction fees
        in return.

        :return: The list of all stakeholders ids.
        :rtype: list[str]
        """
        return [
            tx.content.recipient_id
            for tx in self._transactions_of_type(TYPE_CASHBACK)
        ]

    @property
    def regular_transactions(self):
        """Gets the normal transactions (not cashback, cashing, fees...) of
        this block
        """
        return [tx for tx in self._transactions_of_type(TYPE_TX)]

    @property
    def cashing_transactions(self):
        """Gets the cashing transactions of this block"""
        return [tx for tx in self._transactions_of_type(TYPE_CASHING)]

    @property
    def cashback_transactions(self):
        """Gets the cashback transactions of this block"""
        return [tx for tx in self._transactions_of_type(TYPE_CASHBACK)]

    @property
    def cashback_amount(self):
        """Returns the total amount of cashback returned by this block."""
        return sum(tx.content.amount for tx in self.cashback_transactions)

    @property
    def cashing_amount(self):
        """Returns the total amount of cashing returned by this block."""
        return sum(tx.content.amount for tx in self.cashing_transactions)

    def to_json(self):
        """Provides a JSON representation of this block."""
        dct = {
            'transactions': [tx.to_dict() for tx in self.transactions],
            'tx_count': len(self.transactions)
        }
        if self.header:
            dct.update(self.header.__dict__)
        if self.stamp:
            dct.update(self.stamp.__dict__)
        return json.dumps(dct)

    @classmethod
    def from_json(cls, json_block):
        """Creates a new Block from provided JSON string.

        :param json_block: The dictionary covering the fields of this object.
        :type json_block: str
        """
        try:
            json_dct = json.loads(json_block)
        except (TypeError, json.JSONDecodeError):
            return None

        try:
            transactions = [
                Transaction.from_dict(tx_json)
                for tx_json in json_dct['transactions']
            ]
        except KeyError:
            return None

        header = BlockHeader.from_dict(json_dct)
        stamp = BlockStamp.from_dict(json_dct)
        return cls(transactions, header, stamp)

    def __str__(self):
        """Pretty print of a block."""
        return 'Block of {} transactions ({}) - {}'.format(
            len(self.transactions),
            str(self.header),
            str(self.stamp)
        )
