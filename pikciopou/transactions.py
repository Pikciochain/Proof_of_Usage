"""Contains all transaction related features."""
import json
from datetime import datetime
from json import JSONDecodeError

from pikciopou import crypto

TYPE_TX = 'PKC'
"""Normal transaction."""
TYPE_GENESIS = 'PKC-Genesis'
"""First transaction ever. Allowed to 'create' assets and not taxable."""
TYPE_TX_FEES = 'PKC-TX-Fees'
"""Transaction emitted by a master node closing a block to collect fees."""
TYPE_CASHBACK = 'PKC-Cashback'
"""Transaction emitted by a master node closing a block to redistribute
part of the collected fees.
"""
TYPE_CASHING = 'PKC-Cashing'
"""Transaction emitted by a master node closing a block to save money not
redistributed to stakeholders.
"""


class TransactionContent(object):
    """The transaction core, without signature or the validation details"""

    def __init__(self, sender_id, recipient_id, amount, tx_type=TYPE_TX,
                 tx_time=None, tx_id=None):
        self.tx_id = tx_id or crypto.get_hash()
        self.type = tx_type
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.amount = amount
        self.emission_time = tx_time or datetime.utcnow().timestamp()

    def to_json(self):
        """Provides a JSON representation of this transaction content."""
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_content):
        """Creates a new TransactionContent from provided JSON string.

        :param json_content: The JSON version of a TransactionContent.
        :type json_content: str
        """
        try:
            return cls.from_dict(json.loads(json_content))
        except (TypeError, JSONDecodeError):
            return None

    @classmethod
    def from_dict(cls, json_dct):
        try:
            return cls(
                json_dct['sender_id'],
                json_dct['recipient_id'],
                json_dct['amount'],
                json_dct['type'],
                json_dct['emission_time'],
                json_dct['tx_id']
            )
        except KeyError:
            return None

    def __str__(self):
        """Pretty print of a transaction content."""
        return '{}...: {:.3f} {} from {}... to {}... at {}'.format(
            self.tx_id[:8],
            self.amount,
            self.type,
            self.sender_id[:8],
            self.recipient_id[:8],
            datetime.fromtimestamp(self.emission_time).strftime('%H:%M:%S')
        )

    def compute_fees(self, fees_rate):
        """Computes amount of fees, depending on transaction type and fees
        rate.

        :param fees_rate: The percentage of the gross amount that has to be
        taken as fees.
        :return: The fees amount.
        :rtype: float
        """
        return 0 if self.type != TYPE_TX else fees_rate * self.amount


class TransactionStamp(object):
    """The seal appended by a master node to a transaction."""

    def __init__(self, tx_fees, master_id, processing_time=None):
        """Creates a TransactionStamp containing details of the processing of a
        Transaction by a master.

        :param tx_fees: amount of fees to take fro mthe sender in addition to
            the transaction amount.
        :type tx_fees: float
        :param master_id: Id of master node stamping this transaction.
        :type master_id: str
        :param processing_time: timestamp when the stamp has been created.
        :type processing_time: int
        """
        self.processing_time = processing_time or datetime.utcnow().timestamp()
        self.fees = tx_fees
        self.master_id = master_id

    def to_json(self):
        """Provides a JSON representation of this transaction stamp."""
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_stamp):
        """Creates a new TransactionStamp from provided JSON string."""
        try:
            return cls.from_dict(json.loads(json_stamp))
        except (TypeError, JSONDecodeError):
            return None

    @classmethod
    def from_dict(cls, json_dct):
        try:
            return cls(
                json_dct['fees'],
                json_dct['master_id'],
                json_dct['processing_time'],
            )
        except KeyError:
            return None

    def __str__(self):
        """Pretty print of a transaction stamp."""
        return '(fees: {:.3f}), stamped by {}... at {}'.format(
            self.fees,
            self.master_id[:8],
            datetime.fromtimestamp(self.processing_time).strftime('%H:%M:%S')
        )


class Transaction(object):
    """Stands for a transaction assets between two nodes."""

    def __init__(self, tx_content=None, signature=None, stamp=None):
        """Creates a new Transaction.

        :param tx_content: The very details of the Transaction.
        :type tx_content: TransactionContent
        :param signature: The signature of the content by the sender
        :type signature: str
        :param stamp: The stamp appended by a master node on the transaction.
        :type stamp: TransactionStamp
        """
        self.content = tx_content
        self.signature = signature
        self.stamp = stamp

    @property
    def paid_amount(self):
        """Total paid amount: Transaction amount plus fees."""
        return self.content.amount + self.stamp.fees

    def delta_for(self, node_id):
        """Gets the quantity of assets that this transaction took from or gave
        to the provided node.

        :param node_id: The node to get the delta for.
        :type node_id: str
        :return: A positive amount if the node received the assets, a negative
            one if he spent it and 0 if he wasn't involved.
        :rtype: float
        """
        # The recipient receives the Transaction amount and the sender has to
        # pay the fees and the amount
        return (
            self.content.amount if self.content.recipient_id == node_id else
            -self.paid_amount if self.content.sender_id == node_id else 0
        )

    def to_dict(self):
        """Provides a dict representation of this Transaction."""
        dct = {'signature': self.signature}
        if self.content:
            dct.update(self.content.__dict__)
        if self.stamp:
            dct.update(self.stamp.__dict__)
        return dct

    def to_json(self):
        """Provides a JSON representation of this transaction."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, json_dct):
        """Creates a new Transaction from provided dict.

        :param json_dct: The dictionary covering the fields of this object.
        :type json_dct: dict
        """
        try:
            signature = json_dct['signature']
        except KeyError:
            return None

        content = TransactionContent.from_dict(json_dct)
        stamp = TransactionStamp.from_dict(json_dct)
        return cls(content, signature, stamp)

    @classmethod
    def from_json(cls, json_tx):
        """Creates a new Transaction from provided JSON string.

        :param json_tx: The dictionary covering the fields of this object.
        :type json_tx: str
        """
        try:
            json_dct = json.loads(json_tx)
        except JSONDecodeError:
            return None
        return cls.from_dict(json_dct)

    def __str__(self):
        """Pretty print of a transaction."""
        return 'TX-{} ({}) - {}'.format(
            self.content or 'empty',
            self.stamp or 'no stamp',
            'signed' if self.signature else 'unsigned'
        )

    def __lt__(self, other):
        """Implements lower than to support default sort.

        :param other: Another transaction to compare to this one.
        :type other: Transaction
        """
        return self.content.tx_id < other.content.tx_id

    def verify(self, public_key):
        """Checks that transaction is authentic and has been signed by its
        sender.

        :param public_key: The public_key of the supposedly sender.
        :type public_key: str
        """
        if not self.signature:
            raise Exception('Signature is missing.')
        tx_json = self.content.to_json()
        if not crypto.verify(tx_json, self.signature, public_key):
            raise Exception('Signature does not match content.')
