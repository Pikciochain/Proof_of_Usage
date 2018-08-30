"""Contains all transaction related features."""
from datetime import datetime

from pikciosc.models import ExecutionInfo

from pikciopou import crypto
from pikciopou.serialization import JSONSerializable

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

TYPE_SC_SUBMIT = "PKC-SC-Submit"
"""Transaction used to submit a smart contract to the ledger."""
TYPE_SC_INVOKE = "PKC-SC-Invoke"
"""Transaction used to invoke a smart contract."""
TYPE_SC_EXEC = "PKC-SC-Exec"
"""Transaction used to detail a smart contract execution."""


class MetaTXContent(type):
    """Metaclass used to register real type to perform JSON deserialisation of
    a transaction content."""

    TxTypeToTypeMapping = {}

    def __new__(mcs, name, bases, attrs):
        # Special case: do not register the base class to avoid infinite loop.
        if name == 'TransactionContent':
            return super().__new__(mcs, name, bases, attrs)

        # Sub classes must define a specific type.
        if 'TX_TYPE' not in attrs:
            raise AttributeError('TX_TYPE attribute is required'
                                 ' in class {}'.format(name))
        cls = super().__new__(mcs, name, bases, attrs)
        mcs.TxTypeToTypeMapping[attrs['TX_TYPE']] = cls
        return cls


class TransactionContent(JSONSerializable, metaclass=MetaTXContent):
    """The transaction core, without signature or the validation details"""

    def __init__(self, sender_id, recipient_id, amount, tx_type=TYPE_TX,
                 tx_time=None, tx_id=None):
        """Creates a new TransactionContent with provided parameters.

        :param sender_id: The id of the node sending the transaction.
        :type sender_id: str
        :param recipient_id: The id of the node receiving the transaction.
        :type recipient_id: str
        :param amount: The amount of transferred money.
        :type amount: float
        :param tx_type: Meaning of the transaction.
        :type tx_type: str
        :param tx_time: Timestamp of the emission.
        :type tx_time: float
        :param tx_id: Id of the created transaction.
        :type tx_id: str
        """
        self.tx_id = tx_id or crypto.get_hash()
        self.type = tx_type
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.amount = amount
        self.emission_time = tx_time or datetime.utcnow().timestamp()

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        subcls = MetaTXContent.TxTypeToTypeMapping.get(json_dct['type'])
        return (
            subcls.from_dict_unsecure(json_dct) if subcls else
            cls(json_dct['sender_id'], json_dct['recipient_id'],
                json_dct['amount'], json_dct['type'],
                json_dct['emission_time'], json_dct['tx_id'])
        )

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


class ContractSubmissionContent(TransactionContent):
    """Stands for a transaction submitting a smart contract to the ledger."""

    TX_TYPE = TYPE_SC_SUBMIT

    def __init__(self, sender_id, recipient_id, amount, certificate,
                 source_b64, tx_time=None, tx_id=None):
        """Creates a new ContractSubmissionContent with provided parameters.

        :param sender_id: The id of the node sending the transaction.
        :type sender_id: str
        :param recipient_id: The id of the node receiving the transaction.
        :type recipient_id: str
        :param amount: The amount of fees. Must be the result of a quotation.
        :type amount: float
        :param certificate: Certificate required to submit a contract.
        :type certificate: str
        :param source_b64: Source code for the contract, encoded in base 64.
        :type source_b64: str
        :param tx_time: Timestamp of the emission.
        :type tx_time: float
        :param tx_id: Id of the created transaction.
        :type tx_id: str
        """
        super().__init__(sender_id, recipient_id, amount, self.TX_TYPE,
                         tx_time, tx_id)
        self.source_b64 = source_b64
        self.certificate = certificate

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        return cls(json_dct['sender_id'], json_dct['recipient_id'],
                   json_dct['amount'], json_dct['certificate'],
                   json_dct['source_b64'], json_dct['emission_time'],
                   json_dct['tx_id'])


class ContractInvocationContent(TransactionContent):
    """Stands for a transaction requesting execution of a smart contract."""

    TX_TYPE = TYPE_SC_INVOKE

    def __init__(self, sender_id, recipient_id, amount, sc_id, abi_call,
                 tx_time=None, tx_id=None):
        """Creates a new ContractInvocationContent with provided parameters.

        :param sender_id: The id of the node sending the transaction.
        :type sender_id: str
        :param recipient_id: The id of the node receiving the transaction.
        :type recipient_id: str
        :param amount: The amount of fees. Must be the result of a quotation.
        :type amount: float
        :param sc_id: Id of invoked contract.
        :type sc_id: str
        :param abi_call: Encoded call using contract ABI.
        :type abi_call: str
        :param tx_time: Timestamp of the emission.
        :type tx_time: float
        :param tx_id: Id of the created transaction.
        :type tx_id: str
        """
        super().__init__(sender_id, recipient_id, amount, self.TX_TYPE,
                         tx_time, tx_id)
        self.sc_id = sc_id
        self.abi_call = abi_call

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        return cls(json_dct['sender_id'], json_dct['recipient_id'],
                   json_dct['amount'], json_dct['sc_id'],
                   json_dct['abi_call'], json_dct['emission_time'],
                   json_dct['tx_id'])


class ContractExecutionContent(TransactionContent):
    """Stands for a transaction detailing execution of a smart contract."""

    TX_TYPE = TYPE_SC_EXEC

    def __init__(self, sender_id, sc_id, exec_info, tx_time=None, tx_id=None):
        """Creates a new ContractExecutionContent with provided parameters.

        :param sender_id: The id of the node sending the transaction.
        :type sender_id: str
        :param sc_id: Id of invoked contract.
        :type sc_id: str
        :param exec_info: The detail of the contract execution.
        :type exec_info: ExecutionInfo
        :param tx_time: Timestamp of the emission.
        :type tx_time: float
        :param tx_id: Id of the created transaction.
        :type tx_id: str
        """
        super().__init__(sender_id, sender_id, 0, self.TX_TYPE, tx_time, tx_id)
        self.sc_id = sc_id
        self.exec_info = exec_info

    def to_dict(self):
        """ExecutionInfo has its serialization and must be done separately."""
        exec_info_json = self.exec_info.to_dict()
        return {
            key: val if key != 'exec_info' else exec_info_json
            for key, val in super().to_dict().items()
        }

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        exec_info = ExecutionInfo.from_dict(json_dct['exec_info'])
        return cls(json_dct['sender_id'], json_dct['sc_id'], exec_info,
                   json_dct['emission_time'], json_dct['tx_id'])


class TransactionStamp(JSONSerializable):
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

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        return cls(json_dct['fees'], json_dct['master_id'],
                   json_dct['processing_time'])

    def __str__(self):
        """Pretty print of a transaction stamp."""
        return '(fees: {:.3f}), stamped by {}... at {}'.format(
            self.fees,
            self.master_id[:8],
            datetime.fromtimestamp(self.processing_time).strftime('%H:%M:%S')
        )


class Transaction(JSONSerializable):
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

    @classmethod
    def from_dict_unsecure(cls, json_dct):
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
