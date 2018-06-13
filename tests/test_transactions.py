import unittest

from mock import patch

import pikciopou.transactions as transactions


class TestTransactionContent(unittest.TestCase):
    """Tests the TransactionContent class."""

    def setUp(self):
        self.tx_content = transactions.TransactionContent(
            'sender', 'recipient', 1234, transactions.TYPE_TX, 1, "hash",
        )

    def test_emissions_time_default_is_now(self):
        self.assertEqual(self.tx_content.emission_time, 1)

    @patch('pikciopou.transactions.crypto')
    def test_transaction_id_gets_defined_if_missing(self, crypto_mock):
        transactions.TransactionContent('sender', 'recipient', 1)
        crypto_mock.get_hash_assert_called_once_with(None)

    def test_compute_fees_applies_rate_only_for_regular_ones(self):
        self.assertEqual(
            self.tx_content.compute_fees(0.1),
            0.1 * self.tx_content.amount
        )
        for tx_type in (
                transactions.TYPE_CASHBACK,
                transactions.TYPE_CASHING,
                transactions.TYPE_TX_FEES,
                transactions.TYPE_GENESIS
        ):
            self.tx_content.type = tx_type
            self.assertEqual(self.tx_content.compute_fees(0.1), 0)

    def test_to_json_returns_valid_json(self):
        self.assertEqual(
            self.tx_content.to_json(),
            '{"tx_id": "hash", "type": "PKC", "sender_id": "sender", '
            '"recipient_id": "recipient", "amount": 1234, "emission_time": 1}'
        )

    def test_from_json_returns_original(self):
        content_2 = transactions.TransactionContent.from_json(
            self.tx_content.to_json()
        )
        self.assertDictEqual(self.tx_content.__dict__, content_2.__dict__)

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(transactions.TransactionContent.from_json(""))
        self.assertIsNone(transactions.TransactionContent.from_json("qdsfdh"))

    def test_from_dict_returns_none_if_missing_attribute(self):
        self.assertIsNone(transactions.TransactionContent.from_dict({
            'sender_id': '2',
            'recipient_id': '1',
            'amount': 1234,
        }))

    def test_str_is_implemented(self):
        str(self.tx_content)


class TestTransactionStamp(unittest.TestCase):
    """Tests the TransactionStamp class."""

    def setUp(self):
        self.stamp = transactions.TransactionStamp(30, "master_id", 1)

    def test_to_json_returns_valid_json(self):
        self.assertEqual(
            self.stamp.to_json(),
            '{"processing_time": 1, "fees": 30, '
            '"master_id": "master_id"}'
        )

    def test_from_json_returns_original(self):
        stamp_2 = transactions.TransactionStamp.from_json(self.stamp.to_json())
        self.assertDictEqual(self.stamp.__dict__, stamp_2.__dict__)

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(transactions.TransactionStamp.from_json(""))
        self.assertIsNone(transactions.TransactionStamp.from_json(None))
        self.assertIsNone(transactions.TransactionStamp.from_json("qdsfdhgrh"))

    def test_from_dict_returns_none_if_missing_attribute(self):
        self.assertIsNone(transactions.TransactionStamp.from_dict({
            'fees': 30,
            "master_id": "master"
        }))

    def test_str_is_implemented(self):
        str(self.stamp)


class TestTransaction(unittest.TestCase):
    """Tests the Block class."""

    def setUp(self):
        self.tx = transactions.Transaction(
            transactions.TransactionContent(
                'from', 'to', 300, transactions.TYPE_TX, 12, 'master_id'
            ),
            'signature',
            transactions.TransactionStamp(30, '10', 12)
        )

    def test_delta_for_returns_right_amount(self):
        self.assertEqual(self.tx.delta_for("from"), -330)
        self.assertEqual(self.tx.delta_for("to"), 300)
        self.assertEqual(self.tx.delta_for("other"), 0)

    def test_to_json_returns_valid_json(self):
        self.assertEqual(
            self.tx.to_json(),
            '{"signature": "signature", "tx_id": "master_id", "type": "PKC", '
            '"sender_id": "from", "recipient_id": "to", "amount": 300, '
            '"emission_time": 12, "processing_time": 12, "fees": 30, '
            '"master_id": "10"}'
        )

    def test_from_json_returns_original(self):
        tx_2 = transactions.Transaction.from_json(self.tx.to_json())
        self.assertEqual(self.tx.signature, tx_2.signature)
        self.assertDictEqual(
            self.tx.content.__dict__, tx_2.content.__dict__
        )
        self.assertDictEqual(
            self.tx.stamp.__dict__, tx_2.stamp.__dict__
        )

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(transactions.Transaction.from_json(""))
        self.assertIsNone(transactions.Transaction.from_json("qdsfdhgrfh"))

    def test_from_dict_returns_none_in_case_of_missing_signature(self):
        self.assertIsNone(transactions.Transaction.from_json(
            '{"tx_id": "master_id", "type": "PKC", '
            '"sender_id": "from", "recipient_id": "to", "amount": 300, '
            '"emission_time": 12, "processing_time": 12, "fees": 30, '
            '"net_amount": 270, "master_id": "10"}'
        ))

    @patch('pikciopou.transactions.crypto')
    def test_verify_calls_crypto(self, crypto_mock):
        crypto_mock.verify.return_value = True

        self.tx.verify("key")

        crypto_mock.verify.assert_called_once_with(
            self.tx.content.to_json(), self.tx.signature, "key"
        )

    def test_verify_rejects_unsigned_transactions(self):
        self.tx.signature = None
        with self.assertRaises(Exception):
            self.tx.verify("key")

    @patch('pikciopou.transactions.crypto')
    def test_verify_signature_rejects_invalid_signature(self, crypto_mock):
        crypto_mock.verify.return_value = False
        with self.assertRaises(Exception):
            self.tx.verify("key")

    def test_str_is_implemented(self):
        str(self.tx)
