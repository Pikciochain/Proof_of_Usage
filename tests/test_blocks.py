import unittest

from mock import MagicMock, patch, call

from pikciopou.transactions import Transaction, TransactionContent, TYPE_TX, \
    TransactionStamp, TYPE_CASHBACK, TYPE_CASHING
import pikciopou.blocks as blocks


class TestBlockHeader(unittest.TestCase):
    """Tests the BlockHeader class."""

    def setUp(self):
        with patch('pikciopou.blocks.datetime') as dt_mock:
            dt_mock.utcnow().timestamp.return_value = 2018
            self.header = blocks.BlockHeader(0.1, '1', 'merkle')

    def test_closing_time_default_is_now(self):
        self.assertEqual(self.header.closing_time, 2018)

    def test_to_json_returns_valid_json(self):
        self.assertEqual(
            self.header.to_json(),
            '{"retribution_rate": 0.1, "previous_block_hash": "1",'
            ' "merkle_root": "merkle", "closing_time": 2018}'
        )

    def test_from_json_returns_original(self):
        header_2 = blocks.BlockHeader.from_json(self.header.to_json())
        self.assertEqual(self.header.closing_time, header_2.closing_time)
        self.assertEqual(
            self.header.retribution_rate,
            header_2.retribution_rate
        )
        self.assertEqual(self.header.merkle_root, header_2.merkle_root)

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(blocks.BlockHeader.from_json(""))
        self.assertIsNone(blocks.BlockHeader.from_json(None))
        self.assertIsNone(blocks.BlockHeader.from_json("qdsfdhgrfh"))

    def test_from_dict_returns_none_if_missing_attribute(self):
        self.assertIsNone(blocks.BlockHeader.from_dict({
            'retribution_rate': 0.1,
            'previous_block_hash': '1',
            'merkle_root': "ab"
        }))

    def test_str_is_implemented(self):
        str(self.header)


class TestBlockStamp(unittest.TestCase):
    """Tests the BlockStamp class."""

    def test_to_json_returns_valid_json(self):
        stamp = blocks.BlockStamp('1', 'sign', {'2': 'sign1', '3': 'sign2'})
        self.assertEqual(
            stamp.to_json(),
            '{"master_id": "1", "master_signature": "sign", '
            '"lucky_signatures": {"2": "sign1", "3": "sign2"}}'
        )

    def test_from_json_returns_original(self):
        stamp = blocks.BlockStamp('1', 'sign', {'2': 'sign1', '3': 'sign2'})
        stamp_2 = blocks.BlockStamp.from_json(stamp.to_json())
        self.assertEqual(stamp.master_id, stamp_2.master_id)
        self.assertEqual(stamp.master_signature, stamp_2.master_signature)
        self.assertDictEqual(stamp.lucky_signatures, stamp_2.lucky_signatures)

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(blocks.BlockStamp.from_json(""))
        self.assertIsNone(blocks.BlockStamp.from_json(None))
        self.assertIsNone(blocks.BlockStamp.from_json("qdsfdhgrfh"))

    def test_from_dict_returns_none_if_missing_attribute(self):
        self.assertIsNone(blocks.BlockStamp.from_dict({
            'master_id': '1',
            'master_signature': "ab"
        }))

    def test_str_is_implemented(self):
        stamp = blocks.BlockStamp('1', 'sign', {'2': 'sign1', '3': 'sign2'})
        str(stamp)


class TestBlock(unittest.TestCase):
    """Tests the Block class."""

    def setUp(self):
        with patch('pikciopou.blocks.datetime') as dt_mock:
            dt_mock.utcnow().timestamp.return_value = 12
            self.maxDiff = None
            transactions = [
                Transaction(
                    TransactionContent('1', '2', 100, TYPE_TX, 12, '1'),
                    'signature1',
                    TransactionStamp(10, '10', 12)
                ),
                Transaction(
                    TransactionContent('2', '3', 300, TYPE_TX, 12, '2'),
                    'signature2',
                    TransactionStamp(30, '10', 12)
                )
            ]
            stamp = blocks.BlockStamp('1', 'sign', {'2': 'sig1', '3': 'sig2'})
            header = blocks.BlockHeader(0.1, '1', 'merkle')
            self.block = blocks.Block(transactions, header, stamp)

    def test_to_json_returns_valid_json(self):
        self.assertEqual(
            self.block.to_json(),
            '{"transactions": [{"signature": "signature1", "tx_id": "1", '
            '"type": "PKC", "sender_id": "1", "recipient_id": "2", '
            '"amount": 100, "emission_time": 12, "processing_time": 12, '
            '"fees": 10, "master_id": "10"}, '
            '{"signature": "signature2", "tx_id": "2", "type": "PKC", '
            '"sender_id": "2", "recipient_id": "3", "amount": 300, '
            '"emission_time": 12, "processing_time": 12, "fees": 30, '
            '"master_id": "10"}], "tx_count": 2, '
            '"retribution_rate": 0.1, "previous_block_hash": "1", '
            '"merkle_root": "merkle", "closing_time": 12, "master_id": "1", '
            '"master_signature": "sign", "lucky_signatures": {"2": "sig1", '
            '"3": "sig2"}}'
        )

    def test_from_json_returns_original(self):
        block_2 = blocks.Block.from_json(self.block.to_json())
        self.assertEqual(
            len(self.block.transactions),
            len(block_2.transactions)
        )
        self.assertDictEqual(
            self.block.header.__dict__, block_2.header.__dict__
        )
        self.assertDictEqual(
            self.block.stamp.__dict__, block_2.stamp.__dict__
        )

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(blocks.Block.from_json(""))
        self.assertIsNone(blocks.Block.from_json("qdsfdhgrfh"))

    def test_from_json_returns_none_in_case_of_missing_transactions(self):
        self.assertIsNone(blocks.Block.from_json(
            '{"tx_count": 2, '
            '"retribution_rate": 0.1, "previous_block_hash": "1", '
            '"merkle_root": "merkle", "closing_time": 12, "master_id": "1", '
            '"master_signature": "sign", "lucky_signatures": {"2": "sig1", '
            '"3": "sig2"}}'
        ))

    def test_str_is_implemented(self):
        str(self.block)

    def test_compute_merkle_root_is_deterministic(self):
        self.assertEqual(
            self.block._compute_merkle_root('1'),
            self.block._compute_merkle_root('1')
        )

    def test_compute_merkle_root_is_sensible_to_transaction_alteration(self):
        merkle_1 = self.block._compute_merkle_root('1'),
        self.block.transactions[0].content.amount *= 2

        self.assertNotEqual(
            merkle_1,
            self.block._compute_merkle_root('1')
        )

    def test_compute_merkle_root_is_sensible_to_prev_block_hash_change(self):
        self.assertNotEqual(
            self.block._compute_merkle_root('11111111'),
            self.block._compute_merkle_root('11111112')
        )

    def test_close_creates_a_new_header(self):
        self.block.header = None
        self.block.close(0.1, "12")

        self.assertIsNotNone(self.block.header)
        self.assertEqual(self.block.header.retribution_rate, 0.1)
        self.assertEqual(self.block.header.previous_block_hash, "12")
        self.assertIsInstance(self.block.header.merkle_root, str)

    @patch('pikciopou.blocks.crypto')
    def test_verify_signature_calls_crypto(self, crypto_mock):
        self.block._verify_signature("sig", "key")

        crypto_mock.verify.assert_called_once_with(
            self.block.header.to_json(), "sig", "key"
        )

    def test_verify_rejects_incomplete_blocks(self):
        self.block.header = None
        with self.assertRaises(Exception):
            self.block.verify(None)
        self.block.stamp = None
        with self.assertRaises(Exception):
            self.block.verify(None)

    def test_verify_rejects_invalid_merkle_root(self):
        self.block.header.merkle_root += "0"
        with self.assertRaises(Exception):
            self.block.verify(None)

    def test_verify_signature_is_called_for_each_signature(self):
        self.block._verify_signature = MagicMock(return_value=True)
        self.block._compute_merkle_root = MagicMock(return_value="merkle")
        mock_key_getter = MagicMock()

        self.block.verify(mock_key_getter)

        self.assertEqual(
            mock_key_getter.call_count,
            1 + len(self.block.stamp.lucky_signatures)
        )
        self.block._verify_signature.assert_has_calls([
            call(self.block.stamp.master_signature, mock_key_getter()),
            call("sig1", mock_key_getter()),
            call("sig2", mock_key_getter()),
        ])

    def test_verify_signature_rejects_invalid_master_signature(self):
        self.block._verify_signature = MagicMock(return_value=False)
        self.block._compute_merkle_root = MagicMock(return_value="merkle")
        mock_key_getter = MagicMock()

        with self.assertRaises(Exception):
            self.block.verify(mock_key_getter)

    def test_verify_signature_rejects_invalid_lucky_signature(self):
        self.block._verify_signature = MagicMock(
            side_effect=[True, True, False]
        )
        self.block._compute_merkle_root = MagicMock(return_value="merkle")
        mock_key_getter = MagicMock()

        with self.assertRaises(Exception):
            self.block.verify(mock_key_getter)

    def test_transactions_of_type_returns_right_transactions(self):
        self.assertEqual(
            len(tuple(self.block._transactions_of_type(TYPE_TX))),
            2
        )
        self.assertEqual(
            len(tuple(self.block._transactions_of_type(TYPE_CASHING))),
            0
        )
        self.assertEqual(
            len(tuple(self.block._transactions_of_type(TYPE_CASHBACK))),
            0
        )

    def test_typed_transactions_based_getters(self):
        self.block._transactions_of_type = MagicMock()

        _ = self.block.lucky_stakeholders
        self.block._transactions_of_type.assert_called_with(TYPE_CASHBACK)

        _ = self.block.regular_transactions
        self.block._transactions_of_type.assert_called_with(TYPE_TX)

        _ = self.block.cashing_transactions
        self.block._transactions_of_type.assert_called_with(TYPE_CASHING)

        _ = self.block.cashback_transactions
        self.block._transactions_of_type.assert_called_with(TYPE_CASHBACK)

        _ = self.block.cashing_amount
        self.block._transactions_of_type.assert_called_with(TYPE_CASHING)

        _ = self.block.cashback_amount
        self.block._transactions_of_type.assert_called_with(TYPE_CASHBACK)
