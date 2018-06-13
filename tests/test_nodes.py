import os
import shutil

from mock import patch, MagicMock, call
import unittest

import pikciopou.nodes as nodes
from pikciopou.blocks import BlockStamp
from pikciopou.pou import POUCashback
from pikciopou.transactions import TransactionContent, TYPE_GENESIS, \
    TYPE_CASHBACK, TYPE_CASHING, TYPE_TX, Transaction, TransactionStamp, \
    TYPE_TX_FEES

CURRENT_DIRECTORY = os.path.dirname(__file__)
TEST_INTERMEDIATE_FOLDER = os.path.join(CURRENT_DIRECTORY, 'test')
TEST_CHAIN_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'chain')
TEST_MASTER_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'master')
TEST_CASHING_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'cashing')
TEST_CONSUMER_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'consumer')


class TestChain(unittest.TestCase):
    """Tests the Chain class."""

    def setUp(self):
        self.chain = nodes.Chain(
            TEST_CHAIN_FOLDER,
            lambda json_object: json_object,
            lambda obj: str(obj)
        )

    def tearDown(self):
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    def test_check_folder_creates_folder_correctly(self):
        self.chain._check_folder()
        self.assertTrue(os.path.exists(TEST_CHAIN_FOLDER))

    def test_get_path_returns_correct_object_name(self):
        self.assertEquals(
            self.chain._get_path(2),
            os.path.join(TEST_CHAIN_FOLDER, '2.json')
        )

    def test_clear_removes_objects(self):
        self.chain.push('obj')
        self.chain.clear()
        self.assertFalse(os.path.exists(TEST_CHAIN_FOLDER))

    def test_push_creates_file(self):
        self.chain.push('obj')

        obj_file = os.path.join(TEST_CHAIN_FOLDER, '0.json')
        self.assertTrue(os.path.exists(obj_file))
        with open(obj_file) as key:
            self.assertEquals(key.read(), 'obj')

    def test_push_all_creates_files(self):
        self.chain.push_all(('obj1', 'obj2'))

        obj_file1 = os.path.join(TEST_CHAIN_FOLDER, '0.json')
        obj_file2 = os.path.join(TEST_CHAIN_FOLDER, '1.json')
        self.assertTrue(os.path.exists(obj_file1))
        self.assertTrue(os.path.exists(obj_file2))

    def test_get_returns_obj(self):
        self.chain.push('obj_test')
        self.assertEqual(self.chain.get(0), 'obj_test')

    def test_get_invalid_index_raises_exception(self):
        with self.assertRaises(IndexError):
            self.chain.get(3)

    def test_len_returns_number_of_objects(self):
        self.chain.push_all(('obj1', 'obj2', 'obj3'))
        self.assertEqual(len(self.chain), 3)

    def test_iterator_returns_object_in_chain_order(self):
        self.chain.push_all(('1', '3', '2'))
        self.assertListEqual([obj for obj in self.chain], ['1', '3', '2'])

    def test_reversed_returns_object_in_reversed_chain_order(self):
        self.chain.push_all(('1', '3', '2'))
        self.assertListEqual(list(reversed(self.chain)), ['2', '3', '1'])


class TestNode(unittest.TestCase):
    """Tests the Node class."""

    def setUp(self):
        self.crypto_patch = patch('pikciopou.nodes.crypto')
        self.crypto_mock = self.crypto_patch.start()
        self.crypto_mock.get_hash.return_value = '1'

    def tearDown(self):
        self.crypto_patch.stop()
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    def test_id_gets_defined_randomly(self):
        nodes.Node(MagicMock(), TEST_MASTER_FOLDER)
        self.crypto_mock.get_hash_assert_called_once_with(None)

    def test_node_calls_register_on_context(self):
        context_mock = MagicMock()
        node = nodes.Node(context_mock, TEST_MASTER_FOLDER)

        key_mock = self.crypto_mock.generate_encryption_keys().public_key
        context_mock.register_node.assert_called_once_with(node, key_mock)

    def test_get_public_key_forwards_request_to_context(self):
        context_mock = MagicMock()
        node = nodes.Node(context_mock, TEST_MASTER_FOLDER)
        key = node.get_public_key("node_id")
        context_mock.get_public_key.assert_called_once_with("node_id")
        self.assertEqual(key, context_mock.get_public_key.return_value)


class TestConsumerNode(unittest.TestCase):
    """Tests the ConsumerNode class."""

    def setUp(self):
        self.crypto_patch = patch('pikciopou.nodes.crypto')
        self.crypto_mock = self.crypto_patch.start()
        self.crypto_mock.get_hash.return_value = '1'

        self.node = nodes.ConsumerNode(MagicMock(), TEST_CONSUMER_FOLDER)

    def tearDown(self):
        self.crypto_patch.stop()
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    def test_sign_calls_crypto_sign_correctly(self):
        self.node._sign('payload')

        self.crypto_mock.sign.assert_called_once_with(
            'payload', self.node.private_key, self.node.id
        )

    def test_sign_transaction_calls_sign_correctly(self):
        self.node._sign = MagicMock()

        tx_content_mock = MagicMock()
        self.node.sign_transaction(tx_content_mock)

        self.node._sign.assert_called_once_with(tx_content_mock.to_json())

    def test_sign_block_calls_sign_correctly(self):
        self.node._sign = MagicMock()

        block_header_mock = MagicMock()
        self.node.sign_block(block_header_mock)

        self.node._sign.assert_called_once_with(block_header_mock.to_json())

    @patch('pikciopou.nodes.TransactionContent')
    @patch('pikciopou.nodes.Transaction')
    def test_create_transaction_creates_correct_signed_transaction(
            self, tx_mock, tx_content_mock
    ):
        self.node.sign_transaction = MagicMock()

        tx = self.node.create_transaction("recipient", 100, TYPE_GENESIS)

        tx_content_mock.assert_called_once_with(
            sender_id=self.node.id,
            recipient_id="recipient",
            amount=100,
            tx_type=TYPE_GENESIS
        )
        self.node.sign_transaction.assert_called_once_with(
            tx_content_mock.return_value
        )
        self.assertEqual(tx, tx_mock.return_value)


class TestMasterNode(unittest.TestCase):
    """Tests the MasterNode class."""

    def setUp(self):
        self.crypto_patch = patch('pikciopou.nodes.crypto')
        self.crypto_mock = self.crypto_patch.start()
        self.crypto_mock.get_hash.return_value = '1'

        self.logging_patch = patch('pikciopou.nodes.logging')
        self.logging_mock = self.logging_patch.start()

        self.chain_patch = patch('pikciopou.nodes.Chain')
        self.chain_mock = self.chain_patch.start()

        self.os_makedirs_patch = patch('pikciopou.nodes.os.makedirs')
        self.os_makedirs_patch.start()

        self.node = nodes.MasterNode(
            MagicMock(), TEST_MASTER_FOLDER, MagicMock()
        )

    def tearDown(self):
        self.crypto_patch.stop()
        self.logging_patch.stop()
        self.chain_patch.stop()
        self.os_makedirs_patch.stop()
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    @patch('pikciopou.nodes.TransactionStamp')
    def test_make_stamp_creates_stamp_using_context_info(self, tx_stamp_mock):
        tx_content_mock = MagicMock()
        tx_content_mock.compute_fees.return_value = 30
        tx_content_mock.amount = 300

        self.node._make_transaction_stamp(tx_content_mock)

        tx_stamp_mock.assert_called_once_with(30, self.node.id)

    def test_create_stamped_transaction_adds_the_stamp_to_transaction(self):
        self.node._make_transaction_stamp = MagicMock()
        self.node.create_transaction = MagicMock()

        tx = self.node._create_stamped_transaction('1', 100)

        self.assertIsNotNone(tx.stamp)
        self.node.create_transaction.assert_called_once_with('1', 100, TYPE_TX)
        self.node._make_transaction_stamp.assert_called_once_with(tx.content)

    def test_find_funds_returns_an_amount_equal_to_required_if_enough(self):
        tx_mock = MagicMock()
        tx_mock.delta_for.side_effect = [100, -100, 500]
        transactions = [tx_mock] * 3

        available = self.node._find_funds(transactions, '1', 300)

        tx_mock.delta_for.assert_has_calls([
            call('1'),
            call('1'),
            call('1'),
        ])
        self.assertEqual(available, 300)

    def test_find_funds_returns_available_if_not_enough(self):
        tx_mock = MagicMock()
        tx_mock.delta_for.side_effect = [100, -100, 500]
        transactions = [tx_mock] * 3

        available = self.node._find_funds(transactions, '1', 700)

        tx_mock.delta_for.assert_has_calls([
            call('1'),
            call('1'),
            call('1'),
        ])
        self.assertEqual(available, 500)

    def test_provokes_overdraft_returns_false_if_available_in_stack(self):
        self.node._find_funds = MagicMock(return_value=400)

        self.assertFalse(self.node._provokes_overdraft('1', 200))
        self.assertEqual(self.node._find_funds.call_count, 1)

    def test_provokes_overdraft_returns_false_if_available_in_blocks(self):
        self.node._find_funds = MagicMock(side_effect=[100, 300])
        self.node._blockchain.__reversed__ = MagicMock()
        self.node._blockchain.__reversed__.return_value = [MagicMock()]

        self.assertFalse(self.node._provokes_overdraft('1', 200))
        self.assertEqual(self.node._find_funds.call_count, 2)

    def test_provokes_overdraft_returns_true_if_overdraft(self):
        self.node._find_funds = MagicMock(side_effect=[100, 300, 300])
        self.node._blockchain.__reversed__ = MagicMock()
        self.node._blockchain.__reversed__.return_value = [MagicMock()] * 2

        self.assertTrue(self.node._provokes_overdraft('1', 1000))
        self.assertEqual(self.node._find_funds.call_count, 3)

    def test_shall_close_current_block_returns_true_if_id_equals_chosen(self):
        self.crypto_mock.get_closest_hash_to.return_value = self.node.id

        self.assertTrue(self.node._shall_close_current_block('seed'))
        self.crypto_mock.get_closest_hash_to.assert_called_once_with(
            'seed', self.node.context.masters_ids
        )

    def test_shall_close_current_block_returns_false_if_id_not_chosen(self):
        self.crypto_mock.get_closest_hash_to.return_value = 'other_id'

        self.assertFalse(self.node._shall_close_current_block('seed'))
        self.crypto_mock.get_closest_hash_to.assert_called_once_with(
            'seed', self.node.context.masters_ids
        )

    def test_create_cashbacks_transactions_creates_them_properly(self):
        self.node._create_stamped_transaction = MagicMock()
        cashbacks = [
            POUCashback('1', 100),
            POUCashback('2', 200),
            POUCashback('3', 300),
        ]

        txs = self.node._create_cashbacks_transactions(cashbacks)

        self.assertEqual(len(txs), 3)
        self.node._create_stamped_transaction.assert_has_calls([
            call('1', 100, TYPE_CASHBACK),
            call('2', 200, TYPE_CASHBACK),
            call('3', 300, TYPE_CASHBACK),
        ])

    def test_create_cashing_transaction_creates_it_properly(self):
        self.node._create_stamped_transaction = MagicMock()
        self.node.context.poll_cashing_node_id = MagicMock(return_value='1')

        self.node._create_cashing_transaction(100)

        self.node.context.poll_cashing_node_id.assert_called_once()
        self.node._create_stamped_transaction.assert_called_once_with(
            '1', 100, TYPE_CASHING
        )

    def test_create_return_transactions_returns_cashbacks_and_cashing(self):
        self.node._pou_algo.compute = MagicMock(
            return_value=['cashing', 'cashbacks']
        )
        self.node._create_cashing_transaction = MagicMock(return_value='3')
        self.node._create_cashbacks_transactions = MagicMock(
            return_value=['1', '2']
        )
        tx_mock = MagicMock()
        tx_mock.content.type = TYPE_TX
        result = self.node._create_return_transactions([tx_mock] * 2, 'seed')

        self.node._create_cashing_transaction.assert_called_once_with(
            'cashing'
        )
        self.node._create_cashbacks_transactions.assert_called_once_with(
            'cashbacks'
        )
        self.assertListEqual(result, ['1', '2', '3'])

    def test_create_return_transactions_returns_nothing_if_only_genesis(self):
        self.node._pou_algo.compute = MagicMock()
        tx_mock = MagicMock()
        tx_mock.content.type = TYPE_GENESIS

        result = self.node._create_return_transactions([tx_mock], 'seed')

        self.assertListEqual(result, [])
        self.node._pou_algo.compute.assert_not_called()

    def test_create_fees_collection_transaction_really_collects_fees(self):
        self.node._create_stamped_transaction = MagicMock()
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

        tx = self.node._create_fees_collection_transaction(transactions)
        self.assertEqual(
            tx, self.node._create_stamped_transaction.return_value
        )
        self.node._create_stamped_transaction.assert_called_once_with(
            self.node.id, 40, TYPE_TX_FEES
        )

    def test_push_block_updates_blockchain_and_changes_next_block_seed(self):
        block_mock = MagicMock()
        self.node._push_block(block_mock)

        self.node._blockchain.push.assert_called_once_with(block_mock)
        self.node._next_block_seed = block_mock.header.merkle_root

    def test_collect_transactions_for_block_closure_collects_them_all(self):
        self.node._create_fees_collection_transaction = MagicMock()
        self.node._create_return_transactions = MagicMock()

        txs = [Transaction()] * 3
        self.node._tx_stack = txs

        self.node._collect_transactions_for_block_closure('seed')

        self.node._create_fees_collection_transaction.assert_called_once_with(
            txs
        )
        self.node._create_return_transactions.assert_called_once_with(
            txs, 'seed'
        )

    def test_collect_transactions_for_block_closure_aborts_if_nothing(self):
        self.node._create_fees_collection_transaction = MagicMock()
        self.node._create_return_transactions = MagicMock()

        txs = []
        self.node._tx_stack = txs

        self.node._collect_transactions_for_block_closure('seed')

        self.node._create_fees_collection_transaction.assert_not_called()
        self.node._create_return_transactions.assert_not_called()

    def test_make_block_stamp_make_them_all_sign(self):
        self.node.sign_block = MagicMock()

        block_mock = MagicMock()
        block_mock.lucky_stakeholders = ['1', '2']
        stamp = self.node._make_block_stamp(block_mock)

        self.assertIsInstance(stamp, BlockStamp)
        self.node.sign_block.assert_called_once_with(block_mock.header)
        self.node.context.get_lucky_signature.assert_has_calls([
            call('1', block_mock),
            call('2', block_mock),
        ])

    @patch('pikciopou.nodes.Block')
    def test_close_block_builds_a_stamp_block_and_propagates_it(self,
                                                                block_mock):
        self.node._collect_transactions_for_block_closure = MagicMock()
        self.node._make_block_stamp = MagicMock()
        self.node._push_block = MagicMock()

        self.node._close_block('seed')

        block_mock.return_value.close.assert_called_once()
        closed_block_mock = block_mock.return_value.close.return_value
        self.node._collect_transactions_for_block_closure \
            .assert_called_once_with('seed')
        self.node._make_block_stamp.assert_called_once_with(closed_block_mock)
        self.node.context.broadcast_block_to_masters.assert_called_once_with(
            self.node.id, closed_block_mock
        )
        self.node._push_block.assert_called_once_with(closed_block_mock)
        self.node._tx_stack.clear.assert_called_once()

    def test_close_block_does_nothing_if_no_transaction(self):
        self.node._collect_transactions_for_block_closure = MagicMock(
            return_value=[]
        )
        self.node._make_block_stamp = MagicMock()
        self.node._push_block = MagicMock()

        self.node._close_block('seed')

        self.node._collect_transactions_for_block_closure \
            .assert_called_once_with('seed')
        self.node._make_block_stamp.assert_not_called()
        self.node.context.broadcast_block_to_masters.assert_not_called()
        self.node._push_block.assert_not_called()
        self.node._tx_stack.clear.assert_not_called()

    @patch('pikciopou.nodes.ProofOfUsageAlgorithm')
    def test_verify_proof_of_usage_does_nothing_if_all_ok(self, pou_mock):
        pou_mock.return_value.compute.return_value = 10, [
            POUCashback('1', 15),
            POUCashback('2', 30),
        ]
        block_mock = MagicMock()
        block_mock.cashing_amount = 10
        block_mock.cashback_amount = 45
        block_mock.lucky_stakeholders = '1', '2'

        self.node._verify_proof_of_usage(block_mock, 'seed')

    @patch('pikciopou.nodes.ProofOfUsageAlgorithm')
    def test_verify_proof_of_usage_raises_if_wrong_cashing(self, pou_mock):
        pou_mock.return_value.compute.return_value = 15, [
            POUCashback('1', 15),
            POUCashback('2', 30),
        ]
        block_mock = MagicMock()
        block_mock.cashing_amount = 10
        block_mock.cashback_amount = 45
        block_mock.lucky_stakeholders = '1', '2'

        with self.assertRaises(Exception):
            self.node._verify_proof_of_usage(block_mock, 'seed')

    @patch('pikciopou.nodes.ProofOfUsageAlgorithm')
    def test_verify_proof_of_usage_raises_if_wrong_cashback(self, pou_mock):
        pou_mock.return_value.compute.return_value = 10, [
            POUCashback('1', 20),
            POUCashback('2', 30),
        ]
        block_mock = MagicMock()
        block_mock.cashing_amount = 10
        block_mock.cashback_amount = 45
        block_mock.lucky_stakeholders = '1', '2'

        with self.assertRaises(Exception):
            self.node._verify_proof_of_usage(block_mock, 'seed')

    @patch('pikciopou.nodes.ProofOfUsageAlgorithm')
    def test_verify_proof_of_usage_raises_if_wrong_luckys(self, pou_mock):
        pou_mock.return_value.compute.return_value = 10, [
            POUCashback('1', 15),
            POUCashback('3', 30),
        ]
        block_mock = MagicMock()
        block_mock.cashing_amount = 10
        block_mock.cashback_amount = 45
        block_mock.lucky_stakeholders = '1', '2'

        with self.assertRaises(Exception):
            self.node._verify_proof_of_usage(block_mock, 'seed')

    def test_reset_transaction_stack_after_block_check(self):
        self.node._reset_transaction_stack_after_block_check(MagicMock())

        self.node._tx_stack.clear.assert_called_once()
        self. node._tx_stack.push_all.assert_called_once()

    def test_verify_block_against_transaction_stack(self):
        self.node.get_public_key = MagicMock()
        self.node._reset_transaction_stack_after_block_check = MagicMock()
        tx_1, tx_2, tx_3 = MagicMock(), MagicMock(), MagicMock()
        self.node._tx_stack = tx_1, tx_2

        self.node._verify_block_against_transaction_stack([tx_1, tx_2, tx_3])

        self.node._reset_transaction_stack_after_block_check\
            .assert_called_once()
        tx_1.verify.assert_not_called()
        tx_2.verify.assert_not_called()
        tx_3.verify.assert_called_once_with(self.node.get_public_key())

    def test_receive_transaction_handles_transaction_properly(self):
        self.node.get_public_key = MagicMock()
        self.node._provokes_overdraft = MagicMock(return_value=False)
        self.node._make_transaction_stamp = MagicMock()
        tx_mock = MagicMock()

        self.node.receive_transaction(tx_mock)

        tx_mock.verify.assert_called_once_with(self.node.get_public_key())
        self.node._provokes_overdraft.assert_called_once_with(
            tx_mock.content.sender_id, tx_mock.content.amount.__add__()
        )
        self.node._make_transaction_stamp.assert_called_once_with(
            tx_mock.content
        )
        self.node._tx_stack.push.assert_called_once_with(tx_mock)

    def test_receive_transaction_rejects_invalid_ones(self):
        self.node.get_public_key = MagicMock()
        self.node._provokes_overdraft = MagicMock(return_value=True)
        self.node._make_transaction_stamp = MagicMock()
        tx_mock = MagicMock()

        self.node.receive_transaction(tx_mock)

        tx_mock.verify.assert_called_once_with(self.node.get_public_key())
        self.node._provokes_overdraft.assert_called_once_with(
            tx_mock.content.sender_id, tx_mock.content.amount.__add__()
        )
        self.node._make_transaction_stamp.assert_called_once_with(
            tx_mock.content
        )
        self.node._tx_stack.push.assert_not_called()

    def test_receive_block_verifies_it_correctly(self):
        self.node._verify_proof_of_usage = MagicMock()
        self.node._verify_block_against_transaction_stack = MagicMock()
        self.node._push_block = MagicMock()

        block_mock = MagicMock()
        self.node.receive_block(block_mock)

        block_mock.verify.assert_called_once_with(self.node.get_public_key)
        self.node._verify_proof_of_usage.assert_called_once_with(
            block_mock,
            self.node._next_block_seed
        )
        self.node._verify_block_against_transaction_stack\
            .assert_called_once_with(block_mock.transactions)
        self.node._push_block.assert_called_once_with(block_mock)

    def test_receive_block_rejects_invalid_block(self):
        self.node._verify_proof_of_usage = MagicMock()
        self.node._verify_block_against_transaction_stack = MagicMock()
        self.node._push_block = MagicMock()

        block_mock = MagicMock()
        block_mock.verify.side_effect = Exception
        self.node.receive_block(block_mock)

        block_mock.verify.assert_called_once_with(self.node.get_public_key)
        self.node._verify_proof_of_usage.assert_not_called()
        self.node._verify_block_against_transaction_stack.assert_not_called()
        self.node._push_block.assert_not_called()

    def test_receive_block_rejects_wrong_pou(self):
        self.node._verify_proof_of_usage = MagicMock(side_effect=Exception)
        self.node._verify_block_against_transaction_stack = MagicMock()
        self.node._push_block = MagicMock()

        block_mock = MagicMock()
        self.node.receive_block(block_mock)

        block_mock.verify.assert_called_once_with(self.node.get_public_key)
        self.node._verify_proof_of_usage.assert_called_once_with(
            block_mock,
            self.node._next_block_seed
        )
        self.node._verify_block_against_transaction_stack.assert_not_called()
        self.node._push_block.assert_not_called()

    def test_request_close_block_closes_block_if_it_shall(self):
        self.node._shall_close_current_block = MagicMock(return_value=True)
        self.node._close_block = MagicMock()

        self.node.request_close_block()

        self.node._shall_close_current_block.assert_called_once_with(
            self.node._next_block_seed
        )
        self.node._close_block.assert_called_once_with(
            self.node._next_block_seed
        )

    def test_request_close_block_does_not_close_block_if_it_shant(self):
        self.node._shall_close_current_block = MagicMock(return_value=False)
        self.node._close_block = MagicMock()

        self.node.request_close_block()

        self.node._shall_close_current_block.assert_called_once_with(
            self.node._next_block_seed
        )
        self.node._close_block.assert_not_called()
