import os
import shutil

from mock import patch, MagicMock, call
import unittest

from pikciosc.models import ExecutionInfo

import pikciopou.nodes as nodes
from pikciopou.blocks import BlockStamp
from pikciopou.pou import POUCashback
from pikciopou.transactions import TransactionContent, TYPE_GENESIS, \
    TYPE_CASHBACK, TYPE_CASHING, TYPE_TX, Transaction, TransactionStamp, \
    TYPE_TX_FEES

CURRENT_DIRECTORY = os.path.dirname(__file__)
TEST_INTERMEDIATE_FOLDER = os.path.join(CURRENT_DIRECTORY, 'test')
TEST_MASTER_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'master')
TEST_CASHING_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'cashing')
TEST_CONSUMER_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'consumer')
TEST_TRUSTED_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'trusted')


class TestSCBundle(unittest.TestCase):
    """Tests the SCBundle class."""

    def setUp(self):
        self.crypto_mock = patch('pikciopou.nodes.crypto').start()
        self.scbundle = nodes.SCBundle('source_b64', 'signature', 'emitter_id')
        self.addCleanup(patch.stopall)

    def test_verify_calls_crypto_verify(self):
        self.scbundle.verify(lambda emitter_id: 'key')

        self.crypto_mock.verify.assert_called_once_with('source_b64',
                                                        'signature', 'key')

    def test_from_dict_unsecure_rebuilts_bundle(self):
        self.assertEqual(
            self.scbundle,
            nodes.SCBundle.from_dict_unsecure(self.scbundle.to_dict())
        )


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

    def test_sign_calls_crypto_sign_correctly(self):
        node = nodes.Node(MagicMock(), TEST_MASTER_FOLDER)
        node.sign('payload')

        self.crypto_mock.sign.assert_called_once_with(
            'payload', node.private_key, node.id
        )


class TestTrustedNode(unittest.TestCase):
    """Tests the TrustedNode class."""

    def setUp(self):
        self.crypto_patch = patch('pikciopou.nodes.crypto')
        self.crypto_mock = self.crypto_patch.start()
        self.crypto_mock.get_hash.return_value = '1'

        self.node = nodes.TrustedNode(MagicMock(), TEST_TRUSTED_FOLDER)

    def tearDown(self):
        self.crypto_patch.stop()
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    def test_deliver_certificate_for_calls_sign_appropriately(self):
        self.node.sign = MagicMock()

        result = self.node.deliver_certificate_for('3')

        self.node.sign.assert_called_once_with('3')
        self.assertEquals(result, self.node.sign.return_value)


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

    def test_sign_transaction_calls_sign_correctly(self):
        self.node.sign = MagicMock()

        tx_content_mock = MagicMock()
        self.node.sign_transaction(tx_content_mock)

        self.node.sign.assert_called_once_with(tx_content_mock.to_json())

    def test_sign_block_calls_sign_correctly(self):
        self.node.sign = MagicMock()

        block_header_mock = MagicMock()
        self.node.sign_block(block_header_mock)

        self.node.sign.assert_called_once_with(block_header_mock.to_json())

    def test_create_sc_bundle_encode_source_and_signs_it(self):
        self.node.sign = MagicMock()

        result = self.node.create_sc_bundle('source_code')

        encode_mock = self.crypto_mock.base64_encode
        encode_mock.assert_called_once_with('source_code')
        self.node.sign.assert_called_once_with(encode_mock())
        self.assertEqual(result, nodes.SCBundle(
            encode_mock(), self.node.sign(), self.node.id
        ))

    @patch('pikciopou.nodes.Transaction')
    def test_package_transaction_content_signs_content(self, tx_mock):
        self.node.sign_transaction = MagicMock()
        tx_content_mock = MagicMock()

        tx = self.node._package_transaction_content(tx_content_mock)

        self.node.sign_transaction.assert_called_once_with(tx_content_mock)
        tx_mock.assert_called_once_with(tx_content_mock,
                                        self.node.sign_transaction())
        self.assertEqual(tx, tx_mock())

    @patch('pikciopou.nodes.TransactionContent')
    def test_create_transaction_packages_content(self, tx_content_mock):
        package_mock = self.node._package_transaction_content = MagicMock()

        tx = self.node.create_transaction("recipient", 100, TYPE_GENESIS)

        tx_content_mock.assert_called_once_with(
            sender_id=self.node.id, recipient_id="recipient",
            amount=100, tx_type=TYPE_GENESIS
        )
        package_mock.assert_called_once_with(tx_content_mock())
        self.assertEqual(tx, package_mock())

    @patch('pikciopou.nodes.ContractSubmissionContent')
    def test_create_sc_submit_transaction_packages_content(
            self, tx_content_mock
    ):
        poll_mock = self.node.context.poll_master_node_id = MagicMock()
        package_mock = self.node._package_transaction_content = MagicMock()

        tx = self.node.create_sc_submit_transaction(100, 'certificate',
                                                    'source_b64')

        tx_content_mock.assert_called_once_with(
            sender_id=self.node.id, recipient_id="",
            amount=100, certificate='certificate', source_b64='source_b64'
        )
        poll_mock.assert_called_once_with(tx_content_mock().tx_id)
        self.assertEqual(tx_content_mock().recipient_id, poll_mock())
        package_mock.assert_called_once_with(tx_content_mock())
        self.assertEqual(tx, package_mock())

    @patch('pikciopou.nodes.ContractInvocationContent')
    def test_create_sc_invoke_transaction_packages_content(
            self, tx_content_mock
    ):
        poll_mock = self.node.context.poll_master_node_id = MagicMock()
        package_mock = self.node._package_transaction_content = MagicMock()

        tx = self.node.create_sc_invoke_transaction(100, 'sc_id', 'abi_call')

        tx_content_mock.assert_called_once_with(
            sender_id=self.node.id, recipient_id="",
            amount=100, sc_id='sc_id', abi_call='abi_call'
        )
        poll_mock.assert_called_once_with(tx_content_mock().tx_id)
        self.assertEqual(tx_content_mock().recipient_id, poll_mock())
        package_mock.assert_called_once_with(tx_content_mock())
        self.assertEqual(tx, package_mock())


class TestMasterNode(unittest.TestCase):
    """Tests the MasterNode class."""

    def setUp(self):
        self.crypto_patch = patch('pikciopou.nodes.crypto')
        self.crypto_mock = self.crypto_patch.start()
        self.crypto_mock.get_hash.return_value = '1'
        self.crypto_mock.sign.return_value = 'signature'

        self.logging_patch = patch('pikciopou.nodes.logging')
        self.logging_mock = self.logging_patch.start()

        self.chain_patch = patch('pikciopou.nodes.Chain')
        self.chain_mock = self.chain_patch.start()

        self.os_makedirs_patch = patch('pikciopou.nodes.os.makedirs')
        self.os_makedirs_patch.start()

        self.context_mock = MagicMock()
        self.node = nodes.MasterNode(
            self.context_mock, TEST_MASTER_FOLDER, MagicMock()
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

    def test_all_transactions_joins_stack_and_blocks(self):
        self.node._blockchain = [MagicMock(), MagicMock()]
        self.node._tx_stack = ['tx_1', 'tx_2']
        self.node._blockchain[1].transactions = ['tx_3', 'tx_4']
        self.node._blockchain[0].transactions = ['tx_5', 'tx_6']

        txs = self.node._all_transactions()
        self.assertListEqual(
            list(txs),
            ['tx_1', 'tx_2', 'tx_3', 'tx_4', 'tx_5', 'tx_6']
        )

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

    def test_provokes_overdraft_returns_false_if_available_in_blocks(self):
        self.node._find_funds = MagicMock(side_effect=[100, 300])
        self.node._all_transactions = MagicMock(return_value=[MagicMock()] * 2)

        self.assertFalse(self.node._provokes_overdraft('1', 200))
        self.assertEqual(self.node._find_funds.call_count, 2)

    def test_provokes_overdraft_returns_true_if_overdraft(self):
        self.node._find_funds = MagicMock(side_effect=[100, 300, 300])
        self.node._all_transactions = MagicMock(return_value=[MagicMock()] * 3)

        self.assertTrue(self.node._provokes_overdraft('1', 1000))
        self.assertEqual(self.node._find_funds.call_count, 3)

    def test_shall_close_current_block_returns_true_if_id_equals_chosen(self):
        self.context_mock.poll_master_node_id.return_value = self.node.id

        self.assertTrue(self.node._shall_close_current_block('seed'))
        self.context_mock.poll_master_node_id.assert_called_once_with('seed')

    def test_shall_close_current_block_returns_false_if_id_not_chosen(self):
        self.context_mock.poll_master_node_id.return_value = 'other_id'

        self.assertFalse(self.node._shall_close_current_block('seed'))
        self.context_mock.poll_master_node_id.assert_called_once_with('seed')

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
        self.node._tx_stack.push_all.assert_called_once()

    def test_verify_block_against_transaction_stack(self):
        self.node.get_public_key = MagicMock()
        self.node._reset_transaction_stack_after_block_check = MagicMock()
        tx_1, tx_2, tx_3 = MagicMock(), MagicMock(), MagicMock()
        self.node._tx_stack = tx_1, tx_2

        self.node._verify_block_against_transaction_stack([tx_1, tx_2, tx_3])

        self.node._reset_transaction_stack_after_block_check \
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

    def test_commit_transaction_saves_and_broadcasts_transaction(self):
        self.node.receive_transaction = MagicMock()
        self.node.context.broadcast_transaction_to_masters = MagicMock()
        tx_mock = MagicMock()

        self.node.commit_transaction(tx_mock)

        self.node.receive_transaction.assert_called_once_with(tx_mock)
        self.node.context.broadcast_transaction_to_masters\
            .assert_called_once_with(self.node.id, tx_mock)

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
        self.node._verify_block_against_transaction_stack \
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

    def test_verify_certificate_Calls_crypto_verify_correctly(self):
        self.node.get_public_key = MagicMock()

        self.node._verify_certificate('certificate', '2', '1')

        self.node.get_public_key.assert_called_once_with('1')
        self.crypto_mock.verify.assert_called_once_with(
            '2', 'certificate', self.node.get_public_key.return_value
        )

    @patch('pikciopou.nodes.quotations.get_submit_quotation')
    def test_get_sc_submit_quotation_returns_verified_quote(self, quote_mock):
        bundle_mock = MagicMock()

        result = self.node.get_sc_submit_quotation(bundle_mock)

        bundle_mock.verify.assert_called_once_with(
            self.node.context.get_public_key
        )
        self.crypto_mock.base64_decode.assert_called_once_with(
            bundle_mock.source_b64
        )
        quote_mock.assert_called_once_with(self.crypto_mock.base64_decode())
        self.assertEqual(result, quote_mock())

    @patch('pikciopou.nodes.quotations.get_submit_quotation')
    def test_get_sc_submit_quotation_raises_err_if_invalid_bundle(self,
                                                                  quote_mock):
        bundle_mock = MagicMock()
        bundle_mock.verify.return_value = False

        with self.assertRaises(Exception):
            self.node.get_sc_submit_quotation(bundle_mock)

        bundle_mock.verify.assert_called_once_with(
            self.node.context.get_public_key
        )
        self.crypto_mock.base64_decode.assert_not_called()
        quote_mock.assert_not_called()

    @patch('pikciopou.nodes.quotations.get_exec_quotation')
    def test_get_sc_invoke_quotation_returns_quotation(self, get_exec_mock):
        self.node.sc_env.is_execution_granted = MagicMock()
        self.node.sc_env.get_bin = MagicMock()

        res = self.node.get_sc_invoke_quotation('sc_id', 'invoc_id', 'ep')

        self.node.sc_env.get_bin.assert_called_once_with('sc_id')
        get_exec_mock.assert_called_once_with(self.node.sc_env.get_bin(), 'ep')
        self.assertEqual(res, get_exec_mock())

    @patch('pikciopou.nodes.quotations.get_exec_quotation')
    def test_get_sc_invoke_quotation_raises_err_forbidden(self, get_exec_mock):
        self.node.sc_env.is_execution_granted = MagicMock(return_value=False)
        self.node.sc_env.get_bin = MagicMock()

        with self.assertRaises(ValueError):
            self.node.get_sc_invoke_quotation('sc_id', 'invoc_id', 'ep')

        self.node.sc_env.get_bin.assert_not_called()
        get_exec_mock.assert_not_called()

    def test_get_contract_abi_forwards_call_to_env(self):
        self.node.sc_env = MagicMock()

        result = self.node.get_contract_abi('sc_id')

        self.node.sc_env.get_abi.assert_called_once_with('sc_id')
        self.assertEqual(result, self.node.sc_env.get_abi())

    def test_process_transaction_content_dispatches_content_properly(self):
        self.node.sc_env = MagicMock()
        self.node.process_sc_invocation = MagicMock()
        self.node.process_sc_submission = MagicMock()
        submit_ctnt = nodes.ContractSubmissionContent('1', '', 0, '', 'src')
        invoke_ctnt = nodes.ContractInvocationContent('2', '', 0, '', '')
        exe_ctnt = nodes.ContractExecutionContent('', '3', ExecutionInfo([]))

        self.node.process_transaction_content(submit_ctnt)
        self.node.process_transaction_content(invoke_ctnt)
        self.node.process_transaction_content(exe_ctnt)

        self.node.process_sc_submission.assert_called_once_with(submit_ctnt)
        self.node.process_sc_invocation.assert_called_once_with(invoke_ctnt)
        self.node.sc_env.cache_last_exec.assert_called_once_with(
            '3', exe_ctnt.exec_info
        )

    @patch('pikciopou.nodes.ContractExecutionContent')
    def test_create_sc_exec_transaction_packages_content(self,
                                                         tx_content_mock):
        package_mock = self.node._package_transaction_content = MagicMock()

        tx = self.node._create_sc_exec_transaction('sc_id', 'exec_info')

        tx_content_mock.assert_called_once_with(
            sender_id=self.node.id, sc_id='sc_id', exec_info='exec_info'
        )
        package_mock.assert_called_once_with(tx_content_mock())
        self.assertEqual(tx, package_mock())

    def test_find_exec_info_returns_last_exec_info(self):
        self.node.context.poll_master_node_id = MagicMock(return_value='1')
        exec_info1 = ExecutionInfo([])
        exec_info2 = ExecutionInfo([])
        txs = [
            self.node._create_sc_exec_transaction('3', exec_info1),
            self.node._create_sc_exec_transaction('3', exec_info2),
            self.node.create_sc_invoke_transaction(1, '3', 'abi_call')

        ]
        self.assertEqual(self.node._find_exec_info(txs, '3'), exec_info2)

    def test_find_exec_info_returns_none_if_exec_info_npt_found(self):
        self.node.context.poll_master_node_id = MagicMock(return_value='1')
        exec_info1 = ExecutionInfo([])
        exec_info2 = ExecutionInfo([])
        txs = [
            self.node._create_sc_exec_transaction('2', exec_info1),
            self.node._create_sc_exec_transaction('4', exec_info2),
            self.node.create_sc_invoke_transaction(1, '3', 'abi_call')

        ]
        self.assertIsNone(self.node._find_exec_info(txs, '3'))

    def test_find_exec_info_stops_if_submission_found(self):
        self.node.context.poll_master_node_id = MagicMock(return_value='1')
        submit_tx = self.node.create_sc_submit_transaction(1, '3', 'source')

        txs = [
            submit_tx,
            self.node.create_sc_invoke_transaction(1, '3', 'abi_call')

        ]
        with self.assertRaises(StopIteration):
            self.node._find_exec_info(txs, submit_tx.content.tx_id)

    def test_get_last_exec_info_returns_cached_one_if_any(self):
        self.node.sc_env.get_last_exec_in_cache = MagicMock()
        self.node._all_transactions = MagicMock()
        self.node._find_exec_info = MagicMock()

        self.assertIsNotNone(self.node._get_last_exec_info('1'))
        self.node._all_transactions.assert_not_called()
        self.node._find_exec_info.assert_not_called()

    def test_get_last_exec_info_returns_find_exec_info_result_if_any(self):
        self.node.sc_env.get_last_exec_in_cache = MagicMock(return_value=None)
        self.node._all_transactions = MagicMock(return_value=['tx_group'])
        self.node._find_exec_info = MagicMock()

        self.assertEqual(
            self.node._get_last_exec_info('1'),
            self.node._find_exec_info()
        )
        self.node._all_transactions.assert_called_once()

    def test_get_last_exec_info_returns_none_if_no_result(self):
        self.node.sc_env.get_last_exec_in_cache = MagicMock(return_value=None)
        self.node._all_transactions = MagicMock(return_value=['tx_group'])
        self.node._find_exec_info = MagicMock(side_effect=StopIteration)

        self.assertIsNone(self.node._get_last_exec_info('1'))
        self.node._all_transactions.assert_called_once()
        self.node._find_exec_info.assert_called_once()

    def test_process_sc_submission_only_adds_in_env_if_not_recipient(self):
        self.node.sc_env = MagicMock()
        self.node._create_cashing_transaction = MagicMock()
        self.node.commit_transaction = MagicMock()
        submit_ctnt = nodes.ContractSubmissionContent('1', '2', 0, '', 'src')

        self.node.process_sc_submission(submit_ctnt)

        self.node.sc_env.add.assert_called_once_with(submit_ctnt.tx_id, 'src')
        self.node._create_cashing_transaction.assert_not_called()
        self.node.commit_transaction.assert_not_called()

    def test_process_sc_submission_also_creates_cashing_tx_if_recipient(self):
        self.node.sc_env = MagicMock()
        self.node._create_cashing_transaction = MagicMock()
        self.node.commit_transaction = MagicMock()
        submit_ctnt = nodes.ContractSubmissionContent('2', '1', 30, '', 'src')

        self.node.process_sc_submission(submit_ctnt)

        self.node.sc_env.add.assert_called_once_with(submit_ctnt.tx_id, 'src')
        self.node._create_cashing_transaction.assert_called_once_with(30)
        self.node.commit_transaction.assert_called_once_with(
            self.node._create_cashing_transaction()
        )

    @patch('pikciopou.nodes.invoke')
    @patch('pikciopou.nodes.abi.ABI')
    def test_process_sc_invocation_executes_saves_and_returns_result(
            self, abi_mock, invoke_mock
    ):
        abi_mock.return_value.decode_call.return_value = 'endpoint', 'kwargs'
        self.node.sc_env.get_abi = MagicMock()
        self.node._create_sc_exec_transaction = MagicMock()
        self.node.commit_transaction = MagicMock()
        self.node._get_last_exec_info = MagicMock()

        tx_content = nodes.ContractInvocationContent(
            '1', '1', 1, 'sc_id', 'abi_call'
        )
        result = self.node.process_sc_invocation(tx_content)

        self.node.sc_env.get_abi.assert_called_once_with('sc_id')
        abi_mock.assert_called_once_with(self.node.sc_env.get_abi())
        abi_mock().decode_call.assert_called_once_with('abi_call')
        self.node._get_last_exec_info.assert_called_once_with('sc_id')
        invoke_mock.assert_called_once_with(
            self.node.sc_env.bin_folder, self.node.sc_env.abi_folder,
            self.node._get_last_exec_info(), 'sc_id', 'endpoint', 'kwargs'
        )
        exec_mock = invoke_mock()
        self.node._create_sc_exec_transaction.assert_called_once_with(
            'sc_id', exec_mock
        )
        exec_tx = self.node._create_sc_exec_transaction()
        self.node.commit_transaction.assert_called_once_with(exec_tx)
        abi_mock().encode_call_result.assert_called_once_with(
            exec_mock.call_info
        )
        self.assertEqual(result, abi_mock().encode_call_result())

    @patch('pikciopou.nodes.invoke')
    @patch('pikciopou.nodes.abi.ABI')
    def test_process_sc_invocation_returns_if_node_not_the_one(
            self, abi_mock, invoke_mock
    ):
        abi_mock.return_value.decode_call.return_value = 'endpoint', 'kwargs'
        self.node.sc_env.get_abi = MagicMock()
        self.node._create_sc_exec_transaction = MagicMock()
        self.node.commit_transaction = MagicMock()
        self.node._get_last_exec_info = MagicMock()

        tx_content = nodes.ContractInvocationContent(
            '1', '2', 1, 'sc_id', 'abi_call'
        )
        self.node.process_sc_invocation(tx_content)

        self.node.sc_env.get_abi.assert_not_called()
        abi_mock.assert_not_called()
        abi_mock().decode_call.assert_not_called()
        self.node._get_last_exec_info.assert_not_called()
        invoke_mock.assert_not_called()
        self.node._create_sc_exec_transaction.assert_not_called()
        self.node.commit_transaction.assert_not_called()
        abi_mock().encode_call_result.assert_not_called()

    @patch('pikciopou.nodes.invoke')
    @patch('pikciopou.nodes.abi.ABI')
    def test_process_sc_invocation_raises_exception_if_exec_failure(
            self, abi_mock, invoke_mock
    ):
        abi_mock.return_value.decode_call.return_value = 'endpoint', 'kwargs'
        self.node.sc_env.get_abi = MagicMock()
        self.node._create_sc_exec_transaction = MagicMock()
        self.node.commit_transaction = MagicMock()
        self.node._get_last_exec_info = MagicMock()
        invoke_mock.return_value.success_info.is_success = False

        tx_content = nodes.ContractInvocationContent(
            '1', '1', 1, 'sc_id', 'abi_call'
        )
        with self.assertRaises(RuntimeError):
            self.node.process_sc_invocation(tx_content)

        self.node.sc_env.get_abi.assert_called_once_with('sc_id')
        abi_mock.assert_called_once_with(self.node.sc_env.get_abi())
        abi_mock().decode_call.assert_called_once_with('abi_call')
        self.node._get_last_exec_info.assert_called_once_with('sc_id')
        invoke_mock.assert_called_once_with(
            self.node.sc_env.bin_folder, self.node.sc_env.abi_folder,
            self.node._get_last_exec_info(), 'sc_id', 'endpoint', 'kwargs'
        )
        self.node._create_sc_exec_transaction.assert_not_called()
        self.node.commit_transaction.assert_not_called()
        abi_mock().encode_call_result.assert_not_called()
