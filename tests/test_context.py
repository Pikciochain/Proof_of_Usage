import shutil
import unittest

import os
from mock import MagicMock, patch, call, ANY

import pikciopou.context as context
from pikciopou.nodes import MasterNode, ConsumerNode, CashingNode, TrustedNode

CURRENT_DIRECTORY = os.path.dirname(__file__)
TEST_INTERMEDIATE_FOLDER = os.path.join(CURRENT_DIRECTORY, 'test')
TEST_CASHING_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'cashings')
TEST_MASTER_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'masters')
TEST_CONSUMERS_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'consumers')
TEST_TRUSTED_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'trusted')


class TestLocalContext(unittest.TestCase):
    """Tests the Context class."""

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

        self.ctx = context.LocalContext(
            'keystore/', TEST_MASTER_FOLDER, TEST_CASHING_FOLDER,
            TEST_CONSUMERS_FOLDER, TEST_TRUSTED_FOLDER, 10, 0.1, 0.1
        )
        self.ctx._keystore = MagicMock()

    def tearDown(self):
        self.logging_patch.stop()
        self.crypto_patch.stop()
        self.chain_patch.stop()
        self.os_makedirs_patch.stop()

        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    def test_masters_ids_returns_masters_keys(self):
        self.assertEqual(self.ctx.masters_ids, self.ctx.masternodes.keys())

    def test_consumers_ids_returns_consumers_keys(self):
        self.assertEqual(self.ctx.consumers_ids, self.ctx.consumernodes.keys())

    def test_cashings_ids_returns_cashings_keys(self):
        self.assertEqual(self.ctx.cashings_ids, self.ctx.cashingnodes.keys())

    def test_trusteds_ids_returns_trsuteds_keys(self):
        self.assertEqual(self.ctx.trusteds_ids, self.ctx.trustednodes.keys())

    def test_block_timer_tick_does_not_reset_timer_if_keyboard_interrupt(self):
        self.ctx.fire_close_block = MagicMock(side_effect=KeyboardInterrupt)
        self.ctx._create_block_timer = MagicMock()

        self.ctx._block_timer_tick()

        self.ctx.fire_close_block.assert_called_once()
        self.ctx._create_block_timer.assert_not_called()

    def test_block_timer_tick_resets_timer_if_no_exception(self):
        self.ctx.fire_close_block = MagicMock()
        self.ctx._create_block_timer = MagicMock()

        self.ctx._block_timer_tick()

        self.ctx.fire_close_block.assert_called_once()
        self.ctx._create_block_timer.assert_called_once()
        self.ctx._block_timer.start.assert_called_once()

    def test_block_timer_tick_resets_timer_if_any_other_exception(self):
        self.ctx.fire_close_block = MagicMock(side_effect=Exception)
        self.ctx._create_block_timer = MagicMock()

        self.ctx._block_timer_tick()

        self.ctx.fire_close_block.assert_called_once()
        self.ctx._create_block_timer.assert_called_once()
        self.ctx._block_timer.start.assert_called_once()

    def test_register_node_uses_appropriate_dict(self):
        self.ctx._register_node_internal = MagicMock()

        MasterNode(self.ctx, '', TEST_MASTER_FOLDER)
        self.ctx._keystore.register_public_key.assert_called_once_with(
            '1', self.crypto_mock.generate_encryption_keys().public_key
        )

        with self.assertRaises(RuntimeError):
            self.ctx.register_node(MagicMock(), 'key4')

    def test_fire_close_block_calls_close_on_each_master(self):
        self.ctx.masternodes = {'1': MagicMock(), '2': MagicMock()}

        self.ctx.fire_close_block()

        for node in self.ctx.masternodes.values():
            node.request_close_block.assert_called_once()

    @patch('pikciopou.context.os')
    @patch('pikciopou.context.shutil')
    def test_clear_empties_registers_and_rebuilds_root(self, shutil_mock,
                                                       os_mock):
        self.ctx.masternodes = {'1': MagicMock(), '2': MagicMock()}
        self.ctx.consumernodes = {'1': MagicMock(), '2': MagicMock()}
        self.ctx.cashingnodes = {'1': MagicMock(), '2': MagicMock()}
        os_mock.path.exists.return_value = True

        self.ctx.clear()

        self.assertFalse(self.ctx.masternodes)
        self.assertFalse(self.ctx.consumernodes)
        self.assertFalse(self.ctx.cashingnodes)
        self.assertFalse(self.ctx.trustednodes)
        self.assertEquals(shutil_mock.rmtree.call_count, 4)
        self.assertEquals(os_mock.makedirs.call_count, 4)

    def test_create_masternode_returns_a_masternode(self,):
        node = self.ctx.create_masternode()

        self.assertIsInstance(node, MasterNode)

    def test_create_consumernode_returns_a_consumernode(self):
        self.assertIsInstance(self.ctx.create_consumernode(), ConsumerNode)

    def test_create_cashingnode_returns_a_cashingnode(self):
        self.assertIsInstance(self.ctx.create_cashingnode(), CashingNode)

    def test_create_trustednode_returns_a_trustednode(self):
        self.assertIsInstance(self.ctx.create_trustednode(), TrustedNode)

    def test_poll_cashing_node_id_returns_first_cashing_node_id(self):
        self.ctx.cashingnodes = {'1': MagicMock(), '2': MagicMock()}

        self.assertEqual(self.ctx.poll_cashing_node_id(), '1')

    def test_poll_trusted_node_id_returns_first_trusted_node_id(self):
        self.ctx.trustednodes = {'1': MagicMock(), '2': MagicMock()}

        self.assertEqual(self.ctx.poll_trusted_node_id(), '1')

    def test_poll_master_node_id_returns_first_master_node_id(self):
        self.ctx.masternodes = {'1': MagicMock(), '2': MagicMock()}

        self.assertEqual(self.ctx.poll_master_node_id('1'), '1')

    def test_get_public_key_calls_keystore(self):
        self.ctx.get_public_key('1')

        self.ctx._keystore.public_key.assert_called_once_with('1')

    def test_broadcast_block_to_master_calls_send_on_each_node(self):
        self.ctx.send_block_to_master = MagicMock()
        self.ctx.masternodes = {
            '1': MagicMock(), '2': MagicMock(), '3': MagicMock()
        }

        self.ctx.broadcast_block_to_masters('2', MagicMock())

        self.ctx.send_block_to_master.assert_has_calls([
            call('1', ANY),
            call('3', ANY),
        ])

    def test_broadcast_transaction_to_master_calls_send_on_each_node(self):
        self.ctx.send_transaction_to_master = MagicMock()
        self.ctx.masternodes = {
            '1': MagicMock(), '2': MagicMock(), '3': MagicMock()
        }

        self.ctx.broadcast_transaction_to_masters('2', MagicMock())

        self.ctx.send_transaction_to_master.assert_has_calls([
            call('1', ANY),
            call('3', ANY),
        ])

    def test_get_lucky_signature_returns_node_signature_if_exists(self):
        self.ctx.consumernodes = {'1': MagicMock(), '2': MagicMock()}

        sign1 = self.ctx.get_lucky_signature('1', MagicMock())
        sign_none = self.ctx.get_lucky_signature('3', MagicMock())

        self.assertEqual(sign1, self.ctx.consumernodes['1'].sign_block())
        self.assertIsNone(sign_none)

    def test_send_block_to_master_calls_node_member_method(self):
        self.ctx.masternodes = {'1': MagicMock(), '2': MagicMock()}

        self.ctx.send_block_to_master('2', MagicMock())

        self.ctx.masternodes['2'].receive_block.assert_called_once()

    def test_send_transaction_to_master_calls_node_member_method(self):
        self.ctx.masternodes = {'1': MagicMock(), '2': MagicMock()}

        self.ctx.send_transaction_to_master('2', MagicMock())

        self.ctx.masternodes['2'].receive_transaction.assert_called_once()

    def test_start_does_nothing_if_started_already(self):
        self.ctx._block_timer = MagicMock()
        self.ctx.started = True

        self.ctx.start()

        self.ctx._block_timer.start.assert_not_called()

    def test_start_starts_timer_if_not_started(self):
        self.ctx._block_timer = MagicMock()
        self.ctx.started = False

        self.ctx.start()

        self.ctx._block_timer.start.assert_called_once()

    def test_stop_does_nothing_if_stopped_already(self):
        self.ctx._block_timer = MagicMock()
        self.ctx.started = False

        self.ctx.stop()

        self.ctx._block_timer.cancel.assert_not_called()

    def test_stop_stops_timer_if_not_stopped(self):
        self.ctx._block_timer = MagicMock()
        self.ctx.started = True

        self.ctx.stop()

        self.ctx._block_timer.cancel.assert_called_once()
