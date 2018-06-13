import unittest

from mock import MagicMock

from pikciopou.transactions import Transaction, TransactionContent, TYPE_TX, \
    TransactionStamp
import pikciopou.pou as pou

RaffleTicket = pou.ProofOfUsageAlgorithm.RaffleTicket


class TestPOU(unittest.TestCase):
    """Tests the pou module."""

    def setUp(self):
        self.transactions = [
            Transaction(
                TransactionContent('1', '2', 100, TYPE_TX, 12, '1'),
                'signature1',
                TransactionStamp(10, '10', 12)
            ),
            Transaction(
                TransactionContent('2', '3', 300, TYPE_TX, 12, '2'),
                'signature2',
                TransactionStamp(30, '10', 12)
            ),
            Transaction(
                TransactionContent('3', '1', 700, TYPE_TX, 12, '3'),
                'signature3',
                TransactionStamp(70, '10', 12)
            )
        ]
        self.returned_rate = 0.9
        self.algo = pou.ProofOfUsageAlgorithm(self.returned_rate)

    def test_generate_raffle_tickets_creates_right_tickets(self):
        tickets = self.algo._generate_raffle_tickets(self.transactions)
        self.assertListEqual(tickets, [
            RaffleTicket('1', 10, (0, 100)),
            RaffleTicket('2', 30, (100, 400)),
            RaffleTicket('3', 70, (400, 1100))
        ])

    def test_satoshi_falls_within_maxrange(self):
        satoshis = tuple(
            self.algo._satoshi(str(i), 1100)
            for i in range(3)
        )
        self.assertTrue(all(0 <= satoshi <= 1100 for satoshi in satoshis))

    def test_satoshi_is_deterministic(self):
        self.assertEqual(
            self.algo._satoshi('1', 1100),
            self.algo._satoshi('1', 1100)
        )

    def test_satoshi_generation_from_transactions_is_deterministic(self):
        self.assertListEqual(
            self.algo._generate_satoshis(self.transactions, '1'),
            self.algo._generate_satoshis(self.transactions, '1')
        )

    def test_poll_lucky_tickets_polls_only_winning_tickets(self):
        self.algo._generate_raffle_tickets = MagicMock(
            return_value=[
                RaffleTicket('1', 10, (0, 100)),
                RaffleTicket('2', 30, (100, 400)),
                RaffleTicket('3', 70, (400, 1100))
            ]
        )
        self.algo._generate_satoshis = MagicMock(
            return_value=[
                333.4263245,
                400.0000000,
                955.3254322,
            ]
        )
        winners = self.algo._poll_lucky_tickets(self.transactions, '1')
        self.assertListEqual(winners, [
            RaffleTicket('2', 30, (100, 400)),
            RaffleTicket('3', 70, (400, 1100)),
            RaffleTicket('3', 70, (400, 1100)),
        ])

    def test_compute_gross_cashback_makes_a_good_average(self):
        gross_cashback = self.algo._compute_gross_cashback(self.transactions)
        self.assertEqual(
            gross_cashback,
            (10 + 30 + 70) * self.returned_rate / 3
        )

    def test_compute_gives_right_amount_of_cashback(self):
        self.algo._poll_lucky_tickets = MagicMock(
            return_value=[
                RaffleTicket('2', 30, (100, 400)),
                RaffleTicket('3', 70, (400, 1100)),
                RaffleTicket('3', 70, (400, 1100)),
            ])
        gross_cashback = (10 + 30 + 70) * self.returned_rate / 3

        cashing, cashbacks = self.algo.compute(self.transactions, '1')

        self.assertEqual(cashing, 9 + 21 + 21)
        self.assertListEqual(cashbacks, [
            pou.POUCashback('2', gross_cashback - 9),
            pou.POUCashback('3', gross_cashback - 21),
            pou.POUCashback('3', gross_cashback - 21)
        ])
