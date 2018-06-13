"""Contains all the features related to the redistribution of fees based on a
proof of usage.
"""
from collections import namedtuple

import itertools

from pikciopou import crypto

POUCashback = namedtuple('POUCashback', 'node_id amount')
"""Stands for the amount to return to a lucky stakeholder selected by poll."""


class ProofOfUsageAlgorithm(object):
    """Computes fees to be redistributed to stakeholders based on their
    activity in a set of transactions.
    """

    _SATOSHI_PRECISION = 8
    """Number of decimals of a Satoshi, the smallest fraction of an asset."""

    RaffleTicket = namedtuple('RaffleTicket', 'node_id fees lucky_range')
    """Gives for a node the slice of transactions amount that makes it win."""

    def __init__(self, returned_rate):
        """Creates a new ProofOfUsageAlgorithm.

        :param returned_rate: Tells the rate of fees that is redistributed as
            a cashback. It is usually (1 - master node retribution)
        :type returned_rate: float
        """
        self.returned_rate = returned_rate

    def _generate_raffle_tickets(self, transactions):
        """Generates for each sender in provided transactions a ticket to
        possibly win some cashback on the transaction fees.

        Each ticket identifies a sender node, tells how much fees were taken
        out of his transaction and defines a "lucky range".

        The lucky range is a slice of the total amount of fees that determines
        if the node is going to win. During the poll, if a satoshi (an amount
        with high precision) falls into that slice, the node wins cashback.

        The cashback prize is a share of the total amount of redistributed fees
        equally split between each winner. However, the prize always exclude
        the amount of fees collected on the transaction issuing the ticket, to
        prevent fraud.

        :param transactions: The transactions used to generate the tickets.
        :type transactions: list[Transaction]
        :return: The tickets to enter the raffle.
        :rtype: list[RaffleTicket]
        """
        amounts = [0] + [tx.content.amount for tx in transactions]
        accumulated_amounts = tuple(itertools.accumulate(amounts))

        # accumulated_amounts give slices based on amounts collected.
        # e.g. [1, 3, 2] --> [1, 4, 6] and slices are (0, 1), (1, 4), (4, 6)
        # The padded '0' is used to create the first slice.
        return [
            self.RaffleTicket(
                transaction.content.sender_id,
                transaction.stamp.fees,
                (accumulated_amounts[index], accumulated_amounts[index + 1])
            )
            for index, transaction in enumerate(transactions)
        ]

    def _satoshi(self, seed, max_amount):
        """Creates a Satoshi that falls within a max amount based on a seed.

        The Satoshi here is a positive atomic fraction of assets that will be
        searched in raffle tickets. For example, with a max amount of
        10,000 PKC, this method could generate the atomic 8,637.32345632 PKC.
        :param seed: A SHA256 seed that is derived to give the Satoshi. Since
            the derivation is not random, the same feed will always give the
            same Satoshi.
        :type seed: str
        :param max_amount: Upper bound of the destination set [0, max_amount]
        :type max_amount: float
        :return: The generated Satoshi.
        :rtype: float
        """
        return (int(seed, 16) / pow(10, self._SATOSHI_PRECISION)) % max_amount

    def _generate_satoshis(self, transactions, salt):
        """From a set of transaction and a salt, generates Satoshis to be used
        to poll winning tickets that which should get cashback.

        :param transactions: The list of transactions to generate Satoshis. One
            Satoshi will be generated per transaction.
        :type transactions: list[Transaction]
        :param salt: A salt to ensure the same transaction never gives the same
            Satoshi.
        :type salt: str
        :return: The list of generated Satoshis, one per transaction.
        :rtype: list[str]
        """
        # The seeds are based on senders ids and the provided salt.
        # Both should be stable and pretty unique
        seeds = (
            crypto.get_hash(salt + tx.content.sender_id)
            for tx in transactions
        )

        # Satoshis destination set is [0, total_amount]
        total_amount = sum(tx.content.amount for tx in transactions)
        return [self._satoshi(seed, total_amount) for seed in seeds]

    def _poll_lucky_tickets(self, transactions, seed):
        """Finds lucky stakeholders to redistribute a part of the fees
        collected on provided transactions.

        :param transactions: The transaction required to proceed to a raffle.
        :type transactions: list[Transaction]
        :param seed: A SHA256 seed to add some randomness in winners selection.
        :type seed: str
        :return: A list of winning raffle tickets. A ticket can be duplicated
            if it won several times. Each occurrence of each ticket should let
            its owner win some cashback.
        :rtype: list[RaffleTicket]
        """
        # Generates tickets and Satoshis to find in tickets lucky ranges
        raffle_tickets = self._generate_raffle_tickets(transactions)
        satoshis = self._generate_satoshis(transactions, seed)

        # Proceed to selection of winning tickets by finding the ones who
        # contains the Satoshis.
        return [
            ticket
            for satoshi in satoshis
            for ticket in raffle_tickets
            if ticket.lucky_range[0] <= satoshi < ticket.lucky_range[1]
        ]

    def _compute_gross_cashback(self, transactions):
        """Computes the gross amount of cashback each winner of a raffle based
        on provided transactions is expecting to win.

        This amount is gross, as fees paid on the lucky range containing the
        Satoshi still needs to be removed. The number of winners is the number
        of transactions.

        The masternode doesn't redistribute all the fees, only part of it as it
        is itself rewarded for its active role.

        :param transactions: The transactions giving the amount of transaction
            fees collected as well as the number of winners.
        :type transactions: list[Transaction]
        :return: The gross cashback redistributed to each winner.
        :rtype: float
        """
        total_fees = sum(tx.stamp.fees for tx in transactions)
        return (total_fees * self.returned_rate) / len(transactions)

    def compute(self, transactions, seed):
        """Applies the Pikcio Proof Of Usage algorithm to compute the cashback
        earned by lucky stakeholders which have sent assets in provided
        transactions.

        In addition to the regular cashback, part of the fees are collected to
        be sent to a cashing node that will redistribute them to the community.

        :param transactions: List of transactions to use to redistribute fees.
        :type transactions: list[Transaction]
        :param seed: a SHA256 used to generate algorithm components. It should
            be the hash of the previous block (or a random for the first block)
        :type seed: str
        :return: The resulting tuple cashing/cashbacks that should be used to
            generate transactions.
        :rtype: tuple[float,POUCashback]
        """
        # Find the lucky stakeholders
        lucky_tickets = self._poll_lucky_tickets(transactions, seed)

        # Compute how much they get. Note that they can't get anything from the
        # fees that are part of the winning transaction that made them win.
        gross_cashback_per_winner = self._compute_gross_cashback(transactions)

        # Each stakeholder can't win the fees part of its own transaction, so
        # we have to deduce that part from the gross cashback:
        #   - We know that only "returned_rate" is redistributed
        #   - The part of each transaction fee in each cashback is 1/nb_txs
        # So the amount of fee to tax is:
        taxed_fee = self.returned_rate / len(transactions)
        cashbacks = [
            POUCashback(
                ticket.node_id,
                gross_cashback_per_winner - ticket.fees * taxed_fee
            )
            for ticket in lucky_tickets
        ]

        # Collect cashing: it is the total taxed amount on each cashback.
        cashing = sum(
            gross_cashback_per_winner - cashback.amount
            for cashback in cashbacks
        )
        return cashing, cashbacks
