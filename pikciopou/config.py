"""Handles configuration settings for the project.

Parameters precedence is defined as following:
    1. Command line arguments,
    2. Environment variables,
    3. Default settings in this file.
"""
from argparse import ArgumentParser
from os import environ, path

from pikciosc.quotations import ENV_PKC_SC_SUBMIT_CHAR_COST, \
    ENV_PKC_SC_EXEC_LINE_COST


class Config(object):
    """Single entrypoint for getting parameters"""

    # Define all environment variables used for configuration
    _ENV_MASTERNODES_COUNT = 'POU_MASTERNODES_COUNT'
    _ENV_CASHINGNODES_COUNT = 'POU_CASHINGNODES_COUNT'
    _ENV_CONSUMERNODES_COUNT = 'POU_CONSUMERNODES_COUNT'
    _ENV_TRUSTEDNODES_COUNT = 'POU_TRUSTEDNODES_COUNT'
    _ENV_BLOCK_TIME = 'POU_BLOCK_TIME'
    _ENV_FEES_RATE = 'POU_FEES_RATE'
    _ENV_RETRIBUTE_RATE = 'POU_RETRIBUTION_RATE'
    _ENV_TOTAL_ASSETS = 'POU_TOTAL_ASSETS'

    _singleton = None
    """Global config used across application, unless specified."""

    @classmethod
    def app_config(cls):
        """Obtains the global configuration shared across the application."""
        cls._singleton = cls._singleton or cls().load()
        return cls._singleton

    def __init__(self):
        """Creates a new empty configuration. Use load() to build it."""
        self.masternodes_count = 0      # Number of master nodes
        self.cashingnodes_count = 0     # Number of cashing nodes
        self.consumernodes_count = 0    # Number of consumer nodes
        self.trustednodes_count = 0     # Number of nodes giving certificates
        self.block_time = 0             # Cycle duration in seconds
        self.fees_rate = 0.             # % of amount to take as a fee.
        self.retribute_rate = 0.        # % of Tx fees earned by master nodes
        self.total_assets = 0.          # Total amount of PKC on the market.
        self.local_test = False
        self.remote_master = None

        parent_folder = path.dirname(path.dirname(__file__))
        self.output_folder = path.join(parent_folder, 'output')
        self.keystore_path = path.join(self.output_folder, 'keystore')
        self.masternodes_folder = path.join(self.output_folder, 'masternodes')
        self.consumernodes_folder = path.join(
            self.output_folder, 'consumernodes'
        )
        self.cashingnodes_folder = path.join(
            self.output_folder, 'cashingnodes'
        )
        self.trustednodes_folder = path.join(
            self.output_folder, 'trustednodes'
        )

    def load(self):
        """Loads (or reloads) the configuration settings into this object.

        :returns: This config.
        :rtype: Config
        """
        parser = ArgumentParser(
            description='blockchain: proof of usage'
        )
        parser.add_argument(
            "-mac",
            "--masternodes-count",
            dest="masternodes_count",
            type=int,
            help='Number of master nodes',
            default=environ.get(self._ENV_MASTERNODES_COUNT, 11)
        )
        parser.add_argument(
            "-cac",
            "--cashingnodes-count",
            dest="cashingnodes_count",
            type=int,
            help='Number of cashing nodes',
            default=environ.get(self._ENV_CASHINGNODES_COUNT, 1)
        )
        parser.add_argument(
            "-coc",
            "--consumernodes-count",
            dest="consumernodes_count",
            type=int,
            help='Number of consumer nodes',
            default=environ.get(self._ENV_CONSUMERNODES_COUNT, 10)
        )
        parser.add_argument(
            "-trc",
            "--trustednodes-count",
            dest="trustednodes_count",
            type=int,
            help='Number of trusted nodes',
            default=environ.get(self._ENV_TRUSTEDNODES_COUNT, 1)
        )
        parser.add_argument(
            "-bt",
            "--blocktime",
            dest="blocktime",
            type=int,
            help='Cycle duration in seconds',
            default=environ.get(self._ENV_BLOCK_TIME, 5)
        )
        parser.add_argument(
            "-fr",
            "--fees-rate",
            dest="fees_rate",
            type=float,
            help='Percentage of transaction amount taken as a fee',
            default=environ.get(self._ENV_FEES_RATE, 0.05)
        )
        parser.add_argument(
            "-rr",
            "--retribution-rate",
            dest="retribution_rate",
            type=float,
            help='Percentage of transaction fees earned by master nodes',
            default=environ.get(self._ENV_RETRIBUTE_RATE, 0.1)
        )
        parser.add_argument(
            "-ta",
            "--total-assets",
            dest="total_assets",
            type=float,
            help='Initial amount of assets in the market',
            default=environ.get(self._ENV_TOTAL_ASSETS, 83300000)
        )
        parser.add_argument(
            "-l",
            "--local",
            dest="local_test",
            action="store_true",
            help='Requires a local test instead of a remote one',
            default=False
        )
        parser.add_argument(
            "-rm",
            "--remote-master",
            dest="remote_master",
            type=int,
            help='Index of master to run a remote master node.',
            default=None
        )
        args, _ = parser.parse_known_args()

        self.masternodes_count = args.masternodes_count
        self.cashingnodes_count = args.cashingnodes_count
        self.consumernodes_count = args.consumernodes_count
        self.trustednodes_count = args.trustednodes_count
        self.block_time = args.blocktime
        self.fees_rate = args.fees_rate
        self.retribute_rate = args.retribution_rate
        self.total_assets = args.total_assets
        self.local_test = args.local_test
        self.remote_master = args.remote_master
        if ENV_PKC_SC_SUBMIT_CHAR_COST not in environ:
            environ[ENV_PKC_SC_SUBMIT_CHAR_COST] = '0.1'
        if ENV_PKC_SC_EXEC_LINE_COST not in environ:
            environ[ENV_PKC_SC_EXEC_LINE_COST] = '0.2'

        return self
