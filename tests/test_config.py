import os
import sys
import unittest

import pikciopou.config as config


class TestConfig(unittest.TestCase):
    """Tests the config module."""

    def setUp(self):
        config.Config._singleton = None
        self.original_argv = sys.argv

    def tearDown(self):
        sys.argv = self.original_argv
        if config.Config._ENV_MASTERNODES_COUNT in os.environ:
            del os.environ[config.Config._ENV_MASTERNODES_COUNT]

    def test_config_is_lazily_created(self):
        self.assertIsNone(config.Config._singleton)

        conf = config.Config.app_config()
        self.assertIsNotNone(config.Config._singleton)
        self.assertEquals(conf, config.Config._singleton)

    def test_config_has_default_values_when_nothing_else(self):
        conf = config.Config.app_config()

        self.assertNotEquals(conf.masternodes_count, 0)
        self.assertNotEquals(conf.cashingnodes_count, 0)
        self.assertNotEquals(conf.consumernodes_count, 0)
        self.assertNotEquals(conf.block_time, 0)
        self.assertNotEquals(conf.fees_rate, 0.)
        self.assertNotEquals(conf.retribute_rate, 0.)
        self.assertNotEquals(conf.total_assets, 0.)

    def test_config_catches_environment_variable(self):
        os.environ[config.Config._ENV_MASTERNODES_COUNT] = "10"

        conf = config.Config.app_config()

        self.assertEquals(conf.masternodes_count, 10)

    def test_command_line_has_highest_priority(self):
        os.environ[config.Config._ENV_MASTERNODES_COUNT] = "10"
        sys.argv = ['app_path', '-mac', '30']

        conf = config.Config.app_config()

        self.assertEquals(conf.masternodes_count, 30)
