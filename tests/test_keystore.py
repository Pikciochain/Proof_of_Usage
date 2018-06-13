import os
import unittest
import shutil

import pikciopou.keystore as keystore


CURRENT_DIRECTORY = os.path.dirname(__file__)
TEST_INTERMEDIATE_FOLDER = os.path.join(CURRENT_DIRECTORY, 'test')
TEST_KEYSTORE_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'keystore')


class TestKeystore(unittest.TestCase):
    """Tests the keystore module."""

    def setUp(self):
        self.store = keystore.KeyStore(TEST_KEYSTORE_FOLDER)

    def tearDown(self):
        if os.path.exists(TEST_KEYSTORE_FOLDER):
            shutil.rmtree(TEST_KEYSTORE_FOLDER)
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            os.rmdir(TEST_INTERMEDIATE_FOLDER)

    def test_check_store_creates_folder_correctly(self):
        self.store._check_store()
        self.assertTrue(os.path.exists(TEST_KEYSTORE_FOLDER))

    def test_key_file_name_returns_correct_key_name(self):
        self.assertEquals(
            self.store._key_file_name('1234'),
            os.path.join(TEST_KEYSTORE_FOLDER, '1234.pub')
        )

    def test_clear_removes_keys(self):
        self.store.register_public_key('1234', 'key')
        self.store.clear()
        self.assertFalse(os.path.exists(TEST_KEYSTORE_FOLDER))

    def test_register_public_key_creates_key(self):
        self.store.register_public_key('1', 'key')

        key_file = os.path.join(TEST_KEYSTORE_FOLDER, '1.pub')
        self.assertTrue(os.path.exists(key_file))
        with open(key_file) as key:
            self.assertEquals(key.read(), 'key')

    def test_public_key_returns_key(self):
        self.store.register_public_key('1', 'key')
        self.assertEqual(self.store.public_key('1'), 'key')

    def test_get_missing_key_returns_none(self):
        self.assertIsNone(self.store.public_key('1'))
