import json
import os
import shutil

from mock import patch, MagicMock, ANY
import unittest

import pikciopou.nodes as nodes
import pikciopou.serialization as serialization

CURRENT_DIRECTORY = os.path.dirname(__file__)
TEST_INTERMEDIATE_FOLDER = os.path.join(CURRENT_DIRECTORY, 'test')
TEST_CHAIN_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'chain')
TEST_ABI_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'abi')
TEST_BIN_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'bin')
TEST_EXEC_CACHE_FOLDER = os.path.join(TEST_INTERMEDIATE_FOLDER, 'exec_cache')


class DummySerializable(serialization.JSONSerializable):

    def __init__(self, val):
        self.val = val

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        return cls(json_dct['val'])

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.val == other.val


class TestJSONSerializable(unittest.TestCase):

    def setUp(self):
        self.obj = DummySerializable('1')

    def test_to_dict_returns__dict__by_default(self):
        self.assertIs(self.obj.to_dict(), self.obj.__dict__)

    def test_to_json_returns_valid_json(self):
        self.assertEquals(self.obj.to_json(), json.dumps(self.obj.to_dict()))

    def test_from_json_returns_original(self):
        self.assertEquals(
            DummySerializable.from_json(self.obj.to_json()),
            self.obj
        )

    def test_from_json_returns_none_in_case_of_invalid_json(self):
        self.assertIsNone(DummySerializable.from_json(""))
        self.assertIsNone(DummySerializable.from_json("qdsfdh"))

    def test_from_dict_returns_none_if_missing_attribute(self):
        self.assertIsNone(DummySerializable.from_dict({'fake': '3'}))

    def test_from_dict_unsecure_is_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            serialization.JSONSerializable.from_dict_unsecure(dict())


class TestChain(unittest.TestCase):
    """Tests the Chain class."""

    def setUp(self):
        self.chain = nodes.Chain(
            TEST_CHAIN_FOLDER,
            DummySerializable.from_json,
        )
        self.dummy1 = DummySerializable('1')
        self.dummy2 = DummySerializable('2')
        self.dummy3 = DummySerializable('3')

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
        self.chain.push(self.dummy1)
        self.chain.clear()
        self.assertFalse(os.path.exists(TEST_CHAIN_FOLDER))

    def test_push_creates_file(self):
        self.chain.push(self.dummy1)

        obj_file = os.path.join(TEST_CHAIN_FOLDER, '0.json')
        self.assertTrue(os.path.exists(obj_file))
        with open(obj_file) as key:
            self.assertEquals(key.read(), self.dummy1.to_json())

    def test_push_all_creates_files(self):
        self.chain.push_all((self.dummy1, self.dummy2))

        obj_file1 = os.path.join(TEST_CHAIN_FOLDER, '0.json')
        obj_file2 = os.path.join(TEST_CHAIN_FOLDER, '1.json')
        self.assertTrue(os.path.exists(obj_file1))
        self.assertTrue(os.path.exists(obj_file2))

    def test_get_returns_obj(self):
        self.chain.push(self.dummy1)
        self.assertEqual(self.chain.get(0), self.dummy1)

    def test_get_invalid_index_raises_exception(self):
        with self.assertRaises(IndexError):
            self.chain.get(3)

    def test_len_returns_number_of_objects(self):
        self.chain.push_all((self.dummy1, self.dummy2, self.dummy3))
        self.assertEqual(len(self.chain), 3)

    def test_iterator_returns_object_in_chain_order(self):
        self.chain.push_all((self.dummy1, self.dummy3, self.dummy2))
        self.assertListEqual(
            [obj for obj in self.chain],
            [self.dummy1, self.dummy3, self.dummy2]
        )

    def test_reversed_returns_object_in_reversed_chain_order(self):
        self.chain.push_all((self.dummy1, self.dummy3, self.dummy2))
        self.assertListEqual(
            list(reversed(self.chain)),
            [self.dummy2, self.dummy3, self.dummy1]
        )


class TestSCEnvironment(unittest.TestCase):

    def setUp(self):
        self.env = serialization.SCEnvironment(TEST_INTERMEDIATE_FOLDER)

    def tearDown(self):
        if os.path.exists(TEST_INTERMEDIATE_FOLDER):
            shutil.rmtree(TEST_INTERMEDIATE_FOLDER)

    def test_check_folders_creates_folders_correctly(self):
        self.env._check_folders()
        self.assertTrue(os.path.exists(TEST_ABI_FOLDER))
        self.assertTrue(os.path.exists(TEST_BIN_FOLDER))
        self.assertTrue(os.path.exists(TEST_EXEC_CACHE_FOLDER))

    def test_bin_path_returns_path_to_pyc_file(self):
        self.assertEquals(
            self.env._bin_path('2'),
            os.path.join(TEST_BIN_FOLDER, '2.pyc')
        )

    def test_abi_path_returns_path_to_json_file(self):
        self.assertEquals(
            self.env._abi_path('2'),
            os.path.join(TEST_ABI_FOLDER, '2.json')
        )

    def test_exec_cache_path_returns_path_to_json_file(self):
        self.assertEquals(
            self.env._cache_path(2),
            os.path.join(TEST_EXEC_CACHE_FOLDER, '2.json')
        )

    @patch('pikciosc.parse.parse_string')
    @patch('pikciosc.compile.compile_source')
    @patch('pikciopou.crypto.base64_decode')
    def test_add_compiles_and_creates_abi(self, decode_mock, compile_mock,
                                          parse_string_mock):
        self.env.add('sc_id', 'source_code_b64')

        decode_mock.assert_called_once_with('source_code_b64')
        compile_mock.assert_called_once_with(decode_mock(), ANY)
        parse_string_mock.assert_called_once_with(decode_mock(), 'sc_id')
        parse_string_mock().to_file.assert_called_once()

    @patch('os.path.exists')
    def test_get_bin_returns_bin_path_if_exists(self, exists_mock):
        exists_mock.return_value = True
        self.assertIsInstance(self.env.get_bin('2'), str)

    @patch('os.path.exists')
    def test_get_bin_returns_none_if_missing(self, exists_mock):
        exists_mock.return_value = False
        self.assertIsNone(self.env.get_bin('2'))

    @patch('pikciopou.serialization.ContractInterface')
    @patch('os.path.exists')
    def test_get_abi_returns_interface_if_exists(self, exists_mock,
                                                 interface_mock):
        exists_mock.return_value = True
        self.assertEquals(self.env.get_abi('2'), interface_mock.from_file())

    @patch('pikciopou.serialization.ContractInterface')
    @patch('os.path.exists')
    def test_get_abi_returns_none_if_missing(self, exists_mock,
                                             interface_mock):
        exists_mock.return_value = False
        self.assertIsNone(self.env.get_abi('2'))
        interface_mock.assert_not_called()

    @patch('os.path.exists')
    def test_is_execution_granted_returns_path_exists_val(self, exists_mock):
        self.env._bin_path = MagicMock()

        self.assertEqual(self.env.is_execution_granted('2', '3'),
                         exists_mock.return_value)
        self.env._bin_path.assert_called_once_with('2')

    def test_cache_last_exec_calls_exec_to_file(self):
        self.env._cache_path = MagicMock()
        exec_info = MagicMock()

        self.env.cache_last_exec('2', exec_info)

        self.env._cache_path.assert_called_once_with('2')
        exec_info.to_file.assert_called_once_with(self.env._cache_path())

    @patch('pikciopou.serialization.ExecutionInfo')
    @patch('os.path.exists')
    def test_get_last_exec_in_cache_returns_exec_if_exists(self, exists_mock,
                                                           exec_info_mock):
        exists_mock.return_value = True
        self.assertEquals(self.env.get_last_exec_in_cache('2'),
                          exec_info_mock.from_file.return_value)

    @patch('pikciopou.serialization.ExecutionInfo')
    @patch('os.path.exists')
    def test_get_last_exec_in_cache_returns_none_if_missing(self, exists_mock,
                                                            exec_info_mock):
        exists_mock.return_value = False
        self.assertIsNone(self.env.get_last_exec_in_cache('2'))
        exec_info_mock.from_file.assert_not_called()
