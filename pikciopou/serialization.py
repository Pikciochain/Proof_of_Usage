import os
import json
import shutil

from pikciosc import compile, parse
from pikciosc.models import ContractInterface, ExecutionInfo

from pikciopou import crypto


class JSONSerializable(object):
    """Stands for an object that can be converted from and to JSON"""

    def to_dict(self):
        """Provides a dict representation of this object."""
        return self.__dict__

    def to_json(self):
        """Provides a JSON representation of this object."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_content):
        """Creates a new object from provided JSON string.

        :param json_content: The JSON version of the object.
        :type json_content: str
        """
        try:
            return cls.from_dict(json.loads(json_content))
        except (TypeError, ValueError):
            return None

    @classmethod
    def from_dict(cls, json_dct):
        """Creates a new object from provided dictionary.

        :param json_dct: The dictionary standing for the object.
        :type json_dct: dict
        :return: The created object
        :rtype: cls
        """
        try:
            return cls.from_dict_unsecure(json_dct)
        except KeyError:
            return None

    @classmethod
    def from_dict_unsecure(cls, json_dct):
        """Function to implement in subclasses to provide construction."""
        raise NotImplementedError()


class Chain(object):
    """Manages a chain of objects (transactions, blocks). Objects are saved
    on disk.
    """

    def __init__(self, folder, from_json_func):
        """Creates a new Chain. The transaction will be stored under
        the provided directory that must exist.

        :param folder: The folder to store the objects on disk.
        :type folder: str
        :param from_json_func: Function to convert JSON to a model object.
        :type from_json_func: callable
        """
        self._folder = folder
        self._from_json = from_json_func

    def __iter__(self):
        for i in range(len(self)):
            yield self.get(i)

    def __reversed__(self):
        """Returns a reversed iterator on this chain's objects.

        :return: An iterator on this chain's objects.
        :rtype: iterator
        """
        for i in reversed(range(len(self))):
            yield self.get(i)

    def _check_folder(self):
        """Ensures the directory used by this Chain exists"""
        if not os.path.isdir(self._folder):
            os.makedirs(self._folder)

    def __len__(self):
        self._check_folder()
        return len(os.listdir(self._folder))

    def clear(self):
        """Removes all objects in this chain."""
        if os.path.isdir(self._folder):
            shutil.rmtree(self._folder)

    def _get_path(self, index):
        """Gives object file name depending of its index in the chain.

        :param index: The index of the object in the chain.
        :type index: int
        :return: File path to create or retrieve an object.
        :rtype: str
        """
        return os.path.join(self._folder, '{}.json'.format(index))

    def get(self, index):
        """Returns object in the chain with provided chain index.

        :param index: Index of the object in the chain.
        :type index: int
        :return: The object at the index or None in case object is corrupted.
        """
        count = len(self)
        if index < 0 or index >= count:
            raise IndexError('Invalid chain index {} on {}'.format(
                index, count
            ))
        with open(self._get_path(index), 'r') as txfile:
            return self._from_json(txfile.read())

    def push(self, obj):
        """Puts provided object on the chain.

        :param obj: object to push on top of this chain.
        :type obj: JSONSerializable
        """
        self._check_folder()
        with open(self._get_path(len(self)), 'w') as txfile:
            txfile.write(obj.to_json())

    def push_all(self, objs):
        """Shortcut for pushing a list of objects.

        :param objs: objects to push on top of this chain.
        :type objs: iterable
        """
        for obj in objs:
            self.push(obj)


class SCEnvironment(object):
    """Provides file system storage and retrieval for smart contracts."""

    def __init__(self, root_folder):
        """Creates a new SCEnvironment.

        :param root_folder: The folder where this environment is expected to
            set up.
        :type root_folder: str
        """
        self.bin_folder = os.path.join(root_folder, 'bin')
        self.abi_folder = os.path.join(root_folder, 'abi')
        self.exec_cache_folder = os.path.join(root_folder, 'exec_cache')

    def _check_folders(self):
        """Ensures the directories used by this SCEnvironment exist."""
        for _dir in (self.bin_folder, self.abi_folder, self.exec_cache_folder):
            if not os.path.isdir(_dir):
                os.makedirs(_dir)

    def _bin_path(self, sc_id):
        """Gives path to binaries for provided contract id."""
        return os.path.join(self.bin_folder, '{}.pyc'.format(sc_id))

    def _abi_path(self, sc_id):
        """Gives path to interface for provided contract id."""
        return os.path.join(self.abi_folder, '{}.json'.format(sc_id))

    def _cache_path(self, sc_id):
        """Gives path to cached last execution for provided contract id."""
        return os.path.join(self.exec_cache_folder, '{}.json'.format(sc_id))

    def add(self, sc_id, source_b64):
        """Adds a new contract to that environment.

        :param sc_id: The id of the pushed contract.
        :param source_b64: The code source of the contract, base64 encoded.
        """
        self._check_folders()
        source = crypto.base64_decode(source_b64)
        compile.compile_source(source, self._bin_path(sc_id))
        parse.parse_string(source, sc_id).to_file(self._abi_path(sc_id))

    def get_bin(self, sc_id):
        """Obtains binaries path for provided smart contract id.

        :param sc_id: Id of the contract to retrieve binaries for.
        :type sc_id: str
        :return: The path to the binaries, if any.
        :rtype: str
        """
        bin_path = self._bin_path(sc_id)
        return None if not os.path.exists(bin_path) else bin_path

    def get_abi(self, sc_id):
        """Obtains ABI for provided smart contract id.

        :param sc_id: Id of the contract to retrieve interface for.
        :type sc_id: str
        :return: The contract interface, if any.
        :rtype: ContractInterface
        """
        abi_path = self._abi_path(sc_id)
        return (
            None if not os.path.exists(abi_path) else
            ContractInterface.from_file(abi_path)
        )

    def is_execution_granted(self, sc_id, invoker_id):
        """Tells if provided contract can be executed by specified invoker
        node.

        :param sc_id: Id of Smart Contract to execute.
        :type sc_id: str
        :param invoker_id: Id of node requesting execution.
        :type invoker_id: str
        :return: True if access is granted to that node.
        :rtype: bool
        """
        # TODO: Define permissions somewhere in code.
        return os.path.exists(self._bin_path(sc_id))

    def cache_last_exec(self, sc_id, exec_info):
        """Puts provided execution info in cache.

        :param sc_id: Executed contract id.
        :type sc_id: str
        :param exec_info: Execution info for that contract.
        :type exec_info: ExecutionInfo
        """
        exec_info.to_file(self._cache_path(sc_id))

    def get_last_exec_in_cache(self, sc_id):
        """Check if the last execution for that contract is in cache and
        returns it if it is.

        :param sc_id: if of the contract to fetch last execution for.
        :type sc_id: str
        :return: the last execution or None if no cached execution was found.
        :rtype: ExecutionInfo
        """
        cached_exec = self._cache_path(sc_id)
        return (
            None if not os.path.exists(cached_exec) else
            ExecutionInfo.from_file(cached_exec)
        )
