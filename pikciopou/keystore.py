import os
import shutil


class KeyStore(object):
    """Acts as a registrar for nodes public keys."""

    def __init__(self, store_path):
        """Creates a new empty KeyStore.

        :param: file_path: Path to the folder to store the keys. It will be
            created if missing.
        :type store_path: str
        """
        self._store_path = store_path

    def register_public_key(self, node_id, public_key):
        """Registers node's public key.

        :param node_id: The id of node declaring its public key.
        :type node_id: str
        :param public_key: The public key to declare.
        :type public_key: str
        """
        self._check_store()
        with open(self._key_file_name(node_id), 'w') as fd:
            fd.write(public_key)

    def public_key(self, node_id):
        """Searches this store for the public key matching the node.

        :param node_id: The id of the node whose public key is required.
        :return: The public key or None if node is not registered.
        :rtype: Union[str|None]
        """
        try:
            with open(self._key_file_name(node_id), 'r') as keyfile:
                return keyfile.read()
        except IOError:
            return None

    def _check_store(self):
        """Checks the store folder exists or create it."""
        if not os.path.isdir(self._store_path):
            os.makedirs(os.path.dirname(self._store_path), exist_ok=True)
            os.mkdir(self._store_path)

    def _key_file_name(self, node_id):
        """Gives the key file path matching node id.

        :param node_id: The node whose key is looked for.
        :return: The full path to the key file.
        :rtype: str
        """
        return os.path.join(self._store_path, '{}.pub'.format(node_id))

    def clear(self):
        """Removes all the keys from this keystore."""
        if os.path.exists(self._store_path):
            shutil.rmtree(self._store_path)
