"""Utility module"""

import os
import base64
import logging
import json
import argparse
import getpass

from cryptography.fernet import Fernet
from smswithoutborders_libsig.keypairs import x25519

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[Vault gRPC Client]")


def generate_keypair_and_pk(keystore_path):
    """
    Generate keypair and public key.

    Args:
        keystore_path (str): Path to the keystore.

    Returns:
        tuple: (public_key, keypair_object)
    """
    if os.path.isfile(keystore_path):
        os.remove(keystore_path)

    keypair = x25519(keystore_path)
    pk = keypair.init()
    return pk, keypair


def load_keypair_object(keypair):
    """
    Deserialize a serialized x25519 keypair object from bytes.

    Args:
        keypair (bytes): Serialized x25519 keypair object.

    Returns:
        x25519: Deserialized x25519 keypair object.
    """
    keypair_obj = x25519()
    return keypair_obj.deserialize(keypair)


def store_binary(file_path, data):
    """
    Store binary data to a file.

    Args:
        file_path (str): Path to the file.
        data (bytes): Binary data to store.
    """
    try:
        with open(file_path, "wb") as fb:
            fb.write(data)
    except IOError as e:
        print(f"Error writing to {file_path}: {e}")


def load_binary(file_path):
    """
    Load binary data from a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        bytes: Binary data read from the file.
    """
    try:
        with open(file_path, "rb") as fb:
            return fb.read()
    except IOError as e:
        print(f"Error reading from {file_path}: {e}")
        return b""


def store_json(file_path, data):
    """
    Store JSON data to a file.

    Args:
        file_path (str): Path to the file.
        data (dict): JSON data to store.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as fj:
            json.dump(data, fj, indent=2)
    except IOError as e:
        print(f"Error writing JSON to {file_path}: {e}")


def load_json(file_path):
    """
    Load JSON data from a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        dict: JSON data read from the file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as fj:
            return json.load(fj)
    except IOError as e:
        print(f"Error reading JSON from {file_path}: {e}")
        return {}


class Password(argparse.Action):
    """
    Custom argparse action to securely handle password input.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        """
        Overrides the __call__ method of argparse.Action to handle password input.

        If no password is provided via the command line, the user is prompted
        to enter a password securely using getpass.

        Args:
            parser (argparse.ArgumentParser): The argument parser object.
            namespace (argparse.Namespace): The namespace object where the
                                            parsed arguments are stored.
            values (str or None): The value of the password argument provided
                                  via the command line. If None, the user is
                                  prompted to enter a password.
            option_string (str or None): The option string that triggered this
                                         action. Defaults to None.
        """
        if values is None:
            values = getpass.getpass("Enter Password: ")

        setattr(namespace, self.dest, values)


def decrypt_llt(secret_key, llt_ciphertext):
    """
    Decrypts the given LLT.

    Args:
        secret_key (bytes): The secret key used for decryption.
        llt_ciphertext (bytes): The LLT ciphertext to be decrypted.

    Returns:
        str: The decrypted plaintext.
    """
    key = base64.urlsafe_b64encode(secret_key)
    fernet = Fernet(key)
    return fernet.decrypt(llt_ciphertext).decode("utf-8")
