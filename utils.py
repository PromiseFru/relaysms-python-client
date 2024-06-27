"""Utility module."""

import os
import struct
import base64
import logging
import json
import argparse
import getpass
import hmac
import hashlib
from cryptography.fernet import Fernet

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.ratchets import Ratchets, States, HEADERS

PLATFORM_INFO = {"gmail": {"shortcode": "g"}, "twitter": {"shortcode": "t"}}

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
        logger.error("Error writing to %s: %s", file_path, e)
        raise


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
        logger.error("Error reading from %s: %s", file_path, e)
        raise


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
        logger.error("Error writing JSON to %s: %s", file_path, e)
        raise


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
        logger.error("Error reading JSON from %s: %s", file_path, e)
        raise


class Password(argparse.Action):
    """
    Custom argparse action to securely handle password input.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        """
        Overrides the __call__ method to handle password input securely.

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
    Decrypts the given LLT ciphertext.

    Args:
        secret_key (bytes): The secret key used for decryption.
        llt_ciphertext (bytes): The LLT ciphertext to be decrypted.

    Returns:
        str: The decrypted plaintext.
    """
    key = base64.urlsafe_b64encode(secret_key)
    fernet = Fernet(key)
    return fernet.decrypt(llt_ciphertext).decode("utf-8")


def compute_device_id(secret_key, phone_number, device_id_public_key):
    """
    Compute a device ID using HMAC-SHA256.

    Args:
        secret_key (bytes): The secret key for HMAC.
        phone_number (str): The phone number.
        device_id_public_key (str): The device ID public key.

    Returns:
        bytes: The computed device ID.
    """
    combined_input = phone_number + device_id_public_key
    hmac_object = hmac.new(secret_key, combined_input.encode("utf-8"), hashlib.sha256)
    return hmac_object.digest()


def encrypt_and_encode_payload(
    publish_shared_key, peer_publish_pub_key, content, **kwargs
):
    """
    Encrypt and encode the payload for transmission.

    Args:
        publish_shared_key (bytes): Shared key for publishing.
        peer_publish_pub_key (bytes): Public key of the peer.
        content (str): Content to encrypt.
        **kwargs: Additional keyword arguments.

    Returns:
        tuple: (encoded payload, serialized state)
    """
    state_file_path = "client_state.bin"
    client_publish_keystore_path = kwargs.get("client_publish_keystore_path")

    if not os.path.isfile(state_file_path):
        state = States()
        Ratchets.alice_init(
            state,
            publish_shared_key,
            peer_publish_pub_key,
            client_publish_keystore_path,
        )
    else:
        state = States.deserialize(load_binary(state_file_path))

    header, content_ciphertext = Ratchets.encrypt(
        state, content.encode("utf-8"), peer_publish_pub_key
    )

    serialized_header = header.serialize()
    len_header = len(serialized_header)

    return (
        base64.b64encode(
            struct.pack("<i", len_header) + serialized_header + content_ciphertext
        ).decode("utf-8"),
        state.serialize(),
    )


def decode_and_decrypt_payload(content, publish_pub_key):
    """
    Decodes and decrypts the incoming payload.

    Args:
        content (str): The content to decrypt.
        publish_pub_key (bytes): The client's publish public key.

    Returns:
        str: The decoded payload
    """
    state_file_path = "client_state.bin"
    state = States.deserialize(load_binary(state_file_path))

    payload = base64.b64decode(content)
    len_header = struct.unpack("<i", payload[:4])[0]

    header = payload[4 : 4 + len_header]
    deserialized_header = HEADERS.deserialize(header)

    encrypted_content = payload[4 + len_header :]
    plaintext = Ratchets.decrypt(
        state, deserialized_header, encrypted_content, publish_pub_key
    )
    return plaintext.decode("utf-8")


def encode_transmission_payload(encrypted_content, platform, device_id):
    """
    Encode the payload for transmission.

    Args:
        encrypted_content (str): Encrypted content.
        platform (str): Platform identifier.
        device_id (bytes): Device ID.

    Returns:
        str: Base64 encoded transmission payload.
    """
    platform_letter = PLATFORM_INFO[platform]["shortcode"].encode("utf-8")
    content_ciphertext = base64.b64decode(encrypted_content)
    payload = (
        struct.pack("<i", len(content_ciphertext))
        + platform_letter
        + content_ciphertext
        + device_id
    )

    encoded_payload = base64.b64encode(payload).decode("utf-8")
    return encoded_payload
