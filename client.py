"""RelaySMs Demo Client"""

import sys
import logging
import base64
import argparse

from vault_client import create_an_entity, auth_an_entity, list_stored_tokens
from utils import (
    Password,
    generate_keypair_and_pk,
    store_binary,
    store_json,
    load_binary,
    load_json,
    load_keypair_object,
    decrypt_llt,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[Runner]")


def create_entity(phone_number, country_code, password):
    """
    Creates an entity.

    Args:
        phone_number (str): The phone number of the entity.
        country_code (str): The country code of the entity's phone number.
        password (str): The password for authentication.
    """
    pub_pk, pub_keypair = generate_keypair_and_pk("pub.db")
    did_pk, did_keypair = generate_keypair_and_pk("did.db")

    init_res, init_err = create_an_entity(phone_number)

    if init_err:
        logger.error("%s - %s", init_err.code(), init_err.details())
        sys.exit(1)

    if init_res.requires_ownership_proof:
        logger.info("%s", init_res.message)
        pow_res = input("Enter Proof Response: ")
        fin_res, fin_err = create_an_entity(
            phone_number=phone_number,
            country_code=country_code,
            password=password,
            client_publish_pub_key=base64.b64encode(pub_pk).decode(),
            client_device_id_pub_key=base64.b64encode(did_pk).decode(),
            ownership_proof_response=pow_res,
        )

        if fin_err:
            logger.error("%s - %s", fin_err.code(), fin_err.details())
            sys.exit(1)

        logger.info("Storing server data")
        store_json(
            "data.json",
            {
                "server_publish_pub_key": fin_res.server_publish_pub_key,
                "server_device_id_pub_key": fin_res.server_device_id_pub_key,
                "long_lived_token": fin_res.long_lived_token,
            },
        )

        logger.info("Storing keypairs")
        store_binary("pub_keypair.bin", pub_keypair.serialize())
        store_binary("did_keypair.bin", did_keypair.serialize())

        logger.info("%s", fin_res.message)
        sys.exit(0)

    logger.error("Something went wrong")
    sys.exit(1)


def auth_entity(phone_number, password):
    """
    Authenticates an entity.

    Args:
        phone_number (str): The phone number of the entity.
        password (str): The password for authentication.
    """
    pub_pk, pub_keypair = generate_keypair_and_pk("pub.db")
    did_pk, did_keypair = generate_keypair_and_pk("did.db")

    init_res, init_err = auth_an_entity(phone_number=phone_number, password=password)

    if init_err:
        logger.error("%s - %s", init_err.code(), init_err.details())
        sys.exit(1)

    if init_res.requires_ownership_proof:
        logger.info("%s", init_res.message)
        pow_res = input("Enter Proof Response: ")
        fin_res, fin_err = auth_an_entity(
            phone_number=phone_number,
            client_publish_pub_key=base64.b64encode(pub_pk).decode(),
            client_device_id_pub_key=base64.b64encode(did_pk).decode(),
            ownership_proof_response=pow_res,
        )

        if fin_err:
            logger.error("%s - %s", fin_err.code(), fin_err.details())
            sys.exit(1)

        logger.info("Storing server data")
        store_json(
            "data.json",
            {
                "server_publish_pub_key": fin_res.server_publish_pub_key,
                "server_device_id_pub_key": fin_res.server_device_id_pub_key,
                "long_lived_token": fin_res.long_lived_token,
            },
        )

        logger.info("Storing keypairs")
        store_binary("pub_keypair.bin", pub_keypair.serialize())
        store_binary("did_keypair.bin", did_keypair.serialize())

        logger.info("%s", fin_res.message)
        sys.exit(0)

    logger.error("Something went wrong")
    sys.exit(1)


def list_tokens():
    """
    List an entity's stored tokens
    """
    server_data = load_json("data.json")
    server_pk = server_data["server_device_id_pub_key"]
    llt_ciphertext = server_data["long_lived_token"]
    did_keypair = load_keypair_object(load_binary("did_keypair.bin"))
    did_shared_key = did_keypair.agree(base64.b64decode(server_pk))
    llt = decrypt_llt(did_shared_key, base64.b64decode(llt_ciphertext))

    token_res, token_err = list_stored_tokens(long_lived_token=llt)

    if token_err:
        logger.error("%s - %s", token_err.code(), token_err.details())
        sys.exit(1)

    logger.info("%s", token_res.message)
    logger.info("%s", token_res.stored_tokens)
    sys.exit(0)


def store_tokens():
    """
    To be implemented.
    """
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo RelaySMS Client")
    parser.add_argument(
        "command",
        choices=["create", "auth", "list-tokens", "store-token"],
        help="Command to execute",
    )
    parser.add_argument("-n", "--phone_number", help="The entity's phone number")
    parser.add_argument(
        "-p", action=Password, nargs="?", dest="password", help="Enter your password"
    )
    parser.add_argument(
        "-r",
        "--country_code",
        help="The entity's country code",
    )
    args = parser.parse_args()

    if args.command == "create":
        if not args.phone_number or not args.country_code or not args.password:
            logger.error("Specify: --phone_number, --country_code, --password")
            sys.exit(1)

        create_entity(args.phone_number, args.country_code, args.password)

    elif args.command == "auth":
        if not args.phone_number or not args.password:
            logger.error("Specify: --phone_number, --password")
            sys.exit(1)

        auth_entity(args.phone_number, args.password)

    elif args.command == "list-tokens":
        list_tokens()

    elif args.command == "store-token":
        store_tokens()
