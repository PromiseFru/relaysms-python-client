"""RelaySMs Demo Client"""

import sys
import logging
import base64
import argparse

from vault_client import create_an_entity, auth_an_entity, list_stored_tokens
from publisher_client import (
    get_oauth2_auth_url,
    exchange_oauth2_auth_code,
    publish_content,
)
from utils import (
    Password,
    generate_keypair_and_pk,
    store_binary,
    store_json,
    load_binary,
    load_json,
    load_keypair_object,
    decrypt_llt,
    compute_device_id,
    encrypt_and_encode_payload,
    encode_transmission_payload,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[Runner]")


def get_llt():
    """Retrieves and decrypts the Long-Lived Token."""
    server_data = load_json("data.json")
    server_pk = server_data["server_device_id_pub_key"]
    llt_ciphertext = server_data["long_lived_token"]
    did_keypair = load_keypair_object(load_binary("did_keypair.bin"))
    did_shared_key = did_keypair.agree(base64.b64decode(server_pk))
    return decrypt_llt(did_shared_key, base64.b64decode(llt_ciphertext))


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
                "phone_number": phone_number,
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
                "phone_number": phone_number,
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
    llt = get_llt()
    token_res, token_err = list_stored_tokens(long_lived_token=llt)

    if token_err:
        logger.error("%s - %s", token_err.code(), token_err.details())
        sys.exit(1)

    logger.info("%s", token_res.message)
    logger.info("%s", token_res.stored_tokens)
    sys.exit(0)


def store_tokens(platform, state, code_verifier, autogenerate_code_verifier):
    """
    Exchange OAuth2 Code and Store Access Token.
    """
    llt = get_llt()
    url_res, url_err = get_oauth2_auth_url(
        platform=platform,
        state=state,
        code_verifier=code_verifier,
        autogenerate_code_verifier=autogenerate_code_verifier,
    )

    if url_err:
        logger.error("%s - %s", url_err.code(), url_err.details())
        sys.exit(1)

    logger.info("%s", url_res.message)
    logger.info("State: %s", url_res.state)
    logger.info("Code Verifier: %s", url_res.code_verifier)
    logger.info("Authorization URL: %s", url_res.authorization_url)

    auth_code_res = input("Enter Authorization Code: ")
    store_res, store_err = exchange_oauth2_auth_code(
        long_lived_token=llt,
        authorization_code=auth_code_res,
        platform=platform,
        code_verifier=code_verifier,
    )

    if store_err:
        logger.error("%s - %s", store_err.code(), store_err.details())
        sys.exit(1)

    if not store_res.success:
        logger.error("%s", store_res.message)
        sys.exit(1)

    logger.info("%s", store_res.message)
    sys.exit(0)


def publish_message(message, platform):
    """"""
    server_data = load_json("data.json")
    phone_number = server_data["phone_number"]

    server_did_pk = server_data["server_device_id_pub_key"]
    did_keypair = load_keypair_object(load_binary("did_keypair.bin"))
    did_shared_key = did_keypair.agree(base64.b64decode(server_did_pk))

    server_pub_pk = server_data["server_publish_pub_key"]
    pub_keypair = load_keypair_object(load_binary("pub_keypair.bin"))
    pub_shared_key = pub_keypair.agree(base64.b64decode(server_pub_pk))

    device_id = compute_device_id(
        did_shared_key,
        phone_number,
        base64.b64encode(did_keypair.get_public_key()).decode("utf-8"),
    )

    payload, state = encrypt_and_encode_payload(
        pub_shared_key,
        base64.b64decode(server_pub_pk),
        message,
        client_publish_keystore_path="pub.db",
    )

    store_binary("client_state.bin", state)

    trans_content = encode_transmission_payload(payload, platform, device_id)

    pub_res, pub_err = publish_content(trans_content)

    if pub_err:
        logger.error("%s - %s", pub_err.code(), pub_err.details())
        sys.exit(1)

    if not pub_res.success:
        logger.error("%s", pub_res.message)
        sys.exit(1)

    logger.info("%s", pub_res.message)
    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Demo RelaySMS Client")
    parser.add_argument(
        "command",
        choices=["create", "auth", "list-tokens", "store-token", "publish"],
        help="Command to execute",
    )
    parser.add_argument("-n", "--phone_number", help="The entity's phone number")
    parser.add_argument(
        "-p", action=Password, nargs="?", dest="password", help="Enter your password"
    )
    parser.add_argument("-r", "--country_code", help="The entity's country code")
    parser.add_argument("--platform", help="The target platform")
    parser.add_argument(
        "--state", help="The state parameter for preventing CSRF attacks"
    )
    parser.add_argument("--code_verifier", help="The code verifier used for PKCE")
    parser.add_argument(
        "--auto_cv",
        help="Indicate if the code verifier should be auto-generated",
        action="store_true",
    )
    parser.add_argument("-m", "--message", help="The message to publish")

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
        if not args.platform:
            logger.error("Specify: --platform")
            sys.exit(1)

        store_tokens(args.platform, args.state, args.code_verifier, args.auto_cv)

    elif args.command == "publish":
        if not args.message or not args.platform:
            logger.error("Specify: --message, --platform")
            sys.exit(1)

        publish_message(args.message, args.platform)
