"""Vault gRPC Client"""

import os
import functools
import logging

import grpc

import vault_pb2
import vault_pb2_grpc

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[Vault gRPC Client]")


def get_channel():
    """Get the appropriate gRPC channel based on the mode.

    Returns:
        grpc.Channel: The gRPC channel.
    """
    secure_mode = os.environ.get("TLS")
    hostname = os.environ.get("VAULT_HOST")
    port = os.environ.get("VAULT_PORT")
    secure_port = os.environ.get("VAULT_TLS_PORT")
    root_certificates_path = os.environ.get("ROOT_CERTIFICATE_PATH")

    if secure_mode:
        root_certificates = None
        if root_certificates_path:
            with open(root_certificates_path, "rb") as f:
                root_certificates = f.read()

        logger.info("Connecting to vault gRPC server at %s:%s", hostname, secure_port)
        credentials = grpc.ssl_channel_credentials(root_certificates=root_certificates)
        logger.info("Using secure channel for gRPC communication")
        return grpc.secure_channel(f"{hostname}:{secure_port}", credentials)

    logger.info("Connecting to vault gRPC server at %s:%s", hostname, port)
    logger.warning("Using insecure channel for gRPC communication")
    return grpc.insecure_channel(f"{hostname}:{port}")


def grpc_call(func):
    """Decorator to handle gRPC calls."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            channel = get_channel()

            with channel as conn:
                kwargs["stub"] = vault_pb2_grpc.EntityStub(conn)
                return func(*args, **kwargs)
        except grpc.RpcError as e:
            return None, e
        except Exception as e:
            raise e

    return wrapper


@grpc_call
def create_an_entity(phone_number, **kwargs):
    """Request to create an entity"""
    stub = kwargs["stub"]
    country_code = kwargs.get("country_code")
    password = kwargs.get("password")
    client_publish_pub_key = kwargs.get("client_publish_pub_key")
    client_device_id_pub_key = kwargs.get("client_device_id_pub_key")
    ownership_proof_response = kwargs.get("ownership_proof_response")

    request = vault_pb2.CreateEntityRequest(
        phone_number=phone_number,
        country_code=country_code,
        password=password,
        client_publish_pub_key=client_publish_pub_key,
        client_device_id_pub_key=client_device_id_pub_key,
        ownership_proof_response=ownership_proof_response,
    )

    response = stub.CreateEntity(request)
    return response, None


@grpc_call
def auth_an_entity(phone_number, **kwargs):
    """Request to authenticate an existing entity"""
    stub = kwargs["stub"]
    password = kwargs.get("password")
    client_publish_pub_key = kwargs.get("client_publish_pub_key")
    client_device_id_pub_key = kwargs.get("client_device_id_pub_key")
    ownership_proof_response = kwargs.get("ownership_proof_response")

    request = vault_pb2.AuthenticateEntityRequest(
        phone_number=phone_number,
        password=password,
        client_publish_pub_key=client_publish_pub_key,
        client_device_id_pub_key=client_device_id_pub_key,
        ownership_proof_response=ownership_proof_response,
    )

    response = stub.AuthenticateEntity(request)
    return response, None


@grpc_call
def list_stored_tokens(long_lived_token, **kwargs):
    """Request to list an entity's stored tokens"""
    stub = kwargs["stub"]

    request = vault_pb2.ListEntityStoredTokensRequest(long_lived_token=long_lived_token)

    response = stub.ListEntityStoredTokens(request)
    return response, None


@grpc_call
def delete_an_entity(long_lived_token, **kwargs):
    """Request to delete an entity"""
    stub = kwargs["stub"]

    request = vault_pb2.DeleteEntityRequest(long_lived_token=long_lived_token)

    response = stub.DeleteEntity(request)
    return response, None


@grpc_call
def reset_password(phone_number, **kwargs):
    """Request to reset and entity's password"""
    stub = kwargs["stub"]
    new_password = kwargs.get("new_password")
    client_publish_pub_key = kwargs.get("client_publish_pub_key")
    client_device_id_pub_key = kwargs.get("client_device_id_pub_key")
    ownership_proof_response = kwargs.get("ownership_proof_response")

    request = vault_pb2.ResetPasswordRequest(
        phone_number=phone_number,
        new_password=new_password,
        client_publish_pub_key=client_publish_pub_key,
        client_device_id_pub_key=client_device_id_pub_key,
        ownership_proof_response=ownership_proof_response,
    )

    response = stub.ResetPassword(request)
    return response, None
