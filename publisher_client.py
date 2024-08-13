"""Publisher gRPC Client"""

import os
import functools
import logging

import grpc

import publisher_pb2
import publisher_pb2_grpc

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[Publisher gRPC Client]")


def get_channel():
    """Get the appropriate gRPC channel based on the mode.

    Returns:
        grpc.Channel: The gRPC channel.
    """
    secure_mode = os.environ.get("TLS")
    hostname = os.environ.get("PUBLISHER_HOST")
    port = os.environ.get("PUBLISHER_PORT")
    secure_port = os.environ.get("PUBLISHER_TLS_PORT")

    if secure_mode:
        logger.info(
            "Connecting to publisher gRPC server at %s:%s", hostname, secure_port
        )
        credentials = grpc.ssl_channel_credentials()
        logger.info("Using secure channel for gRPC communication")
        return grpc.secure_channel(f"{hostname}:{secure_port}", credentials)

    logger.info("Connecting to publisher gRPC server at %s:%s", hostname, port)
    logger.warning("Using insecure channel for gRPC communication")
    return grpc.insecure_channel(f"{hostname}:{port}")


def grpc_call(func):
    """Decorator to handle gRPC calls."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            channel = get_channel()

            with channel as conn:
                kwargs["stub"] = publisher_pb2_grpc.PublisherStub(conn)
                return func(*args, **kwargs)
        except grpc.RpcError as e:
            return None, e
        except Exception as e:
            raise e

    return wrapper


@grpc_call
def get_oauth2_auth_url(platform, **kwargs):
    """Request an OAuth2 authorization URL"""
    stub = kwargs["stub"]
    state = kwargs.get("state")
    code_verifier = kwargs.get("code_verifier")
    autogenerate_code_verifier = kwargs.get("autogenerate_code_verifier")
    redirect_url = kwargs.get("redirect_url")

    request = publisher_pb2.GetOAuth2AuthorizationUrlRequest(
        platform=platform,
        state=state,
        code_verifier=code_verifier,
        autogenerate_code_verifier=autogenerate_code_verifier,
        redirect_url=redirect_url,
    )

    response = stub.GetOAuth2AuthorizationUrl(request)
    return response, None


@grpc_call
def exchange_oauth2_auth_code(long_lived_token, platform, authorization_code, **kwargs):
    """Request to exchange OAuth2 authorization code for
    a token and store in the vault
    """
    stub = kwargs["stub"]
    code_verifier = kwargs.get("code_verifier")
    redirect_url = kwargs.get("redirect_url")

    request = publisher_pb2.ExchangeOAuth2CodeAndStoreRequest(
        long_lived_token=long_lived_token,
        platform=platform,
        authorization_code=authorization_code,
        code_verifier=code_verifier,
        redirect_url=redirect_url,
    )

    response = stub.ExchangeOAuth2CodeAndStore(request)
    return response, None


@grpc_call
def publish_content(content, **kwargs):
    """Request for publishing message to a target platform"""
    stub = kwargs["stub"]
    request = publisher_pb2.PublishContentRequest(content=content)

    response = stub.PublishContent(request)
    return response, None


@grpc_call
def revoke_oauth2_access_token(long_lived_token, platform, account, **kwargs):
    """Request for revoking and deleting an entity's access token in the vault"""
    stub = kwargs["stub"]
    request = publisher_pb2.RevokeAndDeleteOAuth2TokenRequest(
        long_lived_token=long_lived_token,
        platform=platform,
        account_identifier=account,
    )

    response = stub.RevokeAndDeleteOAuth2Token(request)
    return response, None


@grpc_call
def revoke_pnba_access_token(long_lived_token, platform, account, **kwargs):
    """Request for revoking and deleting an entity's access token in the vault"""
    stub = kwargs["stub"]
    request = publisher_pb2.RevokeAndDeletePNBATokenRequest(
        long_lived_token=long_lived_token,
        platform=platform,
        account_identifier=account,
    )

    response = stub.RevokeAndDeletePNBAToken(request)
    return response, None


@grpc_call
def get_pnba_code(platform, phone_number, **kwargs):
    """Request a PNBA code"""
    stub = kwargs["stub"]

    request = publisher_pb2.GetPNBACodeRequest(
        platform=platform,
        phone_number=phone_number,
    )

    response = stub.GetPNBACode(request)
    return response, None


@grpc_call
def exchange_pnba_auth_code(
    long_lived_token, platform, authorization_code, phone_number, **kwargs
):
    """Request to exchange PNBA code for a token and store in the vault"""
    stub = kwargs["stub"]
    password = kwargs.get("password")

    request = publisher_pb2.ExchangePNBACodeAndStoreRequest(
        long_lived_token=long_lived_token,
        platform=platform,
        authorization_code=authorization_code,
        phone_number=phone_number,
        password=password,
    )

    response = stub.ExchangePNBACodeAndStore(request)
    return response, None
