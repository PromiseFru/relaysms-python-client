# RelaySMS Demo Client

The RelaySMS Demo Client is a command-line tool designed for managing entities.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Commands](#commands)
  - [Create Entity](#create-entity)
  - [Authenticate Entity](#authenticate-entity)
  - [List Tokens](#list-tokens)
  - [Store Token](#store-token)
  - [Publish Message](#publish-message)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/PromiseFru/relaysms-python-client.git
   cd relaysms-python-client
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To use the RelaySMS Demo Client, run the script with the desired command and
appropriate arguments. Below are the available commands and their descriptions.

## Commands

### Create Entity

Creates a new entity with the specified phone number, country code, and
password.

```bash
python relay_sms_client.py create -n <phone_number> -r <country_code> [-p]
```

### Authenticate Entity

Authenticates an existing entity using the phone number and password.

```bash
python relay_sms_client.py auth -n <phone_number> [-p]
```

### List Tokens

Lists the stored tokens for the authenticated entity.

```bash
python relay_sms_client.py list-tokens
```

### Store Token

Exchanges an OAuth2 authorization code and stores the access token.

```bash
python relay_sms_client.py store-token --platform <platform> --state <state> --code_verifier <code_verifier> [--auto_cv]
```

**Arguments:**

- `--platform`: The target platform (e.g., `gmail`, `twitter`).
- `--state`: The state parameter for preventing CSRF attacks.
- `--code_verifier`: The code verifier used for PKCE.
- `--auto_cv`: Indicate if the code verifier should be auto-generated.

### Publish Message

Publishes a message to the specified platform.

```bash
python relay_sms_client.py publish -m <message> --platform <platform>
```

**Arguments:**

- `-m`, `--message`: The message to publish.
- `--platform`: The target platform (e.g., `gmail`, `twitter`).

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any
improvements or new features.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/my-feature`).
3. Commit your changes (`git commit -am 'Add my feature'`).
4. Push to the branch (`git push origin feature/my-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.
