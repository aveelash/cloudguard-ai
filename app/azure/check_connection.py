
from app.azure.session import get_azure_credential


def test_azure_connection():
    credential = get_azure_credential()

    token = credential.get_token(
        "https://management.azure.com/.default"
    )

    print("Azure authentication successful!")
    print("Access token received:", bool(token.token))


if __name__ == "__main__":
    test_azure_connection()
