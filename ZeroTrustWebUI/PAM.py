import secrets
import string
import tss
import base64

class PAM:
    @staticmethod
    def generate_secret_shares(threshold, num_shares, secret_key, identifier):
        # Ensure the secret key is bytes
        secret_key_bytes = secret_key.encode('utf-8')
        # Ensure the identifier is bytes
        identifier_bytes = identifier.encode('utf-8')
        shares = tss.share_secret(threshold, num_shares, secret_key_bytes, identifier_bytes, tss.Hash.SHA256)
        # Encode shares in Base64
        base64_shares = [base64.b64encode(share).decode('utf-8') for share in shares]
        return base64_shares

    @staticmethod
    def generate_and_reconstruct_secret(threshold, num_shares, secret, identifier):
        shares = tss.share_secret(threshold, num_shares, secret, identifier, tss.Hash.SHA256)
        # Encode shares in Base64
        base64_shares = [base64.b64encode(share).decode() for share in shares]

        # Reconstruct the secret from Base64-encoded shares
        binary_shares = [base64.b64decode(share.encode()) for share in base64_shares]

        try:
            # Recover the secret value
            reconstructed_secret = tss.reconstruct_secret(binary_shares)
            return reconstructed_secret
        except tss.TSSError:
            return None  # Handling error

    @staticmethod
    def reconstruct_secret_from_base64_shares(base64_shares):
        # Reconstruct the secret from Base64-encoded shares
        binary_shares = [base64.b64decode(share.encode('utf-8')) for share in base64_shares]

        try:
            # Recover the secret value (likely returns bytes)
            reconstructed_secret_bytes = tss.reconstruct_secret(binary_shares)
            # Decode the bytes back to a string
            reconstructed_secret_string = reconstructed_secret_bytes.decode('utf-8')
            return reconstructed_secret_string
        except tss.TSSError:
            return None  # Handling error
        except UnicodeDecodeError:
             # Handle cases where the reconstructed bytes are not valid UTF-8
             # This might indicate an issue upstream or that a different encoding was used.
             print("Error decoding reconstructed secret bytes.")
             return None
        
    @staticmethod
    def generate_secret_message(length=20):
        alphabet = string.ascii_letters + string.digits  # Only letters and digits
        secret_message = ''.join(secrets.choice(alphabet) for _ in range(length))
        return secret_message


