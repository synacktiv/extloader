import logging
from rich.logging import RichHandler
from rich.console import Console
from rich.panel import Panel
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

console = Console()

def setup_logging(level="INFO"):
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)]
    )
    return logging.getLogger("rich")

log = setup_logging()

def print_banner():
    banner = """
    ███████╗██╗  ██╗████████╗██╗      ██████╗  █████╗ ██████╗ ███████╗██████╗ 
    ██╔════╝╚██╗██╔╝╚══██╔══╝██║     ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
    █████╗   ╚███╔╝    ██║   ██║     ██║   ██║███████║██║  ██║█████╗  ██████╔╝
    ██╔══╝   ██╔██╗    ██║   ██║     ██║   ██║██╔══██║██║  ██║██╔══╝  ██╔══██╗
    ███████╗██╔╝ ██╗   ██║   ███████╗╚██████╔╝██║  ██║██████╔╝███████╗██║  ██║
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
    """
    console.print(Panel(banner, border_style="bold green"))

def generate_extension_keys() -> tuple[str, str, str]:
    """
    Generate RSA key pair and CRX ID for Chrome extension.
    
    Returns:
        tuple: A tuple containing (crx_id, public_key, private_key) as base64 strings
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    except Exception as e:
        raise Exception(f"Failed to generate RSA key: {e}")

    public_key = private_key.public_key()

    try:
        pub_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        raise Exception(f"Failed to marshal public key: {e}")

    # Compute SHA-256 hash and generate CRX ID
    sha256_hash = hashlib.sha256(pub_key_bytes).digest()
    crx_id = translate_crx_id(sha256_hash[:16].hex())

    # Encode public key in b64
    pub_key = base64.b64encode(pub_key_bytes).decode('utf-8')

    try:
        priv_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    except Exception as e:
        raise Exception(f"Failed to serialize private key: {e}")

    # Encode private key in b64
    priv_key = base64.b64encode(priv_key_bytes).decode('utf-8')

    return crx_id, pub_key, priv_key

def translate_crx_id(input_str: str) -> str:
    """
    Translate hex characters to Chrome extension ID format.
    
    Args:
        input_str: Hex string to translate
        
    Returns:
        str: Translated Chrome extension ID
    """
    translation = {
        '0': 'a', '1': 'b', '2': 'c', '3': 'd',
        '4': 'e', '5': 'f', '6': 'g', '7': 'h',
        '8': 'i', '9': 'j', 'a': 'k', 'b': 'l',
        'c': 'm', 'd': 'n', 'e': 'o', 'f': 'p',
    }

    return ''.join(translation.get(c, c) for c in input_str)
