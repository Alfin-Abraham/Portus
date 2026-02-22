"""
SSL Certificate Generator for Portus LAN File Sharing

This script generates:
  A Root CA (Certificate Authority) 
  A server certificate signed by the Root CA
  An iOS .mobileconfig profile containing the Root CA

All certificates are configured for mDNS (portus.local domain)"""

# Standard library imports
import os
import socket
import uuid
import plistlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

# Third-party imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ----------------------------------
# CONFIGURATION
# ----------------------------------

class CertConfig:
    """Certificate generation configuration."""
    # Key sizes
    ROOT_KEY_SIZE = 4096
    SERVER_KEY_SIZE = 2048

    # Validity
    VALIDITY_DAYS = 397

    # Certificate subject information
    COUNTRY = "US"
    STATE = "Local"
    LOCALITY = "Local"
    ORG_NAME = "Portus File Share"
    ROOT_COMMON_NAME = "Portus Root CA"
    SERVER_COMMON_NAME = "Portus"

    # mDNS domain
    MDNS_DOMAIN = "portus.local"

    # Output directory and files
    OUT_DIR = "Portus_Certificates"
    OUT_ROOT_KEY = os.path.join(OUT_DIR, "root_key.pem")
    OUT_ROOT_PEM = os.path.join(OUT_DIR, "root_cert.pem")
    OUT_ROOT_DER = os.path.join(OUT_DIR, "root_cert.cer")
    OUT_SERVER_KEY = os.path.join(OUT_DIR, "server_key.pem")
    OUT_SERVER_PEM = os.path.join(OUT_DIR, "server_cert.pem")
    OUT_MOBILECONFIG = os.path.join(OUT_DIR, "root_ca.mobileconfig")


# ----------------------------------
# UTILITY FUNCTIONS
# ----------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def detect_hostname() -> Optional[str]:
    """
    Gets the system hostname for certificate Subject Alternative Names.
    Returns None if system hostname is not usable.
    """
    try:
        hostname = socket.gethostname()
        if hostname and hostname not in ["localhost", "portus"]:
            return hostname
    except Exception:
        pass
    return None


def write_bytes(path: str, data: bytes) -> None:
    """Writes binary data to a file."""
    with open(path, "wb") as f:
        f.write(data)
    print(f"Wrote {path}")


def ensure_output_dir() -> None:
   os.makedirs(CertConfig.OUT_DIR, exist_ok=True)


# ----------------------------------
# CERTIFICATE GENERATION
# ----------------------------------

def _build_root_ca_subject() -> x509.Name:
    """Builds the Subject Distinguished Name for the Root CA."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CertConfig.COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CertConfig.STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, CertConfig.LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CertConfig.ORG_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, CertConfig.ROOT_COMMON_NAME),
    ])


def _build_server_subject() -> x509.Name:
    """Builds the Subject Distinguished Name for the server certificate."""
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CertConfig.COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CertConfig.STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, CertConfig.LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CertConfig.ORG_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, CertConfig.SERVER_COMMON_NAME),
    ])


def _build_san_list() -> list:
    """Builds Subject Alternative Names for the server certificate."""
    san_list = [
        x509.DNSName(CertConfig.MDNS_DOMAIN),
        x509.DNSName(CertConfig.SERVER_COMMON_NAME)
    ]

    # Add system hostname if available
    hostname = detect_hostname()
    if hostname:
        san_list.append(x509.DNSName(hostname))
        san_list.append(x509.DNSName(f"{hostname}.local"))

    return san_list


def generate_root_ca() -> Tuple:
    """
    Generates a Root CA certificate and private key.
    Returns: a tuple of (private_key, certificate)
    """
    print("")
    print("-" * 50)
    print("Generating Root CA private key.")
    
    # Generate private key
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CertConfig.ROOT_KEY_SIZE,
        backend=default_backend()
    )

    subject = issuer = _build_root_ca_subject()
    not_before = now_utc() - timedelta(days=1)
    not_after = now_utc() + timedelta(days=CertConfig.VALIDITY_DAYS)

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(root_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    # Add CA extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    # Add key identifiers
    ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        ),
        critical=False
    )

    # Sign the certificate
    root_cert = builder.sign(
        private_key=root_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Export certificates and key
    write_bytes(
        CertConfig.OUT_ROOT_KEY,
        root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    write_bytes(
        CertConfig.OUT_ROOT_PEM,
        root_cert.public_bytes(serialization.Encoding.PEM)
    )
    write_bytes(
        CertConfig.OUT_ROOT_DER,
        root_cert.public_bytes(serialization.Encoding.DER)
    )

    print("Root CA created.")
    print("-" * 50)
    print("")
    return root_key, root_cert


def generate_server_cert(root_key, root_cert) -> Tuple:
    """
    Generates a server certificate signed by the Root CA.
    Args:
        root_key: Root CA private key
        root_cert: Root CA certificate 
    Returns:
        A tuple of (server_private_key, server_certificate)
    """
    print("-" * 50)
    print("Generating server key and certificate signed by Root CA.")
    
    # Generate server private key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=CertConfig.SERVER_KEY_SIZE,
        backend=default_backend()
    )

    subject = _build_server_subject()
    san_list = _build_san_list()
    
    not_before = now_utc() - timedelta(days=1)
    not_after = now_utc() + timedelta(days=CertConfig.VALIDITY_DAYS)

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(root_cert.subject)
    builder = builder.public_key(server_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    # Add extensions
    builder = builder.add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    )

    # Add key identifiers
    ski = x509.SubjectKeyIdentifier.from_public_key(server_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    # Compute Authority Key Identifier from root cert
    try:
        root_ski_ext = root_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=root_ski_ext.value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )
    except Exception:
        root_ski = x509.SubjectKeyIdentifier.from_public_key(
            root_cert.public_key()
        )
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=root_ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )
    builder = builder.add_extension(aki, critical=False)

    # Sign the certificate
    server_cert = builder.sign(
        private_key=root_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Export key and certificate
    write_bytes(
        CertConfig.OUT_SERVER_KEY,
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    write_bytes(
        CertConfig.OUT_SERVER_PEM,
        server_cert.public_bytes(serialization.Encoding.PEM)
    )

    print("Server certificate created.\n")
    return server_key, server_cert


def create_mobileconfig_from_der(der_bytes: bytes,out_path: str,display_name: str = "Portus LAN Root CA") -> None:
    """ Creates an iOS .mobileconfig profile embedding the DER root certificate."""
    print("Creating a .mobileconfig profile embedding the root certificate for iOS/iPadOS.")
    profile_uuid = str(uuid.uuid4())
    cert_payload_uuid = str(uuid.uuid4())

    # Build mobileconfig dictionary
    profile = {
        "PayloadDisplayName": display_name,
        "PayloadDescription": (
            "Installs the Portus Root CA so devices can trust "
            "the local Portus server certificates."
        ),
        "PayloadIdentifier": f"com.portus.rootca.{profile_uuid}",
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
        "PayloadContent": [
            {
                "PayloadType": "com.apple.security.root",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"com.portus.rootca.payload.{cert_payload_uuid}",
                "PayloadUUID": cert_payload_uuid,
                "PayloadDisplayName": display_name,
                "PayloadDescription": (
                    "Root CA certificate to be added to the device trust store."
                ),
                "PayloadContent": der_bytes
            }
        ]
    }

    # Write as XML plist
    with open(out_path, "wb") as f:
        plistlib.dump(profile, f)
    print(f"Wrote {out_path}")


# ----------------------------------
# MAIN WORKFLOW
# ----------------------------------

def _get_all_output_files() -> list[str]:
    """Returns a complete list of files this script produces."""
    return [
        CertConfig.OUT_ROOT_KEY,
        CertConfig.OUT_ROOT_PEM,
        CertConfig.OUT_ROOT_DER,
        CertConfig.OUT_SERVER_KEY,
        CertConfig.OUT_SERVER_PEM,
        CertConfig.OUT_MOBILECONFIG,
    ]


def _confirm_overwrite_if_needed(paths: list[str]) -> bool:
    """If any of the certificates already exist, asks the user whether to overwrite."""
    if not any(os.path.exists(path) for path in paths):
        return True

    response = input(
        "\nExisting output files detected.\n"
        "Do you wish to overwrite? (y/N): "
    ).strip().lower()

    if response != "y":
        print("Action aborted by user.\n")
        return False

    return True


def _print_summary() -> None:
    """Prints a summary of generated files and installation notes."""
    print("")
    print("-" * 50)
    print("Files produced:")
    for path in _get_all_output_files():
        print("  •", path)
    print("-" * 50)

    print("\nInstallation notes:")
    print("  • Copy or host 'root_ca.mobileconfig' and open it on an iOS device.")
    print("  • In iOS: Follow the prompts to install the profile.")
    print("  • Then go to, Settings → General → About → Certificate Trust Settings,")
    print("    enable full trust for the Portus Root CA.")
    print("  • Keep root_key.pem private and secure.\n")
    
    print(f"  • Certificates are valid for {CertConfig.VALIDITY_DAYS} days from the date of creation.\n")
    print(f"  • Certificates configured for mDNS domain: {CertConfig.MDNS_DOMAIN}")
    print(f"\n  • Run 'python Portus.py' next.")
    print(f"  • Access the FastAPI server at: https://{CertConfig.MDNS_DOMAIN}:6080\n")


def main() -> None:
    ensure_output_dir()

    if not _confirm_overwrite_if_needed(_get_all_output_files()):
        return

    # Generate certificates
    root_key, root_cert = generate_root_ca()
    generate_server_cert(root_key, root_cert)

    # Create mobileconfig profile
    der_bytes = root_cert.public_bytes(serialization.Encoding.DER)
    create_mobileconfig_from_der(der_bytes, CertConfig.OUT_MOBILECONFIG)

    _print_summary()


if __name__ == "__main__":
    main()
