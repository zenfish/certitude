#!/usr/bin/env python3

#
# process files containing X.509 PEMs/certs/keys/etc.
#
# Will try to make some sense of file contents, hunting for BEGIN/ENDs,
# trying to deal with multi-certs in a file, etc.
#
# Usage: $0 [-opts] [file-name-or-stdin]
#

import argparse
import fileinput
import hashlib
import json
import logging
import os
import re
import select
import sys
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

import pydantic

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, padding
from cryptography.x509.oid import ExtensionOID


# 10 megs... should be enough, but...
MAX_FILE_SIZE = 1024 * 1024 * 10

# Suppress warnings
warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")
warnings.filterwarnings("ignore", message="Properties that return a naïve datetime object have been deprecated")

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("certitude")

class Settings(pydantic.BaseModel):
    """Application settings."""
    verbose:        bool = False
    debug:          bool = False
    duplicity:      bool = True
    max_file_size:  int  = MAX_FILE_SIZE
    output_format:  str  = "json"
    include_pem:    bool = True  # Include PEM data in output

class KeyUsage(Enum):
    """X.509 Key Usage flags."""
    DIGITAL_SIGNATURE = 0
    NON_REPUDIATION = 1
    KEY_ENCIPHERMENT = 2
    DATA_ENCIPHERMENT = 3
    KEY_AGREEMENT = 4
    KEY_CERT_SIGN = 5
    CRL_SIGN = 6
    ENCIPHER_ONLY = 7
    DECIPHER_ONLY = 8


@dataclass
class CertificateData:
    """Certificate data container."""
    filename:                   str
    cert_obj:                   x509.Certificate
    fingerprint:                str
    pem_data:                   str = ""  # Store the PEM data
    subject:                    Dict[str, str] = field(default_factory=dict)
    issuer:                     Dict[str, str] = field(default_factory=dict)
    serial_number:              str = ""
    not_before:                 datetime = field(default_factory=datetime.now)
    not_after:                  datetime = field(default_factory=datetime.now)
    signature_algorithm:        str = ""
    extensions:                 Dict[str, Any] = field(default_factory=dict)
    is_ca:                      bool = False
    is_self_signed:             bool = False
    key_usage:                  List[str] = field(default_factory=list)
    extended_key_usage:         List[str] = field(default_factory=list)
    raw_oids:                   Dict[str, str] = field(default_factory=dict)
    matching_keys:              List[str] = field(default_factory=list)
    authority_key_identifier:   Optional[str] = None
    subject_key_identifier:     Optional[str] = None
    public_key_type:            str = ""  # Store the key type even if we can't use it
    public_key_info:            Dict[str, Any] = field(default_factory=dict)  # Store public key details

@dataclass
class KeyData:
    """Private key data container."""
    filename:           str
    key_obj:            Any
    key_type:           str
    pem_data:           str = ""  # Store the PEM data
    modulus:            Optional[int] = None
    public_key_hash:    str = ""
    matching_certs:     List[str] = field(default_factory=list)
    matching_keys:      List[str] = field(default_factory=list)  # Add this line
    encrypted:          bool = False
    key_info:           Dict[str, Any] = field(default_factory=dict)  # Store key-specific details
    is_private:         bool = False  # Flag to indicate if this is a private key
    ssh_key_data:       str = ""  # Store SSH key data for matching


@dataclass
class UnknownFormatData:
    """Container for recognized but unsupported formats."""
    filename: str
    format_type: str
    pem_data: str = ""  # Store the PEM data
    encrypted: bool = False
    description: str = ""


class OIDRegistry:
    """Registry of known OIDs and their friendly names."""

    # OID mapping dictionary
    oids = {
        # Basic OIDs
        "2.5.29.14": "subjectKeyIdentifier",
        "2.5.29.15": "keyUsage",
        "2.5.29.17": "subjectAltName",
        "2.5.29.19": "basicConstraints",
        "2.5.29.31": "cRLDistributionPoints",
        "2.5.29.32": "certificatePolicies",
        "2.5.29.35": "authorityKeyIdentifier",
        "2.5.29.37": "extKeyUsage",

        "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",

        # Extended OIDs from original code
        "2.5.29.1":  "authorityKeyIdentifier",
        "2.5.29.2":  "keyAttributes",
        "2.5.29.3":  "certificatePolicies",
        "2.5.29.4":  "keyUsageRestriction",
        "2.5.29.5":  "policyMapping",
        "2.5.29.6":  "subtreesConstraint",
        "2.5.29.7":  "subjectAltName",
        "2.5.29.8":  "issuerAltName",
        "2.5.29.9":  "subjectDirectoryAttributes",
        "2.5.29.10": "basicConstraints",
        "2.5.29.16": "privateKeyUsagePeriod",
        "2.5.29.18": "issuerAltName",
        "2.5.29.20": "cRLNumber",
        "2.5.29.21": "reasonCode",
        "2.5.29.22": "expirationDate",
        "2.5.29.23": "instructionCode",
        "2.5.29.24": "invalidityDate",
        "2.5.29.25": "cRLDistributionPoints",
        "2.5.29.26": "issuingDistributionPoint",
        "2.5.29.27": "deltaCRLIndicator",
        "2.5.29.28": "issuingDistributionPoint",
        "2.5.29.29": "certificateIssuer",
        "2.5.29.30": "nameConstraints",
        "2.5.29.33": "policyMappings",
        "2.5.29.34": "policyConstraints",
        "2.5.29.36": "policyConstraints",
        "2.5.29.38": "authorityAttributeIdentifier",
        "2.5.29.39": "roleSpecCertIdentifier",
        "2.5.29.40": "cRLStreamIdentifier",
        "2.5.29.41": "basicAttConstraints",
        "2.5.29.42": "delegatedNameConstraints",
        "2.5.29.43": "timeSpecification",
        "2.5.29.44": "cRLScope",
        "2.5.29.45": "statusReferrals",
        "2.5.29.46": "freshestCRL",
        "2.5.29.47": "orderedList",
        "2.5.29.48": "attributeDescriptor",
        "2.5.29.49": "userNotice",
        "2.5.29.50": "sOAIdentifier",
        "2.5.29.51": "baseUpdateTime",
        "2.5.29.52": "acceptableCertPolicies",
        "2.5.29.53": "deltaInfo",
        "2.5.29.54": "inhibitAnyPolicy",
        "2.5.29.55": "targetInformation",
        "2.5.29.56": "noRevAvail",
        "2.5.29.57": "acceptablePrivilegePolicies",
        "2.5.29.58": "id-ce-toBeRevoked",
        "2.5.29.59": "id-ce-RevokedGroups",
        "2.5.29.60": "id-ce-expiredCertsOnCRL",
        "2.5.29.61": "indirectIssuer",
        "2.5.29.62": "id-ce-noAssertion",
        "2.5.29.63": "id-ce-aAissuingDistributionPoint",
        "2.5.29.64": "id-ce-issuedOnBehaIFOF",
        "2.5.29.65": "id-ce-singleUse",
        "2.5.29.66": "id-ce-groupAC",
        "2.5.29.67": "id-ce-allowedAttAss",
        "2.5.29.68": "id-ce-attributeMappings",
        "2.5.29.69": "id-ce-holderNameConstraints",

        "1.3.6.1.4.1.11129.2.4.2": "SignedCertTimestamp",

        "1.3.6.1.5.5.7.1.2":     "biometricInfo",
        "1.3.6.1.5.5.7.1.3":     "qcStatements",
        "1.3.6.1.5.5.7.1.4":     "auditIdentity",
        "1.3.6.1.5.5.7.1.6":     "aaControls",
        "1.3.6.1.5.5.7.1.10":    "proxying",
        "1.3.6.1.5.5.7.1.11":    "subjectInfoAccess",
        "1.3.6.1.5.5.7.1.12":    "id-pe-logotype",
        "1.3.6.1.5.5.7.1.13":    "id-pe-wlanSSID",
        "1.3.6.1.5.5.7.1.14":    "id-pe-proxyCertInfo",
        "1.3.6.1.5.5.7.1.21":    "id-pe-clearanceConstraints",
        "1.3.6.1.5.5.7.1.23":    "nsa",
        "1.3.6.1.5.5.7.1.25":    "securityInfo",
        "1.3.6.1.4.1.311.21.10": "szOID_APPLICATION_CERT_POLICIES",

        # Legacy key type OIDs
        "2.5.8.1.1":     "RSA (legacy OID)",
        "1.3.14.3.2.12": "DSA (legacy OID)",
    }

    @classmethod
    def get_friendly_name(cls, oid: str) -> str:
        """Get friendly name for an OID if known, otherwise return the OID."""
        return cls.oids.get(oid, oid)

class Certitude:
    """Main class for certificate analysis."""

    # Known PEM formats
    PEM_FORMATS = {
        # Certificate formats
        "CERTIFICATE":                  ("Certificate", False),
        "X509 CERTIFICATE":             ("X.509 Certificate", False),
        "TRUSTED CERTIFICATE":          ("Trusted Certificate", False),

        # Key formats
        "RSA PRIVATE KEY":              ("RSA Private Key", False),
        "DSA PRIVATE KEY":              ("DSA Private Key", False),
        "EC PRIVATE KEY":               ("EC Private Key", False),
        "PRIVATE KEY":                  ("PKCS#8 Private Key", False),
        "ENCRYPTED PRIVATE KEY":        ("PKCS#8 Encrypted Private Key", True),
        "PUBLIC KEY":                   ("Public Key", False),

        # Other formats
        "SSH2 ENCRYPTED PRIVATE KEY":   ("SSH2 Encrypted Private Key", True),
        "SSH PRIVATE KEY":              ("SSH Private Key", False),
        "OPENSSH PRIVATE KEY":          ("OpenSSH Private Key", False),
        "DH PARAMETERS":                ("DH Parameters", False),
        "SSL SESSION PARAMETERS":       ("SSL Session Parameters", False),
        "PKCS7":                        ("PKCS#7", False),
        "CMS":                          ("Cryptographic Message Syntax", False),
        "CERTIFICATE REQUEST":          ("Certificate Signing Request", False),
        "NEW CERTIFICATE REQUEST":      ("New Certificate Request", False),
        "X509 CRL":                     ("X.509 CRL", False),
    }

    def __init__(self, settings: Settings):
        """Initialize the Certitude analyzer.

        Args:
            settings: Application settings
        """
        self.settings = settings

        self.certificates:      Dict[str, CertificateData] = {}  # Fingerprint -> CertData
        self.keys:              Dict[str, KeyData] = {}  # Key hash -> KeyData
        self.unknown_formats:   Dict[str, List[UnknownFormatData]] = defaultdict(list)  # Filename -> [UnknownFormatData]
        self.cert_by_filename:  Dict[str, List[str]] = defaultdict(list)  # Filename -> [Fingerprints]
        self.key_by_filename:   Dict[str, List[str]] = defaultdict(list)  # Filename -> [Key hashes]
        self.cert_hierarchy:    Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        self.cert_issuers:      Dict[str, str] = {}  # Cert fingerprint -> Issuer fingerprint

        # Configure logging based on settings
        if settings.debug:
            logger.setLevel(logging.DEBUG)
        elif settings.verbose:
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.WARNING)

    def process_files(self, filenames: List[str]) -> None:
        """
        Loop over file(s) given; if it exists/isn't too big, then send it to _process_file to hunt for certs/keys
        Args: filenames: List of filenames to process
        """
        for filename in filenames:
            if not os.path.isfile(filename):
                logger.warning(f"Skipping '{filename}', not a file")
                continue

            if os.stat(filename).st_size > settings.max_file_size:
                logger.warning(f"Skipping '{filename}', larger than maxiumum allowed ({settings.max_file_size} bytes)")
                continue

            logger.info(f"Processing {filename}")
            self._process_file(filename)

        # After processing all files, find relationships
        self._find_cert_key_matches()  # Find certificate-key matches
        self._find_key_key_matches()   # Find key-key matches
        self._build_certificate_hierarchy()

    def _find_cert_key_matches(self) -> None:
        """Find matches between certificates and keys."""
        for cert_fp, cert_data in self.certificates.items():
            try:
                cert_obj = cert_data.cert_obj
    
                # Get the public key, handling potential errors
                try:
                    cert_public_key = cert_obj.public_key()
    
                    # For RSA certificates
                    if isinstance(cert_public_key, rsa.RSAPublicKey):
                        cert_modulus = cert_public_key.public_numbers().n
    
                        # Check each key
                        for key_hash, key_data in self.keys.items():
                            if key_data.modulus and key_data.modulus == cert_modulus:
                                # Match found!
                                cert_data.matching_keys.append(key_hash)
                                key_data.matching_certs.append(cert_fp)
                                logger.info(f"Found matching key for certificate: {cert_data.filename} -> {key_data.filename}")
    
                    # For EC certificates
                    elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
                        cert_public_bytes = cert_public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
    
                        # Check each key
                        for key_hash, key_data in self.keys.items():
                            try:
                                if hasattr(key_data.key_obj, 'public_key'):
                                    key_public_key = key_data.key_obj.public_key()
                                else:
                                    key_public_key = key_data.key_obj
    
                                if isinstance(key_public_key, ec.EllipticCurvePublicKey):
                                    key_public_bytes = key_public_key.public_bytes(
                                        encoding=serialization.Encoding.DER,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    )
                                    if cert_public_bytes == key_public_bytes:
                                        # Match found!
                                        cert_data.matching_keys.append(key_hash)
                                        key_data.matching_certs.append(cert_fp)
                                        logger.info(f"Found matching EC key for certificate: {cert_data.filename} -> {key_data.filename}")
                            except Exception as e:
                                logger.debug(f"Error comparing EC keys: {e}")
    
                    # For DSA certificates - improved handling
                    elif isinstance(cert_public_key, dsa.DSAPublicKey):
                        # Extract DSA parameters from certificate
                        cert_y = cert_public_key.public_numbers().y
                        cert_params = cert_public_key.parameters()
                        cert_param_numbers = cert_params.parameter_numbers()
                        cert_p = cert_param_numbers.p
                        cert_q = cert_param_numbers.q
                        cert_g = cert_param_numbers.g
                        
                        # Check each key
                        for key_hash, key_data in self.keys.items():
                            try:
                                # For private DSA keys
                                if hasattr(key_data.key_obj, 'private_numbers') and hasattr(key_data.key_obj, 'parameters'):
                                    key_public_key = key_data.key_obj.public_key()
                                    if isinstance(key_public_key, dsa.DSAPublicKey):
                                        key_y = key_public_key.public_numbers().y
                                        key_params = key_public_key.parameters()
                                        key_param_numbers = key_params.parameter_numbers()
                                        key_p = key_param_numbers.p
                                        key_q = key_param_numbers.q
                                        key_g = key_param_numbers.g
                                        
                                        # Compare DSA parameters
                                        if (cert_y == key_y and cert_p == key_p and 
                                            cert_q == key_q and cert_g == key_g):
                                            # Match found!
                                            cert_data.matching_keys.append(key_hash)
                                            key_data.matching_certs.append(cert_fp)
                                            logger.info(f"Found matching DSA key for certificate: {cert_data.filename} -> {key_data.filename}")
                                
                                # For public DSA keys
                                elif hasattr(key_data.key_obj, 'public_numbers') and isinstance(key_data.key_obj, dsa.DSAPublicKey):
                                    key_y = key_data.key_obj.public_numbers().y
                                    key_params = key_data.key_obj.parameters()
                                    key_param_numbers = key_params.parameter_numbers()
                                    key_p = key_param_numbers.p
                                    key_q = key_param_numbers.q
                                    key_g = key_param_numbers.g
                                    
                                    # Compare DSA parameters
                                    if (cert_y == key_y and cert_p == key_p and 
                                        cert_q == key_q and cert_g == key_g):
                                        # Match found!
                                        cert_data.matching_keys.append(key_hash)
                                        key_data.matching_certs.append(cert_fp)
                                        logger.info(f"Found matching DSA key for certificate: {cert_data.filename} -> {key_data.filename}")
                            except Exception as e:
                                logger.debug(f"Error comparing DSA keys: {e}")
    
                except ValueError as e:
                    # This handles the "Unknown key type" error
                    logger.info(f"Unsupported public key type in certificate {cert_data.filename}: {e}")
    
                    # For legacy RSA keys, try to match based on modulus from public_key_info
                    if "RSA" in cert_data.public_key_type and "modulus" in cert_data.public_key_info:
                        try:
                            # Convert hex modulus to integer
                            cert_modulus = int(cert_data.public_key_info["modulus"], 16)
    
                            # Check each key
                            for key_hash, key_data in self.keys.items():
                                if key_data.modulus and key_data.modulus == cert_modulus:
                                    # Match found!
                                    cert_data.matching_keys.append(key_hash)
                                    key_data.matching_certs.append(cert_fp)
                                    logger.info(f"Found matching key for legacy RSA certificate: {cert_data.filename} -> {key_data.filename}")
                        except Exception as e:
                            logger.debug(f"Error matching legacy RSA key: {e}")
    
            except Exception as e:
                logger.warning(f"Error processing certificate {cert_fp} for key matching: {e}")


    def _try_load_certificates(self, filename: str, data: bytes) -> bool:
        """Try to load certificates from data.

        Args:
            filename: Source filename
            data: Binary data to parse

        Returns:
            bool: True if at least one certificate was found
        """
        found = False

        # Try PEM format first (most common)
        try:
            # Look for multiple PEM certificates in the file
            pem_start = b"-----BEGIN CERTIFICATE-----"
            pem_end = b"-----END CERTIFICATE-----"

            start_idx = 0
            while True:
                start_pos = data.find(pem_start, start_idx)
                if start_pos == -1:
                    break

                end_pos = data.find(pem_end, start_pos)
                if end_pos == -1:
                    # Malformed PEM data - log and break
                    logger.warning(f"Malformed PEM certificate data in {filename}: found BEGIN but no END")
                    break

                # Include the END marker
                end_pos += len(pem_end)

                cert_data = data[start_pos:end_pos]
                self._process_certificate(filename, cert_data)
                found = True
                start_idx = end_pos

                # Safety check to prevent infinite loops with corrupted files
                if start_idx >= len(data):
                    break

        except Exception as e:
            logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            logger.debug(f"Failed to parse PEM certificates from {filename}: {e}")

        # If no PEM certs found, try DER format
        if not found:
            try:
                cert = x509.load_der_x509_certificate(data, default_backend())
                # For DER format, we need to convert to PEM for storage
                pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
                self._add_certificate(filename, cert, pem_data)
                found = True
            except Exception as e:
                logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                logger.debug(f"Failed to parse DER certificate from {filename}: {e}")

        return found

    def _try_load_keys(self, filename: str, data: bytes) -> bool:
        """
        Try to load private keys from data with enhanced support for EC, SSH, and DSA keys.
        Args:
            filename: Source filename
            data: Binary data to parse
        Returns:
            bool: True if at least one key was found
        """
        found = False
    
        # Try SSH public key format first (most common non-PEM format)
        try:
            data_str = data.decode('utf-8', errors='ignore').strip()
            if data_str.startswith(('ssh-rsa ', 'ssh-ed25519 ', 'ssh-dss ', 'ecdsa-sha2-')):
                if self._process_ssh_public_key(filename, data):
                    return True
        except Exception as e:
            logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            logger.debug(f"Failed to parse SSH public key format from {filename}: {e}")
    
        # Try PEM format
        try:
            # Look for multiple PEM keys in the file
            pem_key_types = [
                (b"-----BEGIN RSA PRIVATE KEY-----",        b"-----END RSA PRIVATE KEY-----",  "RSA"),
                (b"-----BEGIN PRIVATE KEY-----",            b"-----END PRIVATE KEY-----",      "PKCS8"),
                (b"-----BEGIN EC PRIVATE KEY-----",         b"-----END EC PRIVATE KEY-----",   "EC"),
                (b"-----BEGIN DSA PRIVATE KEY-----",        b"-----END DSA PRIVATE KEY-----",  "DSA"),
                (b"-----BEGIN PUBLIC KEY-----",             b"-----END PUBLIC KEY-----",       "PUBLIC"),
                (b"-----BEGIN OPENSSH PRIVATE KEY-----",    b"-----END OPENSSH PRIVATE KEY-----", "OPENSSH"),
            ]
    
            for start_marker, end_marker, key_type in pem_key_types:
                start_idx = 0
                while True:
                    start_pos = data.find(start_marker, start_idx)
                    if start_pos == -1:
                        break
    
                    end_pos = data.find(end_marker, start_pos)
                    if end_pos == -1:
                        # Malformed PEM data - log and break
                        logger.warning(f"Malformed PEM key data in {filename}: found BEGIN but no END")
                        break
    
                    # Include the END marker
                    end_pos += len(end_marker)
    
                    key_data = data[start_pos:end_pos]
                    pem_data = key_data.decode('utf-8')
                    
                    # Special handling for OpenSSH private keys
                    if key_type == "OPENSSH":
                        if self._process_openssh_private_key(filename, key_data, pem_data):
                            found = True
                    else:
                        # Process other key types
                        self._process_key(filename, key_data, key_type, pem_data)
                        found = True
                    
                    start_idx = end_pos
    
                    # Safety check to prevent infinite loops with corrupted files
                    if start_idx >= len(data):
                        break
    
        except Exception as e:
            logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            logger.debug(f"Failed to parse PEM keys from {filename}: {e}")
    
        # If no PEM keys found, try DER format
        if not found:
            try:
                # Try as PKCS8 format
                try:
                    key = serialization.load_der_private_key(
                        data, password=None, backend=default_backend()
                    )
                    # Convert to PEM for storage
                    pem_data = key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ).decode('utf-8')
                    self._add_key(filename, key, "PKCS8", pem_data, is_private=True)
                    found = True
                except Exception as e:
                    logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                    logger.debug(f"Failed to parse DER PKCS8 key from {filename}: {e}")
    
                    # Try as public key
                    try:
                        key = serialization.load_der_public_key(
                            data, backend=default_backend()
                        )
                        # Convert to PEM for storage
                        pem_data = key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8')
                        self._add_key(filename, key, "PUBLIC", pem_data, is_private=False)
                        found = True
                    except Exception as e:
                        logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                        logger.debug(f"Failed to parse DER public key from {filename}: {e}")
    
            except Exception as e:
                logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                logger.debug(f"Failed to parse DER key from {filename}: {e}")
    
        return found


    def _process_file(self, filename: str) -> None:
        """
        Process a file for certificates and keys.
        Args: filename: Path to the file to process
        """
        try:
            with open(filename, 'rb') as f:
                data = f.read()

            # Try to identify other formats first - this will catch DH PARAMETERS etc.
            other_found = self._identify_other_formats(filename, data)

            # If it's not a recognized format, try to load as certificate or key
            if not other_found:
                # Try to load as certificate(s)
                cert_found = self._try_load_certificates(filename, data)

                # Try to load as key(s)
                key_found = self._try_load_keys(filename, data)

                if not cert_found and not key_found:
                    logger.debug(f"No certificates or keys found in {filename}")

        except Exception as e:
            logger.error(f"Error processing {filename}: {e}")


    def _identify_other_formats(self, filename: str, data: bytes) -> bool:
        """Identify other known formats in the file.

        Args:
            filename: Source filename
            data: Binary data to parse

        Returns:
            True if any known format was identified
        """
        # Convert to string for regex matching
        try:
            data_str = data.decode('utf-8', errors='ignore')
        except Exception:
            return False

        # Look for PEM-like formats
        pattern = r"-----BEGIN ([^-]+)-----.*?-----END \1-----"
        matches = re.findall(pattern, data_str, re.DOTALL)

        # logger.debug("huntin' for PEMs...")

        if not matches:
            return False

        found = False

        for match in matches:
            format_type = match.strip().upper()
            if format_type in self.PEM_FORMATS:
                desc, encrypted = self.PEM_FORMATS[format_type]

                # Skip certificate and key formats - we'll handle those separately
                if format_type in ["CERTIFICATE",     "X509 CERTIFICATE", "TRUSTED CERTIFICATE",
                                   "RSA PRIVATE KEY", "DSA PRIVATE KEY",  "EC PRIVATE KEY",
                                   "PRIVATE KEY",     "PUBLIC KEY", "OPENSSH PRIVATE KEY"]:
                    continue

                # Extract the PEM data
                pem_pattern = f"-----BEGIN {match}-----.*?-----END {match}-----"
                pem_match = re.search(pem_pattern, data_str, re.DOTALL)
                pem_data = pem_match.group(0) if pem_match else ""

                unknown_data = UnknownFormatData(
                    filename=filename,
                    format_type=format_type,
                    pem_data=pem_data,
                    encrypted=encrypted,
                    description=desc
                )
                self.unknown_formats[filename].append(unknown_data)
                log_level = logging.INFO if self.settings.verbose else logging.DEBUG
                logger.log(log_level, f"Identified {desc} in {filename}")
                found = True

            else:
                #
                # Unknown format but somewhat still PEM-like
                #
                # Extract data
                #
                pem_pattern = f"-----BEGIN {match}-----.*?-----END {match}-----"
                pem_match = re.search(pem_pattern, data_str, re.DOTALL)
                pem_data = pem_match.group(0) if pem_match else ""

                unknown_data = UnknownFormatData(
                    filename=filename,
                    format_type=format_type,
                    pem_data=pem_data,
                    description=f"Unknown format: {format_type}"
                )

                self.unknown_formats[filename].append(unknown_data)
                log_level = logging.INFO if self.settings.verbose else logging.DEBUG
                logger.log(log_level, f"Identified unknown PEM format '{format_type}' in {filename}")
                found = True

        # logger.debug("...and...?")
        # logger.debug(found)

        return found

    def _parse_ssh_public_key(self, data_str: str) -> Dict[str, Any]:
        """Parse an SSH public key in the standard format."""
        parts = data_str.strip().split()
        if len(parts) >= 2:
            key_type = parts[0]
            key_data = parts[1]
            comment = " ".join(parts[2:]) if len(parts) > 2 else ""

            return {
                "type": key_type,
                "data": key_data,
                "comment": comment
            }
        return {}

    def _process_ssh_public_key(self, filename: str, data: bytes) -> bool:
        """Process an SSH public key in the standard format.
        
        Args:
            filename: Source filename
            data: SSH public key data
            
        Returns:
            True if successfully processed
        """
        try:
            # Convert to string
            data_str = data.decode('utf-8', errors='ignore').strip()
            
            # Check if it's an SSH public key
            parts = data_str.split()
            if len(parts) >= 2 and parts[0] in ['ssh-rsa', 'ssh-ed25519', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']:
                key_type = parts[0]
                key_data = parts[1]
                comment = " ".join(parts[2:]) if len(parts) > 2 else ""
                
                # Determine the algorithm type
                if key_type == 'ssh-rsa':
                    algorithm = "RSA"
                elif key_type == 'ssh-ed25519':
                    algorithm = "ED25519"
                elif key_type == 'ssh-dss':
                    algorithm = "DSA"
                elif key_type.startswith('ecdsa-'):
                    algorithm = "ECDSA"
                else:
                    algorithm = key_type
                
                # Extract the base filename without extension
                base_filename = os.path.splitext(os.path.basename(filename))[0]
                
                # Create a unique hash for this key
                key_hash = hashlib.sha256(key_data.encode('utf-8')).hexdigest().upper()
                
                # Create key info
                key_info = {
                    "algorithm": algorithm,
                    "ssh_type": key_type,
                    "comment": comment,
                    "is_private": False,
                    "base_filename": base_filename  # Store the base filename for matching
                }
                
                # Create key data object
                key_data_obj = KeyData(
                    filename=filename,
                    key_obj=None,  # We don't have a cryptography object for this
                    key_type=f"SSH-{algorithm}",
                    pem_data=data_str,
                    public_key_hash=key_hash,
                    key_info=key_info,
                    is_private=False,
                    ssh_key_data=key_data  # Store the base64 encoded key data
                )
                
                # Store key
                self.keys[key_hash] = key_data_obj
                self.key_by_filename[filename].append(key_hash)
                
                logger.debug(f"Added SSH public key: {key_hash} from {filename}")
                return True
                
            return False
        except Exception as e:
            logger.debug(f"Error processing SSH public key from {filename}: {e}")
            return False

    def _process_openssh_private_key(self, filename: str, key_data: bytes, pem_data: str) -> bool:
        """Process an OpenSSH private key."""
        try:
            # Try to load the private key using cryptography
            try:
                key = serialization.load_ssh_private_key(key_data, password=None, backend=default_backend())
                
                # Extract public key information
                public_key = key.public_key()
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_key_hash = hashlib.sha256(public_key_bytes).hexdigest().upper()
    
                # Determine the algorithm type
                algorithm = "SSH"
                if b"ssh-rsa" in key_data:
                    algorithm = "RSA"
                elif b"ssh-ed25519" in key_data:
                    algorithm = "ED25519"
                elif b"ssh-dss" in key_data or b"ssh-dsa" in key_data:
                    algorithm = "DSA"
                elif b"ecdsa-sha2" in key_data:
                    algorithm = "ECDSA"
    
                # Create a unique hash for this key
                key_hash = hashlib.sha256(key_data).hexdigest().upper()
    
                # Extract the base filename without extension
                base_filename = os.path.splitext(os.path.basename(filename))[0]
    
                # Create key info
                key_info = {
                    "algorithm": algorithm,
                    "ssh_type": f"ssh-{algorithm.lower()}",
                    "is_private": True,
                    "base_filename": base_filename  # Store the base filename for matching
                }
    
                # Create key data object
                key_data_obj = KeyData(
                    filename=filename,
                    key_obj=key,
                    key_type=f"SSH-{algorithm}",
                    pem_data=pem_data,
                    public_key_hash=public_key_hash,
                    key_info=key_info,
                    is_private=True,
                    ssh_key_data=""  # We don't have the public key data
                )
    
                # Store key
                self.keys[key_hash] = key_data_obj
                self.key_by_filename[filename].append(key_hash)
    
                logger.debug(f"Added SSH private key: {key_hash} from {filename}")
                return True
                
            except ValueError as e:
                # Handle encrypted key case
                if "password" in str(e).lower():
                    logger.info(f"Encrypted SSH key found in {filename}")
                    
                    # Extract the base filename without extension for matching
                    base_filename = os.path.splitext(os.path.basename(filename))[0]
                    
                    # Create a unique hash for this key
                    key_hash = hashlib.sha256(key_data).hexdigest().upper()
                    
                    # Determine the algorithm type from content
                    algorithm = "SSH"
                    if b"ssh-rsa" in key_data:
                        algorithm = "RSA"
                    elif b"ssh-ed25519" in key_data:
                        algorithm = "ED25519"
                    elif b"ssh-dss" in key_data or b"ssh-dsa" in key_data:
                        algorithm = "DSA"
                    elif b"ecdsa-sha2" in key_data:
                        algorithm = "ECDSA"
                    
                    # Create key info
                    key_info = {
                        "algorithm": algorithm,
                        "ssh_type": f"ssh-{algorithm.lower()}",
                        "is_private": True,
                        "encrypted": True,
                        "base_filename": base_filename  # Store the base filename for matching
                    }
                    
                    # Create key data object
                    key_data_obj = KeyData(
                        filename=filename,
                        key_obj=None,  # Can't load the key without password
                        key_type=f"SSH-{algorithm}",
                        pem_data=pem_data,
                        public_key_hash="",  # Can't compute without decrypting
                        key_info=key_info,
                        is_private=True,
                        encrypted=True,
                        ssh_key_data=""  # We don't have the public key data
                    )
                    
                    # Store key
                    self.keys[key_hash] = key_data_obj
                    self.key_by_filename[filename].append(key_hash)
                    
                    logger.debug(f"Added encrypted SSH private key: {key_hash} from {filename}")
                    return True
                else:
                    raise
                    
        except Exception as e:
            logger.debug(f"Error processing OpenSSH private key from {filename}: {e}")
            return False


    def _process_certificate(self, filename: str, cert_data: bytes) -> None:
        """Process a certificate from PEM data.

        Args:
            filename: Source filename
            cert_data: PEM certificate data
        """
        try:
            # Suppress warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            pem_data = cert_data.decode('utf-8')
            self._add_certificate(filename, cert, pem_data)
        except Exception as e:
            logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            logger.debug(f"Failed to parse certificate in {filename}: {e}")

    def _add_certificate(self, filename: str, cert: x509.Certificate, pem_data: str) -> None:
        """Add a certificate to the registry.

        Args:
            filename: Source filename
            cert: Certificate object
            pem_data: PEM encoded certificate data
        """
        # Generate SHA256 fingerprint as unique ID
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()

        # Skip if we've already seen this certificate
        if fingerprint in self.certificates:
            self.cert_by_filename[filename].append(fingerprint)
            logger.debug(f"Duplicate certificate found in {filename}, fingerprint: {fingerprint}")
            return

        # Extract certificate data
        cert_data = CertificateData(
            filename=filename,
            cert_obj=cert,
            fingerprint=fingerprint,
            pem_data=pem_data,
            subject=self._extract_name_attributes(cert.subject),
            issuer=self._extract_name_attributes(cert.issuer),
            serial_number=f"{cert.serial_number:x}",
            not_before=cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before,
            not_after=cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after,
            signature_algorithm=cert.signature_algorithm_oid._name,
        )

        # Extract public key information
        self._extract_public_key_info(cert_data, cert)

        # Process extensions
        self._process_extensions(cert_data, cert)

        # Check if self-signed
        cert_data.is_self_signed = self._is_self_signed(cert_data)

        # Store certificate
        self.certificates[fingerprint] = cert_data
        self.cert_by_filename[filename].append(fingerprint)

        logger.debug(f"Added certificate: {fingerprint} from {filename}")


    def _extract_public_key_info(self, cert_data: CertificateData, cert: x509.Certificate) -> None:
        """Extract public key information from certificate.

        Args:
            cert_data: Certificate data to update
            cert: Certificate object
        """
        try:
            # Try to get public key
            public_key = cert.public_key()

            # Determine key type
            if isinstance(public_key, rsa.RSAPublicKey):
                cert_data.public_key_type = "RSA"
                # Extract RSA key details
                numbers = public_key.public_numbers()
                cert_data.public_key_info = {
                    "algorithm": "RSA",
                    "key_size": public_key.key_size,
                    "modulus": f"{numbers.n:x}",
                    "exponent": numbers.e
                }
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                cert_data.public_key_type = "EC"
                # Extract EC key details
                curve = public_key.curve.name
                cert_data.public_key_info = {
                    "algorithm": "EC",
                    "curve": curve
                }
            else:
                cert_data.public_key_type = str(type(public_key))
                cert_data.public_key_info = {
                    "algorithm": "Unknown",
                    "type": str(type(public_key))
                }

        except ValueError as e:
            # Handle unsupported key types
            error_msg = str(e)
            if "Unknown key type:" in error_msg:
                key_type_oid = error_msg.split(":")[-1].strip()
                cert_data.public_key_type = OIDRegistry.get_friendly_name(key_type_oid)

                # For legacy RSA keys, try to extract the modulus from the certificate's TBS data
                if "RSA" in cert_data.public_key_type:
                    try:
                        # Extract the raw public key bytes from the certificate
                        from asn1crypto import pem
                        from asn1crypto import x509 as asn1_x509

                        # Parse the certificate
                        if cert_data.pem_data:
                            _, _, der_bytes = pem.unarmor(cert_data.pem_data.encode('utf-8'))
                        else:
                            der_bytes = cert.public_bytes(encoding=serialization.Encoding.DER)

                        cert_parsed = asn1_x509.Certificate.load(der_bytes)

                        # Get the public key info
                        public_key_info = cert_parsed['tbs_certificate']['subject_public_key_info']

                        # For RSA, extract modulus and exponent
                        if public_key_info['algorithm']['algorithm'].native == 'rsa':
                            key = public_key_info['public_key'].parsed
                            cert_data.public_key_info = {
                                "algorithm": "RSA (legacy)",
                                "modulus": f"{key['modulus'].native:x}",
                                "exponent": key['public_exponent'].native
                            }
                    except Exception as parse_error:
                        logger.debug(f"Could not parse legacy RSA key details: {parse_error}")
                        cert_data.public_key_info = {
                            "algorithm": cert_data.public_key_type,
                            "error": "Could not extract key details"
                        }
                else:
                    cert_data.public_key_info = {
                        "algorithm": cert_data.public_key_type,
                        "oid": key_type_oid
                    }

                logger.info(f"Certificate in {cert_data.filename} uses unsupported key type: {cert_data.public_key_type}")
            else:
                cert_data.public_key_type = "Unknown"
                cert_data.public_key_info = {
                    "algorithm": "Unknown",
                    "error": str(e)
                }
                logger.warning(f"Could not determine key type for certificate in {cert_data.filename}: {e}")
        except Exception as e:
            cert_data.public_key_type = "Error"
            cert_data.public_key_info = {
                "algorithm": "Error",
                "error": str(e)
            }
            logger.warning(f"Error extracting public key info from certificate in {cert_data.filename}: {e}")


    def _is_self_signed(self, cert_data: CertificateData) -> bool:
        """Check if a certificate is self-signed.
        Args:    cert_data: Certificate data
        Returns: True if the certificate is self-signed
        """
        # Basic check: subject == issuer
        if cert_data.subject != cert_data.issuer:
            return False

        # Advanced check: verify signature using its own public key
        try:
            cert_obj = cert_data.cert_obj
            public_key = cert_obj.public_key()

            # Different verification methods based on key type
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert_obj.signature_hash_algorithm
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    ec.ECDSA(cert_obj.signature_hash_algorithm)
                )
            else:
                # For other key types, fall back to subject/issuer comparison
                return True

            return True
        except Exception:
            return False

    def _extract_name_attributes(self, name: x509.Name) -> Dict[str, str]:
        """Extract attributes from X.509 Name object.

        Args:    name: X.509 Name object
        Returns: Dict mapping attribute types to values

        """

        result = {}
        for attr in name:
            oid_name = attr.oid._name
            if oid_name:
                result[oid_name] = attr.value
            else:
                # If no friendly name, use the OID
                result[attr.oid.dotted_string] = attr.value
        return result

    def _process_extensions(self, cert_data: CertificateData, cert: x509.Certificate) -> None:
        """Process certificate extensions.
        Args:
            cert_data: Certificate data object to update
            cert: Certificate object
        """

        extensions = {}

        try:
            # First, get a list of all extensions to process them one by one
            all_extensions = list(cert.extensions)

            for ext in all_extensions:
                try:
                    oid = ext.oid.dotted_string
                    friendly_name = OIDRegistry.get_friendly_name(oid)

                    # Always store the raw OID
                    cert_data.raw_oids[oid] = friendly_name

                    # Process specific extensions
                    if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                        cert_data.is_ca = ext.value.ca
                        if ext.value.ca and ext.value.path_length is not None:
                            extensions["basicConstraints"] = f"CA:TRUE, pathlen:{ext.value.path_length}"
                        elif ext.value.ca:
                            extensions["basicConstraints"] = "CA:TRUE"
                        else:
                            extensions["basicConstraints"] = "CA:FALSE"

                    elif ext.oid == ExtensionOID.KEY_USAGE:
                        usages = []
                        try:
                            if ext.value.digital_signature:
                                usages.append("digitalSignature")
                                cert_data.key_usage.append("digitalSignature")
                            if ext.value.content_commitment:
                                usages.append("nonRepudiation")
                                cert_data.key_usage.append("nonRepudiation")
                            if ext.value.key_encipherment:
                                usages.append("keyEncipherment")
                                cert_data.key_usage.append("keyEncipherment")
                            if ext.value.data_encipherment:
                                usages.append("dataEncipherment")
                                cert_data.key_usage.append("dataEncipherment")
                            if ext.value.key_agreement:
                                usages.append("keyAgreement")
                                cert_data.key_usage.append("keyAgreement")
                                # Only check these if key_agreement is True
                                if ext.value.encipher_only:
                                    usages.append("encipherOnly")
                                    cert_data.key_usage.append("encipherOnly")
                                if ext.value.decipher_only:
                                    usages.append("decipherOnly")
                                    cert_data.key_usage.append("decipherOnly")
                            if ext.value.key_cert_sign:
                                usages.append("keyCertSign")
                                cert_data.key_usage.append("keyCertSign")
                            if ext.value.crl_sign:
                                usages.append("cRLSign")
                                cert_data.key_usage.append("cRLSign")
                        except Exception as e:
                            logger.warning(f"Error processing key usage for certificate {cert_data.fingerprint} in {cert_data.filename}: {e}")

                        extensions["keyUsage"] = ", ".join(usages)

                    elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                        usages = []
                        for usage_oid in ext.value:
                            if usage_oid._name:
                                usages.append(usage_oid._name)
                                cert_data.extended_key_usage.append(usage_oid._name)
                            else:
                                usages.append(usage_oid.dotted_string)
                                cert_data.extended_key_usage.append(usage_oid.dotted_string)
                        extensions["extendedKeyUsage"] = ", ".join(usages)

                    elif ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        san_values = []
                        for name in ext.value:
                            if isinstance(name, x509.DNSName):
                                san_values.append(f"DNS:{name.value}")
                            elif isinstance(name, x509.IPAddress):
                                san_values.append(f"IP:{name.value}")
                            elif isinstance(name, x509.RFC822Name):
                                san_values.append(f"email:{name.value}")
                            elif isinstance(name, x509.UniformResourceIdentifier):
                                san_values.append(f"URI:{name.value}")
                            else:
                                san_values.append(str(name))
                        extensions["subjectAltName"] = ", ".join(san_values)

                    elif ext.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                        cert_data.subject_key_identifier = ext.value.digest.hex().upper()
                        extensions["subjectKeyIdentifier"] = ext.value.digest.hex()

                    elif ext.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                        if ext.value.key_identifier:
                            cert_data.authority_key_identifier = ext.value.key_identifier.hex().upper()
                            extensions["authorityKeyIdentifier"] = ext.value.key_identifier.hex()

                    elif ext.oid == ExtensionOID.CERTIFICATE_POLICIES:
                        policies = []
                        try:
                            for policy in ext.value:
                                policy_id = policy.policy_identifier.dotted_string
                                policies.append(policy_id)
                            extensions["certificatePolicies"] = ", ".join(policies)
                        except Exception as e:
                            # Get the raw DER encoding of the extension
                            raw_der = ext.value.public_bytes()
                            hex_value = raw_der.hex()
                            logger.warning(f"Error parsing certificate policies in {cert_data.filename}: {e}. Raw value: {hex_value}")
                            extensions["certificatePolicies"] = f"Error parsing: {hex_value}"

                    elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                        crl_points = []
                        for point in ext.value:
                            if point.full_name:
                                for name in point.full_name:
                                    if isinstance(name, x509.UniformResourceIdentifier):
                                        crl_points.append(f"URI:{name.value}")
                                    else:
                                        crl_points.append(str(name))
                        extensions["cRLDistributionPoints"] = ", ".join(crl_points)

                    elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                        aia_points = []
                        for access in ext.value:
                            if access.access_method._name:
                                method = access.access_method._name
                            else:
                                method = access.access_method.dotted_string

                            if isinstance(access.access_location, x509.UniformResourceIdentifier):
                                location = f"URI:{access.access_location.value}"
                            else:
                                location = str(access.access_location)

                            aia_points.append(f"{method}:{location}")
                        extensions["authorityInfoAccess"] = ", ".join(aia_points)

                    else:
                        # For other extensions, try to get the raw DER value
                        try:
                            raw_der = ext.value.public_bytes()
                            hex_value = raw_der.hex()
                            extensions[friendly_name] = f"present (critical: {ext.critical}, value: {hex_value})"
                        except Exception:
                            extensions[friendly_name] = f"present (critical: {ext.critical})"

                except Exception as e:
                    # For individual extension errors, log but continue processing other extensions
                    try:
                        # Try to get the raw DER encoding of the extension
                        raw_der = ext.value.public_bytes()
                        hex_value = raw_der.hex()
                        logger.warning(f"Error processing extension {ext.oid.dotted_string} in {cert_data.filename}: {e}. Raw value: {hex_value}")
                        extensions[friendly_name] = f"Error parsing: {hex_value}"
                    except Exception:
                        logger.warning(f"Error processing extension {ext.oid.dotted_string} in {cert_data.filename}: {e}")
                        extensions[friendly_name] = f"Error parsing: {e}"

        except Exception as e:
            logger.warning(f"Error processing extensions for certificate {cert_data.fingerprint} in {cert_data.filename}: {e}")

        cert_data.extensions = extensions

    def _match_ssh_keys(self) -> int:
        """Match SSH public and private keys."""
        matches_found = 0
        
        for pub_hash, pub_data in self.keys.items():
            if not pub_data.key_type.startswith("SSH-") or pub_data.is_private:
                continue  # Only process SSH public keys
            
            for priv_hash, priv_data in self.keys.items():
                if not priv_data.key_type.startswith("SSH-") or not priv_data.is_private:
                    continue  # Only process SSH private keys
                
                # Skip if already matched
                if pub_hash in priv_data.matching_keys or priv_hash in pub_data.matching_keys:
                    continue
                
                # Check if base filenames match
                pub_basename = pub_data.key_info.get('base_filename', '')
                priv_basename = priv_data.key_info.get('base_filename', '')
                
                # Get filenames without paths
                pub_filename = os.path.basename(pub_data.filename)
                priv_filename = os.path.basename(priv_data.filename)
                
                # Check for common naming patterns
                if (pub_basename == priv_basename or 
                    pub_basename == priv_basename + ".pub" or 
                    priv_basename == pub_basename + ".pub" or
                    pub_filename == priv_filename + ".pub" or
                    pub_filename.replace(".pub", "") == priv_filename):
                    # Match found based on filename
                    pub_data.matching_keys.append(priv_hash)
                    priv_data.matching_keys.append(pub_hash)
                    matches_found += 1
                    logger.info(f"Found matching SSH key pair by filename: {pub_data.filename} -> {priv_data.filename}")
                    continue
                    
                # Try to match based on key data if available
                try:
                    if pub_data.ssh_key_data and "ssh-" in priv_data.pem_data and pub_data.ssh_key_data in priv_data.pem_data:
                        pub_data.matching_keys.append(priv_hash)
                        priv_data.matching_keys.append(pub_hash)
                        matches_found += 1
                        logger.info(f"Found matching SSH key pair by key data: {pub_data.filename} -> {priv_data.filename}")
                except Exception as e:
                    logger.debug(f"Error matching SSH keys by data: {e}")
        
        return matches_found


    def _process_key(self, filename: str, key_data: bytes, key_type: str, pem_data: str) -> None:
        """Process a key from PEM data."""
        try:
            # Handle public keys separately
            if key_type == "PUBLIC":
                try:
                    key = serialization.load_pem_public_key(
                        key_data,
                        backend=default_backend()
                    )
                    self._add_key(filename, key, "PUBLIC", pem_data, is_private=False)
                    return
                except Exception as e:
                    logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                    logger.debug(f"Failed to parse public key in {filename}: {e}")
                    return
    
            # For EC keys, special handling
            if key_type == "EC":
                try:
                    key = serialization.load_pem_private_key(
                        key_data,
                        password=None,
                        backend=default_backend()
                    )
                    self._add_key(filename, key, "EC", pem_data, encrypted=False, is_private=True)
                    return
                except Exception as e:
                    logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                    logger.debug(f"Failed to parse EC key in {filename}: {e}")
                    # Continue to generic handling
    
            # For DSA keys, try specific handling
            if key_type == "DSA":
                try:
                    key = serialization.load_pem_private_key(
                        key_data,
                        password=None,
                        backend=default_backend()
                    )
                    self._add_key(filename, key, "DSA", pem_data, encrypted=False, is_private=True)
                    return
                except Exception as e:
                    logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                    logger.debug(f"Failed to parse DSA key in {filename}: {e}")
                    # Continue to generic handling
    
            # For all other key types, try the generic approach
            try:
                key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
                encrypted = False
                # Set is_private=True for private keys
                self._add_key(filename, key, key_type, pem_data, encrypted=encrypted, is_private=True)
                return
    
            except TypeError as e:
                # If it fails with TypeError about password, it's encrypted
                if "password" in str(e).lower():
                    logger.info(f"Encrypted {key_type} key found in {filename}")
                    unknown_data = UnknownFormatData(
                        filename=filename,
                        format_type=key_type,
                        pem_data=pem_data,
                        encrypted=True,
                        description=f"{key_type} Private Key (encrypted)"
                    )
                    self.unknown_formats[filename].append(unknown_data)
                    return
            except Exception as e:
                # For any other error, still recognize the key format
                logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
                logger.debug(f"Failed to parse {key_type} key in {filename}: {e}")
                unknown_data = UnknownFormatData(
                    filename=filename,
                    format_type=key_type,
                    pem_data=pem_data,
                    encrypted=False,
                    description=f"{key_type} Private Key (format error: {str(e)})"
                )
                self.unknown_formats[filename].append(unknown_data)
                return
    
        except Exception as e:
            log_level = logging.INFO if self.settings.verbose else logging.DEBUG
            logger.debug('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            logger.log(log_level, f"Failed to parse {key_type} key in {filename}: {e}")
    
            # Still recognize the format even if we couldn't parse it
            unknown_data = UnknownFormatData(
                filename=filename,
                format_type=f"{key_type} PRIVATE KEY",
                pem_data=pem_data,
                encrypted=False,
                description=f"{key_type} Private Key (parsing error: {str(e)})"
            )
            self.unknown_formats[filename].append(unknown_data)

    def _add_key(self, filename: str, key: Any, key_type: str, pem_data: str, encrypted: bool = False, is_private: bool = None) -> None:
        """Add a key to the registry with enhanced support for EC, SSH, and DSA keys."""
        try:
            # Extract public key and key-specific information
            modulus = None
            key_info = {}

            # Determine if this is a private key if not explicitly specified
            if is_private is None:
                is_private = hasattr(key, 'private_numbers')

            # For SSH keys, try to get more specific information
            if key_type.startswith("SSH-"):
                ssh_type = key_type
            else:
                ssh_type = None

            if is_private:
                # This is a private key
                public_key = key.public_key()

                # Extract key-specific information based on public key type
                if isinstance(public_key, rsa.RSAPublicKey):
                    modulus = key.private_numbers().public_numbers.n
                    key_info = {
                        "algorithm": ssh_type or "RSA",
                        "key_size": key.key_size,
                        "modulus": f"{modulus:x}",
                        "public_exponent": key.private_numbers().public_numbers.e,
                        "is_private": True
                    }
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_info = {
                        "algorithm": ssh_type or "EC",
                        "curve": key.curve.name,
                        "x": f"{key.private_numbers().public_numbers.x:x}",
                        "y": f"{key.private_numbers().public_numbers.y:x}",
                        "is_private": True
                    }
                else:
                    # This might be a DSA key or another type
                    key_info = {
                        "algorithm": ssh_type or type(key).__name__,
                        "is_private": True
                    }

                    # Try to extract DSA parameters if available
                    try:
                        if hasattr(key, 'parameters') and callable(key.parameters):
                            params = key.parameters()
                            if hasattr(params, 'parameter_numbers') and callable(params.parameter_numbers):
                                param_numbers = params.parameter_numbers()
                                if hasattr(param_numbers, 'p'):
                                    # This is a DSA key with proper parameters
                                    key_size = param_numbers.p.bit_length()
                                    key_info.update({
                                        "algorithm": "DSA",
                                        "key_size": key_size,
                                        "y": f"{key.private_numbers().public_numbers.y:x}",
                                        "p": f"{param_numbers.p:x}",
                                        "q": f"{param_numbers.q:x}",
                                        "g": f"{param_numbers.g:x}"
                                    })
                    except Exception as e:
                        logger.debug(f"Error extracting DSA parameters: {e}")
            else:
                # It's already a public key
                public_key = key

                # Extract key-specific information for public keys
                if isinstance(public_key, rsa.RSAPublicKey):
                    modulus = public_key.public_numbers().n
                    key_info = {
                        "algorithm": ssh_type or "RSA Public Key",
                        "key_size": public_key.key_size,
                        "modulus": f"{modulus:x}",
                        "public_exponent": public_key.public_numbers().e,
                        "is_private": False
                    }
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_info = {
                        "algorithm": ssh_type or "EC Public Key",
                        "curve": public_key.curve.name,
                        "x": f"{public_key.public_numbers().x:x}",
                        "y": f"{public_key.public_numbers().y:x}",
                        "is_private": False
                    }
                else:
                    # This might be a DSA public key or another type
                    key_info = {
                        "algorithm": ssh_type or f"Unknown Public Key Type: {type(public_key).__name__}",
                        "is_private": False
                    }

                    # Try to extract DSA parameters if available
                    try:
                        if hasattr(public_key, 'parameters') and callable(public_key.parameters):
                            params = public_key.parameters()
                            if hasattr(params, 'parameter_numbers') and callable(params.parameter_numbers):
                                param_numbers = params.parameter_numbers()
                                if hasattr(param_numbers, 'p'):
                                    # This is a DSA key with proper parameters
                                    key_size = param_numbers.p.bit_length()
                                    key_info.update({
                                        "algorithm": "DSA Public Key",
                                        "key_size": key_size,
                                        "y": f"{public_key.public_numbers().y:x}",
                                        "p": f"{param_numbers.p:x}",
                                        "q": f"{param_numbers.q:x}",
                                        "g": f"{param_numbers.g:x}"
                                    })
                    except Exception as e:
                        logger.debug(f"Error extracting DSA parameters: {e}")

            # Generate a hash of the public key to use as ID
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
            key_hash.update(public_bytes)
            key_hash_value = key_hash.finalize().hex().upper()

            # Create key data object
            key_data = KeyData(
                filename=filename,
                key_obj=key,
                key_type=key_type,
                pem_data=pem_data,
                modulus=modulus,
                public_key_hash=key_hash_value,
                encrypted=encrypted,
                key_info=key_info,  # Add key-specific information
                is_private=is_private  # Add is_private flag
            )

            # Store key
            self.keys[key_hash_value] = key_data
            self.key_by_filename[filename].append(key_hash_value)

            # logger.debug(f"{key_data}")
            # logger.debug(f"{filename}")
            # logger.debug(f"{key_hash_value}")
            logger.debug(f"Added {'private' if is_private else 'public'} {key_type} key: {key_hash_value} from {filename}")

        except Exception as e:
            log_level = logging.INFO if self.settings.verbose else logging.DEBUG
            logger.log(log_level, f"Error processing key from {filename}: {e}")


    def debug_key_key_match(self, key_file1: str, key_file2: str) -> bool:
        """Debug key matching between two specific key files.

        Args:
            key_file1: Path to first key file
            key_file2: Path to second key file

        Returns:
            True if a match is found
        """
        logger.info(f"Debugging key match between {key_file1} and {key_file2}")

        # Find key hashes for these files
        key_hashes1 = self.key_by_filename.get(key_file1, [])
        if not key_hashes1:
            logger.warning(f"No keys found in {key_file1}")
            return False

        key_hashes2 = self.key_by_filename.get(key_file2, [])
        if not key_hashes2:
            logger.warning(f"No keys found in {key_file2}")
            return False

        # Check for matches
        for key_hash1 in key_hashes1:
            key_data1 = self.keys[key_hash1]
            logger.info(f"Key 1: {key_file1}")
            logger.info(f"  Type: {key_data1.key_type}")
            logger.info(f"  Is private: {key_data1.is_private}")
            logger.info(f"  Algorithm: {key_data1.key_info.get('algorithm', 'Unknown')}")

            for key_hash2 in key_hashes2:
                key_data2 = self.keys[key_hash2]
                logger.info(f"Key 2: {key_file2}")
                logger.info(f"  Type: {key_data2.key_type}")
                logger.info(f"  Is private: {key_data2.is_private}")
                logger.info(f"  Algorithm: {key_data2.key_info.get('algorithm', 'Unknown')}")

                try:
                    # Get public keys
                    if key_data1.is_private:
                        key1_public = key_data1.key_obj.public_key()
                    else:
                        key1_public = key_data1.key_obj

                    if key_data2.is_private:
                        key2_public = key_data2.key_obj.public_key()
                    else:
                        key2_public = key_data2.key_obj

                    # Log key types
                    logger.info(f"  Key 1 public key type: {type(key1_public).__name__}")
                    logger.info(f"  Key 2 public key type: {type(key2_public).__name__}")

                    # Get public key bytes
                    key1_bytes = key1_public.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    key2_bytes = key2_public.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    # Log byte hashes for comparison
                    key1_hash = hashlib.sha256(key1_bytes).hexdigest()
                    key2_hash = hashlib.sha256(key2_bytes).hexdigest()

                    logger.info(f"  Key 1 public key bytes hash: {key1_hash}")
                    logger.info(f"  Key 2 public key bytes hash: {key2_hash}")

                    # Compare
                    if key1_bytes == key2_bytes:
                        logger.info("MATCH FOUND: Public key bytes match")
                        return True
                    else:
                        logger.info("No match: Public key bytes differ")

                except Exception as e:
                    logger.warning(f"Error comparing keys: {e}")

        logger.warning("No match found between keys")
        return False


    def debug_ssh_keys(self) -> None:
        """Debug function to print information about all SSH keys."""
        logger.info(f"Total keys: {len(self.keys)}")
        
        ssh_keys = [(h, k) for h, k in self.keys.items() if k.key_type.startswith("SSH-")]
        logger.info(f"Found {len(ssh_keys)} SSH keys")
        
        for key_hash, key_data in ssh_keys:
            logger.info(f"SSH Key: {key_data.filename}")
            logger.info(f"  Hash: {key_hash}")
            logger.info(f"  Type: {key_data.key_type}")
            logger.info(f"  Is private: {key_data.is_private}")
            logger.info(f"  Algorithm: {key_data.key_info.get('algorithm', 'Unknown')}")
            logger.info(f"  Base filename: {key_data.key_info.get('base_filename', 'Unknown')}")
            
            if key_data.matching_keys:
                logger.info(f"  Matching keys: {len(key_data.matching_keys)}")
                for match_hash in key_data.matching_keys:
                    match_data = self.keys[match_hash]
                    logger.info(f"    - {match_data.filename} ({match_data.key_type}, private: {match_data.is_private})")
            else:
                logger.info("  No matching keys found")

    def debug_dsa_key(self, filename: str) -> None:
        """Debug a DSA key file."""

        try:
            print("in DSA debug")

            with open(filename, 'rb') as f:
                key_data = f.read()

            # Try to load the key
            key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )

            logger.info(f"Successfully loaded key from {filename}")
            logger.info(f"Key type: {type(key).__name__}")

            # Check if it's a DSA key
            if hasattr(key, 'parameters') and hasattr(key, 'private_numbers'):
                logger.info("Key has parameters and private_numbers methods (likely DSA)")

                # Get parameters
                params = key.parameters()
                logger.info(f"Parameters type: {type(params).__name__}")

                # Get parameter numbers
                param_numbers = params.parameter_numbers()
                logger.info(f"Parameter numbers type: {type(param_numbers).__name__}")

                # Get p, q, g values
                p = param_numbers.p
                q = param_numbers.q
                g = param_numbers.g

                logger.info(f"p bit length: {p.bit_length()}")
                logger.info(f"q bit length: {q.bit_length()}")
                logger.info(f"g bit length: {g.bit_length()}")

                # Get public key
                public_key = key.public_key()
                logger.info(f"Public key type: {type(public_key).__name__}")

                # Get public numbers
                public_numbers = key.private_numbers().public_numbers
                logger.info(f"Public numbers type: {type(public_numbers).__name__}")

                # Get y value
                y = public_numbers.y
                logger.info(f"y bit length: {y.bit_length()}")

                # Try to get public bytes
                public_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                logger.info(f"Public bytes length: {len(public_bytes)}")
                logger.info(f"Public bytes hash: {hashlib.sha256(public_bytes).hexdigest()}")

            else:
                logger.info("Key does not appear to be a DSA key")

        except Exception as e:
            logger.error(f"Error debugging DSA key {filename}: {e}")


    def debug_key_cert_match(self, cert_file: str, key_file: str) -> bool:
        """Debug key/certificate matching between two specific files.

        Args:
            cert_file: Path to certificate file
            key_file: Path to key file

        Returns:
            True if a match is found
        """
        logger.info(f"Debugging match between certificate {cert_file} and key {key_file}")

        # Find certificate fingerprints for this file
        cert_fps = self.cert_by_filename.get(cert_file, [])
        if not cert_fps:
            logger.warning(f"No certificates found in {cert_file}")
            return False

        # Find key hashes for this file
        key_hashes = self.key_by_filename.get(key_file, [])
        if not key_hashes:
            logger.warning(f"No keys found in {key_file}")
            return False

        # Check for matches
        for cert_fp in cert_fps:
            cert_data = self.certificates[cert_fp]
            cert_obj = cert_data.cert_obj

            try:
                cert_public_key = cert_obj.public_key()
                logger.info(f"Certificate public key type: {type(cert_public_key).__name__}")

                # Get certificate key details
                if isinstance(cert_public_key, rsa.RSAPublicKey):
                    cert_modulus = cert_public_key.public_numbers().n
                    cert_exponent = cert_public_key.public_numbers().e
                    logger.info(f"Certificate RSA modulus: {cert_modulus}")
                    logger.info(f"Certificate RSA exponent: {cert_exponent}")
                elif isinstance(cert_public_key, ec.EllipticCurvePublicKey):
                    cert_curve = cert_public_key.curve.name
                    cert_x = cert_public_key.public_numbers().x
                    cert_y = cert_public_key.public_numbers().y
                    logger.info(f"Certificate EC curve: {cert_curve}")
                    logger.info(f"Certificate EC point: ({cert_x}, {cert_y})")
                elif isinstance(cert_public_key, dsa.DSAPublicKey):
                    cert_y = cert_public_key.public_numbers().y
                    logger.info(f"Certificate DSA y: {cert_y}")

                # Get certificate public key bytes
                cert_public_bytes = cert_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                logger.info(f"Certificate public key bytes hash: {hashlib.sha256(cert_public_bytes).hexdigest()}")

                # Check each key
                for key_hash in key_hashes:
                    key_data = self.keys[key_hash]
                    logger.info(f"Key type: {key_data.key_type}")

                    # Get key details
                    if hasattr(key_data.key_obj, 'public_key'):
                        key_public_key = key_data.key_obj.public_key()
                    else:
                        key_public_key = key_data.key_obj

                    logger.info(f"Key public key type: {type(key_public_key).__name__}")

                    # Compare based on key type
                    if isinstance(cert_public_key, rsa.RSAPublicKey) and isinstance(key_public_key, rsa.RSAPublicKey):
                        key_modulus = key_public_key.public_numbers().n
                        key_exponent = key_public_key.public_numbers().e
                        logger.info(f"Key RSA modulus: {key_modulus}")
                        logger.info(f"Key RSA exponent: {key_exponent}")

                        if cert_modulus == key_modulus and cert_exponent == key_exponent:
                            logger.info("MATCH FOUND: RSA modulus and exponent match")
                            return True

                    elif isinstance(cert_public_key, ec.EllipticCurvePublicKey) and isinstance(key_public_key, ec.EllipticCurvePublicKey):
                        key_curve = key_public_key.curve.name
                        key_x = key_public_key.public_numbers().x
                        key_y = key_public_key.public_numbers().y
                        logger.info(f"Key EC curve: {key_curve}")
                        logger.info(f"Key EC point: ({key_x}, {key_y})")

                        if cert_curve == key_curve and cert_x == key_x and cert_y == key_y:
                            logger.info("MATCH FOUND: EC curve and point match")
                            return True

                    elif isinstance(cert_public_key, dsa.DSAPublicKey) and isinstance(key_public_key, dsa.DSAPublicKey):
                        key_y = key_public_key.public_numbers().y
                        logger.info(f"Key DSA y: {key_y}")

                        if cert_y == key_y:
                            logger.info("MATCH FOUND: DSA value match")
                            return True

                    # Compare public key bytes as a last resort
                    try:
                        key_public_bytes = key_public_key.public_bytes(
                            encoding=serialization.Encoding.DER,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                        logger.info(f"Key public key bytes hash: {hashlib.sha256(key_public_bytes).hexdigest()}")

                        if cert_public_bytes == key_public_bytes:
                            logger.info("MATCH FOUND: Public key bytes match")
                            return True
                    except Exception as e:
                        logger.debug(f"Error comparing public key bytes: {e}")

            except Exception as e:
                logger.warning(f"Error comparing certificate and key: {e}")

        logger.warning("No match found between certificate and key")
        return False


    #
    # it's *interesting* if we find a key that matches a cert we have
    #

    def _find_key_key_matches(self) -> None:
        """Find matches between public and private keys."""
        
        logger.info("Looking for matches between public and private keys")
        matches_found = 0
        
        # First, match SSH keys specifically
        ssh_matches = self._match_ssh_keys()
        matches_found += ssh_matches
        logger.info(f"Found {ssh_matches} SSH key matches")

        # Create lists of public and private keys (excluding SSH keys that were already matched)
        public_keys = []
        private_keys = []
        
        for key_hash, key_data in self.keys.items():
            # Skip SSH keys that already have matches
            if key_data.key_type.startswith("SSH-") and key_data.matching_keys:
                continue
                
            if key_data.is_private:
                private_keys.append((key_hash, key_data))
            else:
                public_keys.append((key_hash, key_data))
        
        logger.debug(f"Found {len(public_keys)} public keys and {len(private_keys)} private keys (excluding matched SSH keys)")
        
        # If we have both public and private keys, match them
        if len(public_keys) > 0 and len(private_keys) > 0:
            # Compare each public key with each private key
            for pub_hash, pub_data in public_keys:
                for priv_hash, priv_data in private_keys:
                    try:
                        # Skip if already matched
                        if pub_hash in priv_data.matching_keys or priv_hash in pub_data.matching_keys:
                            continue
                            
                        # Get public key from private key
                        if hasattr(priv_data.key_obj, 'public_key'):
                            priv_public_key = priv_data.key_obj.public_key()
                            
                            # Compare public key bytes
                            pub_bytes = pub_data.key_obj.public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            priv_bytes = priv_public_key.public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            
                            if pub_bytes == priv_bytes:
                                # Match found!
                                pub_data.matching_keys.append(priv_hash)
                                priv_data.matching_keys.append(pub_hash)
                                matches_found += 1
                                logger.info(f"Found matching key pair: {pub_data.filename} -> {priv_data.filename}")
                        
                    except Exception as e:
                        logger.debug(f"Error comparing keys {pub_data.filename} and {priv_data.filename}: {e}")
        else:
            # If we don't have a clear separation of public and private keys, try matching all keys with each other
            logger.debug("No clear public/private key separation, trying to match all keys")
            all_keys = [(h, k) for h, k in self.keys.items() if not (k.key_type.startswith("SSH-") and k.matching_keys)]
            
            for i in range(len(all_keys)):
                key1_hash, key1_data = all_keys[i]
                
                for j in range(i + 1, len(all_keys)):
                    key2_hash, key2_data = all_keys[j]
                    
                    # Skip if already matched
                    if key2_hash in key1_data.matching_keys or key1_hash in key2_data.matching_keys:
                        continue
                    
                    try:
                        # Get public key bytes for both keys
                        if hasattr(key1_data.key_obj, 'public_key') and key1_data.key_obj is not None:
                            key1_public = key1_data.key_obj.public_key()
                            
                            if hasattr(key2_data.key_obj, 'public_key') and key2_data.key_obj is not None:
                                key2_public = key2_data.key_obj.public_key()
                                
                                key1_bytes = key1_public.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                
                                key2_bytes = key2_public.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                
                                if key1_bytes == key2_bytes:
                                    # Match found!
                                    key1_data.matching_keys.append(key2_hash)
                                    key2_data.matching_keys.append(key1_hash)
                                    matches_found += 1
                                    logger.info(f"Found matching key pair: {key1_data.filename} <-> {key2_data.filename}")
                            elif key2_data.key_obj is not None:
                                # key2 is already a public key
                                key1_bytes = key1_public.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                
                                key2_bytes = key2_data.key_obj.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                
                                if key1_bytes == key2_bytes:
                                    # Match found!
                                    key1_data.matching_keys.append(key2_hash)
                                    key2_data.matching_keys.append(key1_hash)
                                    matches_found += 1
                                    logger.info(f"Found matching key pair: {key1_data.filename} <-> {key2_data.filename}")
                        elif key1_data.key_obj is not None and key2_data.key_obj is not None:
                            # key1 is already a public key
                            if hasattr(key2_data.key_obj, 'public_key'):
                                key2_public = key2_data.key_obj.public_key()
                                
                                key1_bytes = key1_data.key_obj.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                
                                key2_bytes = key2_public.public_bytes(
                                    encoding=serialization.Encoding.DER,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                
                                if key1_bytes == key2_bytes:
                                    # Match found!
                                    key1_data.matching_keys.append(key2_hash)
                                    key2_data.matching_keys.append(key1_hash)
                                    matches_found += 1
                                    logger.info(f"Found matching key pair: {key1_data.filename} <-> {key2_data.filename}")
                            
                    except Exception as e:
                        logger.debug(f"Error comparing keys {key1_data.filename} and {key2_data.filename}: {e}")
        
        logger.info(f"Found {matches_found} key-key matches in total")

    #
    # a CA creates a cert... the cert is below it. Etcetera.
    #
    def _build_certificate_hierarchy(self) -> None:
        """Build certificate hierarchy based on issuer/subject relationships."""
        # First pass: map certificates by subject key identifier
        ski_map = {}
        for fp, cert_data in self.certificates.items():
            if cert_data.subject_key_identifier:
                ski_map[cert_data.subject_key_identifier] = fp

        # Second pass: find issuers using authority key identifier
        for fp, cert_data in self.certificates.items():
            if cert_data.authority_key_identifier:
                aki = cert_data.authority_key_identifier
                if aki in ski_map:
                    issuer_fp = ski_map[aki]
                    self.cert_issuers[fp] = issuer_fp
                    logger.debug(f"Found issuer for {fp}: {issuer_fp} (using AKI)")

        # Third pass: try to find issuers by matching subject/issuer names
        for fp, cert_data in self.certificates.items():
            if fp not in self.cert_issuers and not cert_data.is_self_signed:
                for other_fp, other_cert_data in self.certificates.items():
                    if fp != other_fp and cert_data.issuer == other_cert_data.subject:
                        # Try to verify the signature
                        try:
                            cert_obj = cert_data.cert_obj
                            issuer_public_key = other_cert_data.cert_obj.public_key()

                            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                                issuer_public_key.verify(
                                    cert_obj.signature,
                                    cert_obj.tbs_certificate_bytes,
                                    padding.PKCS1v15(),
                                    cert_obj.signature_hash_algorithm
                                )
                                self.cert_issuers[fp] = other_fp
                                logger.debug(f"Found issuer for {fp}: {other_fp} (using subject/issuer match)")
                                break
                        except Exception:
                            # Verification failed, not the issuer
                            pass


    def generate_output(self) -> Dict[str, Any]:
        """Generate the output structure."""

        result = {
            "Certificate Authorities": [],
            "Certificates": [],
            "Unknown Formats": [],
            "Key Pairs": [],
            "Spare Keys": [] 
        }

        # Find all root CAs (self-signed certificates with CA:TRUE)
        root_cas = []
        for fp, cert_data in self.certificates.items():
            if cert_data.is_ca and cert_data.is_self_signed:
                root_cas.append(fp)

        # If no root CAs found, look for any CA certificates
        if not root_cas:
            for fp, cert_data in self.certificates.items():
                if cert_data.is_ca:
                    root_cas.append(fp)

        # Process each root CA
        processed_certs = set()
        for ca_fp in root_cas:
            ca_data = self.certificates[ca_fp]
            ca_output = self._format_certificate_for_output(ca_data)
            processed_certs.add(ca_fp)

            # Find subordinate CAs
            sub_cas = self._find_subordinate_cas(ca_fp, processed_certs)
            if sub_cas:
                ca_output["Subordinate CAs"] = {}
                for sub_ca_fp in sub_cas:
                    sub_ca_data = self.certificates[sub_ca_fp]
                    sub_ca_name = self._get_cert_name(sub_ca_data)
                    ca_output["Subordinate CAs"][sub_ca_name] = self._format_certificate_for_output(sub_ca_data)
                    processed_certs.add(sub_ca_fp)

                    # Find certificates issued by this sub CA
                    sub_ca_certs = self._find_issued_certificates(sub_ca_fp, processed_certs)
                    if sub_ca_certs:
                        ca_output["Subordinate CAs"][sub_ca_name]["Certificates"] = {}
                        for cert_fp in sub_ca_certs:
                            cert_data = self.certificates[cert_fp]
                            cert_name = self._get_cert_name(cert_data)
                            ca_output["Subordinate CAs"][sub_ca_name]["Certificates"][cert_name] = self._format_certificate_for_output(cert_data)
                            processed_certs.add(cert_fp)

            # Find certificates issued directly by this CA
            ca_certs = self._find_issued_certificates(ca_fp, processed_certs)
            if ca_certs:
                ca_output["Certificates"] = {}
                for cert_fp in ca_certs:
                    cert_data = self.certificates[cert_fp]
                    cert_name = self._get_cert_name(cert_data)
                    ca_output["Certificates"][cert_name] = self._format_certificate_for_output(cert_data)
                    processed_certs.add(cert_fp)

            result["Certificate Authorities"].append(ca_output)

        # Add remaining certificates (not issued by any CA in our set)
        for fp, cert_data in self.certificates.items():
            if fp not in processed_certs:
                cert_name = self._get_cert_name(cert_data)
                result["Certificates"].append({
                    cert_name: self._format_certificate_for_output(cert_data)
                })


        # Add key pairs (matching public-private key pairs)
        processed_keys = set()
        for key_hash, key_data in self.keys.items():
            if key_hash in processed_keys:
                continue
    
            if key_data.matching_keys:
                for matched_key_hash in key_data.matching_keys:
                    if matched_key_hash in processed_keys:
                        continue
    
                    matched_key_data = self.keys[matched_key_hash]
    
                    # Determine which is public and which is private
                    if key_data.is_private:
                        private_key = key_data
                        public_key = matched_key_data
                    else:
                        private_key = matched_key_data
                        public_key = key_data
    
                    # Add to output
                    key_pair = {
                        "Private Key": {
                            "filename": private_key.filename,
                            "type": private_key.key_type,
                            "algorithm": private_key.key_info.get("algorithm", "Unknown")
                        },
                        "Public Key": {
                            "filename": public_key.filename,
                            "type": public_key.key_type,
                            "algorithm": public_key.key_info.get("algorithm", "Unknown")
                        }
                    }
    
                    # Include PEM data if requested
                    if self.settings.include_pem:
                        if private_key.pem_data:
                            key_pair["Private Key"]["pem_data"] = private_key.pem_data
                        if public_key.pem_data:
                            key_pair["Public Key"]["pem_data"] = public_key.pem_data
    
                    result["Key Pairs"].append(key_pair)
                    processed_keys.add(key_hash)
                    processed_keys.add(matched_key_hash)


    
        # Add key pairs (matching public-private key pairs)
        processed_keys = set()
        for key_hash, key_data in self.keys.items():
            if key_hash in processed_keys:
                continue
    
            if key_data.matching_keys:
                for matched_key_hash in key_data.matching_keys:
                    if matched_key_hash in processed_keys:
                        continue
    
                    matched_key_data = self.keys[matched_key_hash]
    
                    # Determine which is public and which is private
                    if key_data.is_private:
                        private_key = key_data
                        public_key = matched_key_data
                    else:
                        private_key = matched_key_data
                        public_key = key_data
    
                    # Add to output
                    key_pair = {
                        "Private Key": {
                            "filename": private_key.filename,
                            "type": private_key.key_type,
                            "algorithm": private_key.key_info.get("algorithm", "Unknown")
                        },
                        "Public Key": {
                            "filename": public_key.filename,
                            "type": public_key.key_type,
                            "algorithm": public_key.key_info.get("algorithm", "Unknown")
                        }
                    }
    
                    # Include PEM data if requested
                    if self.settings.include_pem:
                        if private_key.pem_data:
                            key_pair["Private Key"]["pem_data"] = private_key.pem_data
                        if public_key.pem_data:
                            key_pair["Public Key"]["pem_data"] = public_key.pem_data
    
                    result["Key Pairs"].append(key_pair)
                    processed_keys.add(key_hash)
                    processed_keys.add(matched_key_hash)
    
        # Add spare keys (keys that aren't matched to any certificate or other key)
        for key_hash, key_data in self.keys.items():
            # Skip keys that have already been processed as part of a key pair
            if key_hash in processed_keys:
                continue
                
            # Skip keys that are matched to certificates
            if key_data.matching_certs:
                continue
                
            # This is a spare key - add it to the output
            spare_key = {
                "filename": key_data.filename,
                "type": key_data.key_type,
                "is_private": key_data.is_private,
                "algorithm": key_data.key_info.get("algorithm", "Unknown")
            }
            
            # Add additional information based on key type
            if key_data.key_type.startswith("SSH-"):
                spare_key["ssh_type"] = key_data.key_info.get("ssh_type", "")
                if not key_data.is_private:
                    spare_key["comment"] = key_data.key_info.get("comment", "")
            
            # Include key size if available
            if "key_size" in key_data.key_info:
                spare_key["key_size"] = key_data.key_info["key_size"]
                
            # Include encryption status
            spare_key["encrypted"] = key_data.encrypted
            
            # Include PEM data if requested
            if self.settings.include_pem and key_data.pem_data:
                spare_key["pem_data"] = key_data.pem_data
                
            result["Spare Keys"].append(spare_key)


        # Add unknown formats
        if self.unknown_formats:
            for filename, formats in self.unknown_formats.items():
                for fmt in formats:
                    unknown_format = {
                        "filename": filename,
                        "format": fmt.format_type,
                        "description": fmt.description,
                        "encrypted": fmt.encrypted
                    }

                    # Include PEM data if requested
                    if self.settings.include_pem and fmt.pem_data:
                        unknown_format["pem_data"] = fmt.pem_data

                    result["Unknown Formats"].append(unknown_format)

        return result

    #
    # lotsa important things happen with sub-CAs
    #
    def _find_subordinate_cas(self, issuer_fp: str, processed_certs: Set[str]) -> List[str]:
        """Find subordinate CAs issued by a given CA.

        Args:
            issuer_fp: Fingerprint of the issuing CA
            processed_certs: Set of already processed certificates

        Returns:
            List of fingerprints of subordinate CAs
        """
        sub_cas = []
        for fp, cert_data in self.certificates.items():
            if fp in processed_certs:
                continue

            if fp in self.cert_issuers and self.cert_issuers[fp] == issuer_fp and cert_data.is_ca:
                sub_cas.append(fp)

        return sub_cas

    #
    # each CA/CA-lite may or may not have certs that it issued....
    #
    def _find_issued_certificates(self, issuer_fp: str, processed_certs: Set[str]) -> List[str]:
        """Find certificates issued by a given CA.

        Args:
            issuer_fp: Fingerprint of the issuing CA
            processed_certs: Set of already processed certificates

        Returns:
            List of fingerprints of issued certificates
        """
        certs = []
        for fp, cert_data in self.certificates.items():
            if fp in processed_certs:
                continue

            if fp in self.cert_issuers and self.cert_issuers[fp] == issuer_fp and not cert_data.is_ca:
                certs.append(fp)

        return certs

    def _format_certificate_for_output(self, cert_data: CertificateData) -> Dict[str, Any]:
        """Format certificate data for output.

        Args:    cert_data: Certificate data
        Returns: Dictionary with formatted certificate data

        """
        result = {
            "Name":                 self._get_cert_name(cert_data),
            "filename":             cert_data.filename,
            "Serial Number":        cert_data.serial_number,
            "SHA256 Fingerprint":   cert_data.fingerprint,
            "UID":                  cert_data.fingerprint,
            "Signature Algorithm":  cert_data.signature_algorithm,
            "Issuer":               cert_data.issuer,
            "Validity": {
                "Not Before":       cert_data.not_before.strftime("%b %d %H:%M:%S %Y GMT"),
                "Not After":        cert_data.not_after.strftime("%b %d %H:%M:%S %Y GMT")
            },
            "Subject":              cert_data.subject,
            "Public Key":           cert_data.public_key_info,
            "Self Signed":          cert_data.is_self_signed
        }

        # Add trust information for self-signed certificates
        if cert_data.is_self_signed:
            if cert_data.is_ca:
                result["Trust Status"] = "Self-signed root CA"
            else:
                result["Trust Status"] = "Self-signed certificate (not a CA)"

        # Include PEM data if requested
        if self.settings.include_pem and cert_data.pem_data:
            result["pem_data"] = cert_data.pem_data

        # Add extensions if present
        if cert_data.extensions:
            result["X509v3 extensions"] = cert_data.extensions

        # Add key information if available
        if cert_data.matching_keys:
            key_info = []
            for key_hash in cert_data.matching_keys:
                key_data = self.keys[key_hash]
                key_entry = {
                    "filename": key_data.filename,
                    "type": key_data.key_type,
                    "encrypted": key_data.encrypted
                }

                # Include PEM data if requested
                if self.settings.include_pem and key_data.pem_data:
                    key_entry["pem_data"] = key_data.pem_data

                key_info.append(key_entry)
            result["Private Key"] = key_info
        else:
            result["Private Key"] = "unknown"

        return result


    def _get_cert_name(self, cert_data: CertificateData) -> str:
        """Get a friendly name for a certificate.

        Args:
            cert_data: Certificate data

        Returns:
            Friendly name for the certificate
        """
        # Try Common Name first
        if "commonName" in cert_data.subject:
            return cert_data.subject["commonName"]

        # Try Organization Name
        if "organizationName" in cert_data.subject:
            return cert_data.subject["organizationName"]

        # Fall back to fingerprint
        return cert_data.fingerprint[:8]

#
# some fun (woohoo! :)) stats
#
def text_summary(rez):

    # Text output - simplified for now
    print("Certificate Analysis Results:")
    print(f"Total CAs: {len(rez['Certificate Authorities'])}")
    print(f"Total Certificates: {len(rez['Certificates'])}")

    # Print CAs
    for ca in rez["Certificate Authorities"]:
        print(f"\nCA: {ca['Name']}")
        print(f"  Fingerprint: {ca['SHA256 Fingerprint']}")
        print(f"  File: {ca['filename']}")
        if ca.get("Public Key"):
            print(f"  Public Key: {ca['Public Key']['algorithm']}")
            if "key_size" in ca["Public Key"]:
                print(f"  Key Size: {ca['Public Key']['key_size']} bits")
        if ca.get("Subordinate CAs"):
            print(f"  Subordinate CAs: {len(ca['Subordinate CAs'])}")
            for sub_ca_name, sub_ca in ca["Subordinate CAs"].items():
                print(f"    - {sub_ca_name}")
                if sub_ca.get("Certificates"):
                    print(f"      Issued Certificates: {len(sub_ca['Certificates'])}")
                    for cert_name in sub_ca["Certificates"]:
                        print(f"        - {cert_name}")

        if ca.get("Certificates"):
            print(f"  Issued Certificates: {len(ca['Certificates'])}")
            for cert_name in ca["Certificates"]:
                print(f"    - {cert_name}")

    # Print certificates
    if rez["Certificates"]:
        print("\nUnassociated Certificates:")
        for cert_entry in rez["Certificates"]:
            for name, details in cert_entry.items():
                print(f"  - {name} ({details['filename']})")

    # Print unknown formats
    if rez["Unknown Formats"]:
        print("\nUnknown or Unsupported Formats:")
        for fmt in rez["Unknown Formats"]:
            encrypted = " (encrypted)" if fmt["encrypted"] else ""
            print(f"  - {fmt['filename']}: {fmt['description']}{encrypted}")

    # Print certificates with matching keys
    certs_with_keys = []
    for ca in rez["Certificate Authorities"]:
        if ca["Private Key"] != "unknown":
            certs_with_keys.append((ca["Name"], ca["filename"], ca["Private Key"]))

        if ca.get("Subordinate CAs"):
            for sub_ca_name, sub_ca in ca["Subordinate CAs"].items():
                if sub_ca["Private Key"] != "unknown":
                    certs_with_keys.append((sub_ca_name, sub_ca["filename"], sub_ca["Private Key"]))

                if sub_ca.get("Certificates"):
                    for cert_name, cert in sub_ca["Certificates"].items():
                        if cert["Private Key"] != "unknown":
                            certs_with_keys.append((cert_name, cert["filename"], cert["Private Key"]))

        if ca.get("Certificates"):
            for cert_name, cert in ca["Certificates"].items():
                if cert["Private Key"] != "unknown":
                    certs_with_keys.append((cert_name, cert["filename"], cert["Private Key"]))

    for cert_entry in rez["Certificates"]:
        for name, details in cert_entry.items():
            if details["Private Key"] != "unknown":
                certs_with_keys.append((name, details["filename"], details["Private Key"]))

    if certs_with_keys:
        print("\nCertificates with matching private keys:")
        for name, cert_file, key_info in certs_with_keys:
            if isinstance(key_info, list):
                key_files = ", ".join(k["filename"] for k in key_info)
                print(f"  - {name}: Certificate in {cert_file}, Key(s) in {key_files}")
            else:
                print(f"  - {name}: Certificate in {cert_file}, Key info: {key_info}")

#
# what goes on in CLI-land?
#
def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns: Parsed arguments

    """

    parser = argparse.ArgumentParser(
        description="Analyze X.509 certificates and keys"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    parser.add_argument(
        "--debug-dsa",
        metavar="DSA_KEY_FILE",
        help="Debug a DSA key file"
    )
    parser.add_argument(
        "--debug-key-key-match",
        nargs=2,
        metavar=("KEY_FILE1", "KEY_FILE2"),
        help="Debug matching between two specific key files"
    )
    parser.add_argument(
        "--debug-match",
        nargs=2,
        metavar=("CERT_FILE", "KEY_FILE"),
        help="Debug matching between a specific certificate and key file"
    )
    parser.add_argument(
        "--debug-ssh",
        action="store_true",
        help="Debug SSH key processing"
    )
    parser.add_argument(
        "files",
        metavar="FILES",
        nargs="*",
        help="Files to analyze"
    )
    parser.add_argument(
        "--max_file_size",
        "-m",
        type=int,
        default=MAX_FILE_SIZE,
        help="Maximum size in bytes to process potential PEM/key/etc files"
    )
    parser.add_argument(
        "--no-duplicity",
        action="store_true",
        help="Report duplicate certificates"
    )
    parser.add_argument(
        "--no-pem",
        action="store_true",
        help="Don't include PEM data in output"
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()


#
# OMG... finally... it begins!
#

args = parse_args()

settings = Settings(
    max_file_size   = args.max_file_size,
    verbose         = args.verbose,
    debug           = args.debug,
    duplicity       = not args.no_duplicity,
    output_format   = args.output,
    include_pem     = not args.no_pem
)

#
# the main kahuna that everything gets tossed into
#
certitude = Certitude(settings)

#
# look at two (matching?) files
#
if args.debug_match:
    logger.setLevel(logging.DEBUG)
    cert_file, key_file = args.debug_match
    certitude.process_files([cert_file, key_file])
    certitude.debug_key_cert_match(cert_file, key_file)
    sys.exit(0)

if args.debug_dsa:
    logger.setLevel(logging.DEBUG)
    certitude.debug_dsa_key(args.debug_dsa)
    sys.exit(0)

if args.debug_ssh:
    logger.setLevel(logging.DEBUG)
    certitude.process_files(args.files)
    certitude.debug_ssh_keys()
    sys.exit(0)

if args.debug_key_key_match:
    logger.setLevel(logging.DEBUG)
    key_file1, key_file2 = args.debug_key_key_match
    certitude.process_files([key_file1, key_file2])
    certitude.debug_key_key_match(key_file1, key_file2)
    sys.exit(0)

#
# all the werk... here
#
certitude.process_files(args.files)

result    = certitude.generate_output()

#
# ok... if no files, then try to read stdin
#
#   https://stackoverflow.com/questions/1450393/how-do-you-read-from-stdin
#

if not args.files:
    if select.select([sys.stdin,],[],[],0.0)[0]:
        # print "stdin detected!"
        args.files = []
        for filey in fileinput.input():
            filey = filey[:-1]
            # files could have spaces
            # filey = filey.strip()
            args.files.append(filey)

    else:
        print("Error: No files specified")
        sys.exit(1)

#
# Suppress possibly/probably spurious warnings
#
# warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")
# warnings.filterwarnings("ignore", message="Properties that return a naïve datetime object have been deprecated")

#
# json => machine readable, a bit human readable
# text => summary, some interesting stuff, much less data
#
if settings.output_format == "json":
    # Convert datetime objects to strings for JSON serialization
    print(json.dumps(result, indent=2, default=str))

else:
    text_summary(result)


