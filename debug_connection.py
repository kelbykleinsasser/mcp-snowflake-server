#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import logging
import dotenv
from snowflake.snowpark import Session
import traceback
import socket
import ssl
from backports.ssl_match_hostname import match_hostname, CertificateError
import urllib.request
from datetime import datetime, timezone
import tempfile
import json

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('snowflake_debug')

# Configure Snowflake specific logging
for logger_name in ['snowflake.connector', 'botocore', 'boto3']:
    logging.getLogger(logger_name).setLevel(logging.DEBUG)

def get_snowflake_hostname(account):
    """Generate appropriate Snowflake hostname based on account identifier."""
    # Remove any quotes from the account identifier
    account = account.strip('"\'')
    
    # If it's already a full URL, extract just the hostname part
    if '.snowflakecomputing.com' in account:
        return account
    
    # Try different hostname patterns
    hostnames = [
        f"{account}.snowflakecomputing.com",
    ]
    
    # Test each hostname
    for hostname in hostnames:
        try:
            socket.getaddrinfo(hostname, 443)
            logger.info(f"Successfully resolved hostname: {hostname}")
            return hostname
        except socket.gaierror:
            continue
    
    # If no hostname resolves, return the basic one
    return f"{account}.snowflakecomputing.com"

def test_dns_resolution(hostname):
    """Test DNS resolution for the Snowflake hostname."""
    logger.info(f"Testing DNS resolution for {hostname}...")
    try:
        ip_addresses = socket.getaddrinfo(hostname, 443)
        logger.info(f"Successfully resolved {hostname} to: {ip_addresses}")
        return True
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {hostname}: {e}")
        return False

def test_ssl_connection(hostname):
    """Test SSL connection to the Snowflake hostname with detailed certificate validation."""
    logger.info(f"Testing SSL connection to {hostname}...")
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Log detailed certificate information
                logger.info("SSL Certificate Details:")
                logger.info(f"Subject: {cert.get('subject', [])}")
                logger.info(f"Issuer: {cert.get('issuer', [])}")
                logger.info(f"Valid from: {cert.get('notBefore', '')}")
                logger.info(f"Valid until: {cert.get('notAfter', '')}")
                logger.info(f"Serial number: {cert.get('serialNumber', '')}")
                
                # Parse certificate dates and convert to timezone-aware
                def parse_cert_date(date_str):
                    dt = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                    return dt.replace(tzinfo=timezone.utc)
                
                not_after = parse_cert_date(cert['notAfter'])
                not_before = parse_cert_date(cert['notBefore'])
                now = datetime.now(timezone.utc)
                
                if now < not_before:
                    logger.error("Certificate is not yet valid!")
                    return False
                if now > not_after:
                    logger.error("Certificate has expired!")
                    return False
                
                # Check SANs (Subject Alternative Names)
                sans = cert.get('subjectAltName', [])
                logger.info("Subject Alternative Names:")
                for san_type, san_value in sans:
                    logger.info(f"  {san_type}: {san_value}")
                
                # Verify hostname matches certificate
                try:
                    match_hostname(cert, hostname)
                    logger.info("Hostname validation successful")
                except CertificateError as e:
                    logger.error(f"Hostname validation failed: {e}")
                    return False
                
                return True
                
    except ssl.SSLError as e:
        logger.error(f"SSL Error: {e}")
        logger.error("This might indicate a certificate validation issue or a protocol mismatch")
        return False
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        return False

def load_and_verify_env():
    """Load and verify all required environment variables."""
    logger.info("Loading environment variables...")
    
    # Load .env file
    env_path = Path('.env')
    if not env_path.exists():
        logger.error(f".env file not found at {env_path.absolute()}")
        sys.exit(1)
    
    dotenv.load_dotenv(env_path)
    
    # Required variables
    required_vars = [
        'SNOWFLAKE_USER',
        'SNOWFLAKE_ACCOUNT',
        'SNOWFLAKE_PASSWORD',
        'SNOWFLAKE_ROLE',
        'SNOWFLAKE_DATABASE',
        'SNOWFLAKE_SCHEMA',
        'SNOWFLAKE_WAREHOUSE'
    ]
    
    # Check and display each variable (masked for sensitive data)
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            logger.error(f"Missing required environment variable: {var}")
            sys.exit(1)
        
        # Mask sensitive information in logs
        if 'PASSWORD' in var:
            display_value = '*' * len(value)
        else:
            display_value = value
        logger.info(f"{var}: {display_value}")

def test_connection():
    """Test Snowflake connection with detailed error reporting."""
    logger.info("Creating connection parameters...")
    
    # Get account identifier and ensure it's lowercase
    account = os.getenv("SNOWFLAKE_ACCOUNT", "").lower()
    hostname = get_snowflake_hostname(account)
    
    # Test DNS and SSL before attempting connection
    if not test_dns_resolution(hostname):
        logger.error("DNS resolution failed. Please check your account identifier.")
        return False
        
    if not test_ssl_connection(hostname):
        logger.error("SSL connection failed. Please check your network and SSL configuration.")
        return False
    
    connection_parameters = {
        "user": os.getenv("SNOWFLAKE_USER"),
        "password": os.getenv("SNOWFLAKE_PASSWORD"),
        "account": account,
        "role": os.getenv("SNOWFLAKE_ROLE"),
        "database": os.getenv("SNOWFLAKE_DATABASE"),
        "schema": os.getenv("SNOWFLAKE_SCHEMA"),
        "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
        # SSL settings
        "insecure_mode": True,  # Temporarily disable certificate validation
        "validate_default_parameters": True,
    }
    
    logger.info("Attempting to create Snowflake session...")
    try:
        session = Session.builder.configs(connection_parameters).create()
        logger.info("Successfully connected to Snowflake!")
        
        # Test basic query
        logger.info("Testing simple query...")
        result = session.sql("SELECT CURRENT_WAREHOUSE(), CURRENT_DATABASE(), CURRENT_SCHEMA()").collect()
        logger.info(f"Query result: {result}")
        
        return True
        
    except Exception as e:
        logger.error("Failed to connect to Snowflake")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error message: {str(e)}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        
        # Additional connection debugging
        logger.info("Debug information:")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Snowpark package version: {Session.__module__}")
        
        return False

def main():
    logger.info("Starting Snowflake connection debug script...")
    load_and_verify_env()
    success = test_connection()
    
    if success:
        logger.info("All tests passed successfully!")
        sys.exit(0)
    else:
        logger.error("Connection test failed. Please check the logs above for details.")
        sys.exit(1)

if __name__ == "__main__":
    main() 