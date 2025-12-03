#!/usr/bin/env python3
"""
Cardano Stake Pool ID Generator with Custom Prefix

This script generates Cardano stake pool cold keys (Ed25519) and derives
the pool ID using Cardano-compatible hashing (Blake2b-224). It repeatedly
generates keys until finding a pool ID that starts with the desired prefix.

Usage:
    python cardano_pool_id_generator.py --prefix blink

Requirements:
    - Python 3.8+
    - pynacl (pip install pynacl)

Security Note:
    The generated private keys are sensitive. Handle them securely and
    never share them. The output files should be stored in a secure location.
"""

import argparse
import hashlib
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

try:
    from nacl.signing import SigningKey
except ImportError:
    print("Error: pynacl library is required. Install it with: pip install pynacl")
    sys.exit(1)


# Bech32 encoding characters (Cardano uses this for pool IDs)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


@dataclass
class PoolKeyPair:
    """Represents a Cardano stake pool key pair with derived pool ID."""
    private_key: bytes
    public_key: bytes
    pool_id_hash: bytes
    pool_id_bech32: str


def compute_pool_id_hash(public_key: bytes) -> bytes:
    """
    Compute the pool ID hash from a public key using Blake2b-224.
    
    Cardano uses Blake2b-224 to hash the cold verification key to derive
    the pool ID (28 bytes).
    
    Args:
        public_key: The Ed25519 public key (32 bytes)
    
    Returns:
        The pool ID hash (28 bytes)
    """
    return hashlib.blake2b(public_key, digest_size=28).digest()


def bech32_polymod(values: list) -> int:
    """Internal function for Bech32 checksum calculation."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list:
    """Expand the HRP (human-readable part) for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: list) -> list:
    """Create a Bech32 checksum."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list:
    """Convert a byte array between bit representations."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return []
    return ret


def encode_bech32(hrp: str, data: bytes) -> str:
    """
    Encode data as a Bech32 string.
    
    Args:
        hrp: Human-readable part (e.g., "pool" for pool IDs)
        data: The data to encode
    
    Returns:
        Bech32-encoded string
    """
    converted = convertbits(data, 8, 5)
    checksum = bech32_create_checksum(hrp, converted)
    combined = converted + checksum
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


def generate_pool_keypair() -> PoolKeyPair:
    """
    Generate a new Ed25519 key pair and derive the pool ID.
    
    Returns:
        PoolKeyPair containing the private key, public key, and pool ID
    """
    # Generate Ed25519 key pair
    signing_key = SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    
    # Compute pool ID hash (Blake2b-224 of public key)
    pool_id_hash = compute_pool_id_hash(public_key)
    
    # Encode as Bech32 with "pool" prefix
    pool_id_bech32 = encode_bech32("pool", pool_id_hash)
    
    return PoolKeyPair(
        private_key=private_key,
        public_key=public_key,
        pool_id_hash=pool_id_hash,
        pool_id_bech32=pool_id_bech32
    )


def search_for_prefix(target_prefix: str, batch_size: int = 1000) -> Tuple[Optional[PoolKeyPair], int]:
    """
    Search for a pool ID with the specified prefix.
    
    This function runs in a worker process and generates keys in batches,
    checking each for the target prefix.
    
    Args:
        target_prefix: The desired prefix (after "pool1")
        batch_size: Number of keys to generate per batch
    
    Returns:
        Tuple of (PoolKeyPair if found, number of attempts)
    """
    full_prefix = "pool1" + target_prefix.lower()
    attempts = 0
    
    for _ in range(batch_size):
        attempts += 1
        keypair = generate_pool_keypair()
        
        if keypair.pool_id_bech32.startswith(full_prefix):
            return keypair, attempts
    
    return None, attempts


def estimate_difficulty(prefix_length: int) -> int:
    """
    Estimate the expected number of attempts to find a matching prefix.
    
    Bech32 uses 32 characters, so each additional character multiplies
    the difficulty by approximately 32.
    
    Args:
        prefix_length: Length of the desired prefix
    
    Returns:
        Estimated number of attempts
    """
    return 32 ** prefix_length


def save_keys(keypair: PoolKeyPair, output_dir: Path) -> None:
    """
    Save the generated keys and pool ID to files.
    
    The files are saved in Cardano-compatible format:
    - cold.skey: Private signing key (JSON envelope format)
    - cold.vkey: Public verification key (JSON envelope format)
    - pool_id.txt: The pool ID in Bech32 format
    
    Args:
        keypair: The generated key pair
        output_dir: Directory to save the files
    """
    import json
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Set restrictive permissions on the output directory
    os.chmod(output_dir, 0o700)
    
    # Save private key (signing key) in Cardano JSON envelope format
    skey_path = output_dir / "cold.skey"
    skey_data = {
        "type": "StakePoolSigningKey_ed25519",
        "description": "Stake Pool Cold Signing Key",
        "cborHex": "5820" + keypair.private_key.hex()
    }
    with open(skey_path, "w") as f:
        json.dump(skey_data, f, indent=4)
    os.chmod(skey_path, 0o600)  # Restrictive permissions for private key
    
    # Save public key (verification key) in Cardano JSON envelope format
    vkey_path = output_dir / "cold.vkey"
    vkey_data = {
        "type": "StakePoolVerificationKey_ed25519",
        "description": "Stake Pool Cold Verification Key",
        "cborHex": "5820" + keypair.public_key.hex()
    }
    with open(vkey_path, "w") as f:
        json.dump(vkey_data, f, indent=4)
    os.chmod(vkey_path, 0o644)
    
    # Save pool ID
    pool_id_path = output_dir / "pool_id.txt"
    with open(pool_id_path, "w") as f:
        f.write(keypair.pool_id_bech32 + "\n")
    os.chmod(pool_id_path, 0o644)
    
    print(f"\nKeys saved to: {output_dir}")
    print(f"  - Private key: {skey_path}")
    print(f"  - Public key:  {vkey_path}")
    print(f"  - Pool ID:     {pool_id_path}")


def main():
    """Main entry point for the Cardano Pool ID Generator."""
    parser = argparse.ArgumentParser(
        description="Generate Cardano stake pool ID with custom prefix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python cardano_pool_id_generator.py --prefix blink
    python cardano_pool_id_generator.py --prefix abc --workers 8
    python cardano_pool_id_generator.py --prefix z --output ./my_pool_keys

Security Warning:
    The generated private key is extremely sensitive. Never share it,
    and store the output files in a secure location with proper backups.
"""
    )
    
    parser.add_argument(
        "--prefix", "-p",
        required=True,
        help="Desired prefix for the pool ID (after 'pool1')"
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Number of worker processes (default: number of CPU cores)"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="./pool_keys",
        help="Output directory for generated keys (default: ./pool_keys)"
    )
    
    parser.add_argument(
        "--max-attempts", "-m",
        type=int,
        default=0,
        help="Maximum number of attempts (0 = unlimited, default: 0)"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )
    
    args = parser.parse_args()
    
    # Validate prefix (must be valid Bech32 characters after pool1)
    prefix = args.prefix.lower()
    for char in prefix:
        if char not in BECH32_CHARSET:
            print(f"Error: Invalid character '{char}' in prefix.")
            print(f"Valid Bech32 characters: {BECH32_CHARSET}")
            sys.exit(1)
    
    # Warn about computational intensity for long prefixes
    difficulty = estimate_difficulty(len(prefix))
    print(f"Target pool ID prefix: pool1{prefix}")
    print(f"Prefix length: {len(prefix)} characters")
    print(f"Estimated attempts needed: ~{difficulty:,}")
    
    if len(prefix) >= 4:
        print("\n⚠️  WARNING: Long prefixes require significant computational resources.")
        print("   This may take hours, days, or longer depending on prefix length.")
        print(f"   A {len(prefix)}-character prefix requires approximately {difficulty:,} attempts on average.")
    
    if len(prefix) >= 6:
        print("\n⚠️  EXTREME WARNING: A 6+ character prefix is computationally infeasible.")
        print("   Consider using a shorter prefix.")
        response = input("\nDo you want to continue? (yes/no): ")
        if response.lower() not in ("yes", "y"):
            print("Aborted.")
            sys.exit(0)
    
    print("\nStarting search...")
    
    # Set up multiprocessing
    num_workers = args.workers or os.cpu_count() or 4
    print(f"Using {num_workers} worker processes")
    
    batch_size = 10000  # Keys per batch per worker
    total_attempts = 0
    start_time = time.time()
    result = None
    
    try:
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            while result is None:
                # Submit batch of work
                futures = [
                    executor.submit(search_for_prefix, prefix, batch_size)
                    for _ in range(num_workers)
                ]
                
                # Wait for results
                for future in as_completed(futures):
                    keypair, attempts = future.result()
                    total_attempts += attempts
                    
                    if keypair is not None:
                        result = keypair
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break
                
                # Check max attempts limit
                if args.max_attempts > 0 and total_attempts >= args.max_attempts:
                    print(f"\nMax attempts ({args.max_attempts:,}) reached. No match found.")
                    sys.exit(1)
                
                # Progress update
                if not args.quiet:
                    elapsed = time.time() - start_time
                    rate = total_attempts / elapsed if elapsed > 0 else 0
                    print(f"\rAttempts: {total_attempts:,} | Rate: {rate:,.0f}/sec | "
                          f"Time: {elapsed:.1f}s", end="", flush=True)
    
    except KeyboardInterrupt:
        print("\n\nSearch interrupted by user.")
        sys.exit(1)
    
    # Found a match!
    elapsed = time.time() - start_time
    print(f"\n\n{'='*60}")
    print("✓ SUCCESS! Matching pool ID found!")
    print(f"{'='*60}")
    print(f"Pool ID:      {result.pool_id_bech32}")
    print(f"Attempts:     {total_attempts:,}")
    print(f"Time:         {elapsed:.2f} seconds")
    print(f"Rate:         {total_attempts/elapsed:,.0f} keys/second")
    
    # Save keys
    output_dir = Path(args.output)
    save_keys(result, output_dir)
    
    print(f"\n{'='*60}")
    print("⚠️  SECURITY REMINDER:")
    print("  - Keep cold.skey PRIVATE and SECURE")
    print("  - Never share your private key")
    print("  - Create secure backups of your keys")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
