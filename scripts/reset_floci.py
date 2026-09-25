#!/usr/bin/env python3
"""
Reset Floci environment for CSPM integration testing.

This script provides convenient methods to reset the Floci environment.
It can either:
1. Restart the Docker container (cleanest approach)
2. Clean up seeded resources via API calls

Usage:
    python scripts/reset_floci.py
    python scripts/reset_floci.py --method docker
    python scripts/reset_floci.py --method api
"""

import argparse
import subprocess
import sys
import time


def reset_docker():
    """Reset Floci by restarting the Docker container."""
    print("Resetting Floci via Docker restart...")
    
    try:
        # Stop and remove container
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.floci.yml", "down"],
            check=True,
            capture_output=True,
            text=True
        )
        print("  Stopped Floci container")
        
        # Start fresh
        subprocess.run(
            ["docker", "compose", "-f", "docker-compose.floci.yml", "up", "-d"],
            check=True,
            capture_output=True,
            text=True
        )
        print("  Started Floci container")
        
        # Wait for health check
        print("  Waiting for Floci to be ready...")
        time.sleep(10)
        
        print("Floci reset complete!")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Error resetting Docker: {e}")
        if e.stderr:
            print(f"  stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print("Error: docker compose not found. Is Docker installed?")
        return False


def reset_via_api():
    """Reset Floci by cleaning up resources via API calls."""
    print("Resetting Floci via API cleanup...")
    
    try:
        # Import and run the cleanup from seed script
        sys.path.insert(0, "scripts")
        from seed_floci import cleanup_resources, FLOCI_ENDPOINT
        
        cleanup_resources()
        print("API cleanup complete!")
        return True
        
    except ImportError:
        print("Error: Could not import seed_floci module")
        return False
    except Exception as e:
        print(f"Error during API cleanup: {e}")
        return False


def check_floci_health(endpoint: str = "http://localhost:4566") -> bool:
    """Check if Floci is healthy."""
    try:
        import requests
        response = requests.get(f"{endpoint}/_localstack/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Reset Floci environment for CSPM integration testing"
    )
    parser.add_argument(
        "--method",
        choices=["docker", "api"],
        default="docker",
        help="Reset method: docker (restart container) or api (cleanup resources)"
    )
    parser.add_argument(
        "--check-health",
        action="store_true",
        help="Only check Floci health status"
    )
    
    args = parser.parse_args()
    
    if args.check_health:
        if check_floci_health():
            print("Floci is healthy and ready!")
            sys.exit(0)
        else:
            print("Floci is not responding")
            sys.exit(1)
    
    if args.method == "docker":
        success = reset_docker()
    else:
        success = reset_via_api()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()