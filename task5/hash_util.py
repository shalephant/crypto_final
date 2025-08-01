import hashlib
import json
import sys
import os

def compute_hashes(filename):
    """Compute SHA-256, SHA-1, and MD5 hashes."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(filename, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest()
    }

def save_hashes(filename, hash_file="hashes.json"):
    hashes = compute_hashes(filename)
    with open(hash_file, "w") as f:
        json.dump(hashes, f, indent=4)
    print(f"Hashes saved to {hash_file}")

def check_integrity(filename, hash_file="hashes.json"):
    if not os.path.exists(hash_file):
        print("Hash file not found!")
        return False

    with open(hash_file, "r") as f:
        original = json.load(f)

    current = compute_hashes(filename)

    if (current["sha256"] == original["sha256"] and
        current["sha1"] == original["sha1"] and
        current["md5"] == original["md5"]):
        print("✅ Integrity check PASSED")
        return True
    else:
        print("❌ Integrity check FAILED")
        print("Changes detected in the file!")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python hash_util.py [save|check] <filename>")
        sys.exit(1)

    action = sys.argv[1]
    filename = sys.argv[2]

    if action == "save":
        save_hashes(filename)
    elif action == "check":
        check_integrity(filename)
    else:
        print("Action must be 'save' or 'check'")
