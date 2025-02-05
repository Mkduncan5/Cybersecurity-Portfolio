import itertools

def brute_force_attack(target_password, max_length=4):
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    
    for length in range(1, max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            attempt = ''.join(attempt)
            print(f"Trying: {attempt}")
            if attempt == target_password:
                print(f"Password found: {attempt}")
                return attempt
    print("Password not found")
    return None

# Example usage
target_password = "abc"
brute_force_attack(target_password)
