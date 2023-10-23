import subprocess
import re

def decode(Pass):

    # Command to run gspassenc.exe
    command = f"gspassenc.exe d {Pass}"

    # Run the command and capture the output
    output = subprocess.check_output(command, shell=True, text=True)

    # Define a regular expression pattern to extract the decrypted password
    pattern = r"decrypted password: (.*)"

    # Search for the pattern in the output
    match = re.search(pattern, output)

    # Check if a match was found
    if match:
        decrypted_password = match.group(1)
        print(decrypted_password)
    else:
        print("Decrypted password not found in the output.")
    return decrypted_password
