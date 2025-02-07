from crypto import generate_rsa_keys

def create_rsa_keys_and_save(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    public_key, private_key = generate_rsa_keys()
    with open(private_key_path, "w") as priv_file:
        priv_file.write(private_key)
    with open(public_key_path, "w") as pub_file:
        pub_file.write(public_key)
    print("RSA keys generated and saved.")
    return public_key, private_key

if __name__ == "__main__":
    create_rsa_keys_and_save()
