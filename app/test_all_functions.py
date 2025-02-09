import unittest

class TestProjectFunctions(unittest.TestCase):
    def test_decentralized_storage(self):
        data = b"Sample Data for Storage"
        distributed_nodes = ["node1/", "node2/", "node3/"]
    
        # Разделение данных между узлами
        for i, node in enumerate(distributed_nodes):
            with open(f"{node}part_{i}.dat", "wb") as file:
                file.write(data[i::len(distributed_nodes)])
    
        # Проверка доступности данных с каждого узла
        collected_data = b"".join([
            open(f"{node}part_{i}.dat", "rb").read()
            for i, node in enumerate(distributed_nodes)
    ])
    
        assert collected_data == data, "Данные не совпадают!"
        pass

    def test_key_rotation(self):
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import serialization, hashes
        import time

        # Генерация ключей RSA
        def generate_keys():
         private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
         public_key = private_key.public_key()
         return public_key, private_key
        
        # Зашифрование и расшифрование
        def encrypt_decrypt_test(data: str, public_key, private_key) -> str:
         # Преобразуем данные в байты
         data_bytes = data.encode('utf-8')
         encrypted_data = public_key.encrypt(
             data_bytes,
             padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None
             )
         )
         decrypted_data = private_key.decrypt(
             encrypted_data,
             padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None
             )
         )
         return decrypted_data.decode('utf-8')
        
        # Тестирование смены ключа
        def test_key_rotation():
            data = "Secret message"

            # Генерация первого ключа
            public_key1, private_key1 = generate_keys()
            result1 = encrypt_decrypt_test(data, public_key1, private_key1)
            assert result1 == data, "Данные не совпадают после первого шифрования!"

            # Ожидание или принудительная смена ключа
            time.sleep(1)  # Для теста – ожидание 1 секунда, на практике 24 часа
            public_key2, private_key2 = generate_keys()
            result2 = encrypt_decrypt_test(data, public_key2, private_key2)

            assert result2 == data, "Данные не совпадают после смены ключа!"
            print("Test key rotation passed.")

        if __name__ == '__main__':
         test_key_rotation()

        pass

if __name__ == "__main__":
    unittest.main()
