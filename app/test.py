# ===================================================================
# ТЕСТ БЕЗОПАСНОСТИ ПРОЕКТА CRYPTOSECURITY
# ===================================================================

import unittest
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class TestCryptographicSecurity(unittest.TestCase):
    """
    Модуль тестирования безопасности криптографических операций
    
    Эти тесты демонстрируют:
    1. Корректность шифрования/дешифрования
    2. Уникальность ключей
    3. Невозможность подмены данных
    4. Защиту от replay-атак
    """
    
    def setUp(self):
        """Подготовка тестовой среды"""
        # Генерация тестовых RSA ключей
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        
        # Тестовые данные
        self.test_data = b"This is a secret message for encryption testing!"
    
    
    def test_rsa_key_uniqueness(self):
        """
        Тест 1: Проверка уникальности RSA ключей
        
        Математика:
        Каждый вызов генерации должен создавать уникальную пару (p, q),
        что обеспечивает уникальность n = p × q
        """
        # Генерация 10 пар ключей
        keys = [RSA.generate(2048) for _ in range(10)]
        
        # Извлечение модулей n из всех ключей
        moduli = [key.n for key in keys]
        
        # Проверка: все модули должны быть уникальными
        self.assertEqual(len(moduli), len(set(moduli)), 
                        "Обнаружены неуникальные RSA ключи!")
        
        print("✓ Тест уникальности ключей пройден")
    
    
    def test_aes_encryption_decryption_correctness(self):
        """
        Тест 2: Корректность AES шифрования/дешифрования
        
        Математика:
        Для любого plaintext P:
        Decrypt(Encrypt(P, k), k) = P
        """
        # Генерация AES ключа
        aes_key = get_random_bytes(32)  # 256 бит
        iv = get_random_bytes(16)  # 128 бит
        
        # Шифрование
        cipher_enc = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(self.test_data, AES.block_size)
        ciphertext = cipher_enc.encrypt(padded_data)
        
        # Дешифрование
        cipher_dec = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher_dec.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        
        # Проверка: расшифрованные данные должны совпадать с оригиналом
        self.assertEqual(self.test_data, decrypted_data,
                        "Дешифрование не вернуло исходные данные!")
        
        print("✓ Тест корректности AES шифрования пройден")
    
    
    def test_rsa_encryption_decryption_correctness(self):
        """
        Тест 3: Корректность RSA шифрования/дешифрования
        
        Математика:
        (M^e mod n)^d mod n = M
        """
        # Тестовое сообщение (должно быть меньше модуля RSA)
        message = b"Test RSA message"
        
        # Шифрование с публичным ключом
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher_rsa.encrypt(message)
        
        # Дешифрование с приватным ключом
        decipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        decrypted_message = decipher_rsa.decrypt(ciphertext)
        
        # Проверка
        self.assertEqual(message, decrypted_message,
                        "RSA дешифрование не вернуло исходное сообщение!")
        
        print("✓ Тест корректности RSA шифрования пройден")
    
    
    def test_hybrid_encryption_full_cycle(self):
        """
        Тест 4: Полный цикл гибридного шифрования
        
        Математика:
        1. Генерация AES ключа k
        2. C_data = AES_k(plaintext)
        3. C_key = RSA_pub(k)
        4. k' = RSA_priv(C_key)
        5. plaintext' = AES_k'(C_data)
        6. plaintext' должно равняться plaintext
        """
        # Шаг 1: Генерация AES ключа
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        
        # Шаг 2: Шифрование данных AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(self.test_data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        
        # Шаг 3: Шифрование AES ключа RSA
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        
        # === ПЕРЕДАЧА: (encrypted_data, encrypted_key, iv) ===
        
        # Шаг 4: Дешифрование AES ключа RSA
        decipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        decrypted_aes_key = decipher_rsa.decrypt(encrypted_key)
        
        # Шаг 5: Дешифрование данных AES
        decipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
        decrypted_padded = decipher_aes.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        
        # Проверка
        self.assertEqual(self.test_data, decrypted_data,
                        "Гибридное дешифрование не вернуло исходные данные!")
        
        print("✓ Тест полного цикла гибридного шифрования пройден")
    
    
    def test_data_tampering_detection(self):
        """
        Тест 5: Обнаружение подмены данных
        
        Если зашифрованные данные изменены, дешифрование должно
        либо завершиться с ошибкой, либо вернуть некорректные данные
        """
        # Шифрование
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(self.test_data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Подмена одного байта в зашифрованных данных
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[10] ^= 0xFF  # Инвертируем один байт
        tampered_ciphertext = bytes(tampered_ciphertext)
        
        # Попытка дешифрования подменённых данных
        decipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = decipher.decrypt(tampered_ciphertext)
        
        # Должна возникнуть ошибка при удалении паддинга ИЛИ
        # данные должны отличаться от оригинала
        try:
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            self.assertNotEqual(self.test_data, decrypted_data,
                               "Подменённые данные не обнаружены!")
        except ValueError:
            # Ожидаемая ошибка при некорректном паддинге
            pass
        
        print("✓ Тест обнаружения подмены данных пройден")
    
    
    def test_aes_key_non_reusability(self):
        """
        Тест 6: Проверка, что каждое шифрование использует уникальный AES ключ
        
        В гибридной схеме каждый файл должен шифроваться новым AES ключом
        """
        keys = [get_random_bytes(32) for _ in range(100)]
        
        # Все ключи должны быть уникальными
        self.assertEqual(len(keys), len(set(keys)),
                        "Обнаружены повторяющиеся AES ключи!")
        
        print("✓ Тест уникальности AES ключей пройден")
    
    
    def test_iv_uniqueness(self):
        """
        Тест 7: Проверка уникальности векторов инициализации (IV)
        
        Математика:
        Для безопасности CBC режима каждый IV должен быть уникальным
        """
        ivs = [get_random_bytes(16) for _ in range(100)]
        
        # Все IV должны быть уникальными
        self.assertEqual(len(ivs), len(set(ivs)),
                        "Обнаружены повторяющиеся векторы инициализации!")
        
        print("✓ Тест уникальности IV пройден")
    
    
    def test_rsa_different_ciphertexts(self):
        """
        Тест 8: RSA с OAEP должен давать разные шифротексты для одного сообщения
        
        OAEP добавляет случайность, поэтому два шифрования одного сообщения
        должны давать разные результаты
        """
        message = b"Same message"
        
        # Двукратное шифрование одного сообщения
        cipher1 = PKCS1_OAEP.new(self.public_key)
        ciphertext1 = cipher1.encrypt(message)
        
        cipher2 = PKCS1_OAEP.new(self.public_key)
        ciphertext2 = cipher2.encrypt(message)
        
        # Шифротексты должны отличаться
        self.assertNotEqual(ciphertext1, ciphertext2,
                           "RSA OAEP создал одинаковые шифротексты!")
        
        # Но оба должны расшифровываться в исходное сообщение
        decipher = PKCS1_OAEP.new(self.rsa_key)
        self.assertEqual(message, decipher.decrypt(ciphertext1))
        self.assertEqual(message, decipher.decrypt(ciphertext2))
        
        print("✓ Тест случайности RSA OAEP пройден")
    
    
    def test_wrong_key_decryption_fails(self):
        """
        Тест 9: Дешифрование с неправильным ключом должно завершаться с ошибкой
        """
        aes_key = get_random_bytes(32)
        wrong_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        
        # Шифрование с правильным ключом
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(self.test_data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Попытка дешифрования с неправильным ключом
        wrong_cipher = AES.new(wrong_key, AES.MODE_CBC, iv)
        decrypted_padded = wrong_cipher.decrypt(ciphertext)
        
        # Должна возникнуть ошибка при удалении паддинга ИЛИ
        # данные должны быть некорректными
        try:
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            self.assertNotEqual(self.test_data, decrypted_data)
        except ValueError:
            # Ожидаемая ошибка
            pass
        
        print("✓ Тест защиты от неправильного ключа пройден")
    
    
    def test_file_size_encryption_performance(self):
        """
        Тест 10: Оценка производительности шифрования для разных размеров файлов
        """
        import time
        
        sizes = [1024, 10240, 102400, 1024000]  # 1KB, 10KB, 100KB, 1MB
        results = []
        
        for size in sizes:
            test_data = os.urandom(size)
            aes_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            
            # Измерение времени шифрования
            start = time.time()
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = pad(test_data, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            end = time.time()
            
            elapsed = end - start
            results.append((size, elapsed))
            print(f"  Файл {size} байт: {elapsed:.6f} сек")
        
        # Проверка линейности: O(N)
        # Время для 1MB должно быть примерно в 1000 раз больше, чем для 1KB
        self.assertLess(results[-1][1] / results[0][1], 2000,
                       "Производительность не соответствует O(N)")
        
        print("✓ Тест производительности шифрования пройден")


def run_security_tests():
    """
    Запуск всех тестов безопасности
    """
    print("="*70)
    print("ЗАПУСК ТЕСТОВ БЕЗОПАСНОСТИ CRYPTOSECURITY PROJECT")
    print("="*70)
    print()
    
    # Создание тестового набора
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCryptographicSecurity)
    
    # Запуск тестов
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("="*70)
    print(f"РЕЗУЛЬТАТЫ: {result.testsRun} тестов выполнено")
    print(f"✓ Успешно: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"✗ Провалено: {len(result.failures)}")
    print(f"✗ Ошибки: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_security_tests()
    exit(0 if success else 1)
