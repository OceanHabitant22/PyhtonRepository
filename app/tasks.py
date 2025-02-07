import schedule
import time
from app.rsa_keys import generate_rsa_keys
from app.models import Key
from app.myextensions import db

def regenerate_keys():
    all_keys = Key.query.all()
    for key_entry in all_keys:
        # Генерация новых ключей
        private_key, public_key = generate_rsa_keys()
        key_entry.private_key = private_key
        key_entry.public_key = public_key

    db.session.commit()
    print("Keys regenerated for all users!")

# Планируем задачу раз в 24 часа
schedule.every(24).hours.do(regenerate_keys)

while True:
    schedule.run_pending()
    time.sleep(1)
