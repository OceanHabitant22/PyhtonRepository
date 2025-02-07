import schedule
import time
from app import create_app, rotate_keys

def periodic_key_rotation():
    app = create_app()
    with app.app_context():
        rotate_keys(app)

# Schedule key rotation every 24 hours
schedule.every(24).hours.do(periodic_key_rotation)

if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(1)
