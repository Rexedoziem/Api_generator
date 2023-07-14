import random
import hashlib
import base64
import mysql.connector
from datetime import datetime, timedelta


MYSQL_HOST = "localhost"
MYSQL_USER = "your_username"
MYSQL_PASSWORD = "your_password"
MYSQL_DATABASE = "apikeys"
APIKEY_POOL_SIZE = 10
APIKEY_EXPIRATION_DAYS = 30


class APIKeyDatabase(object):
    def __init__(self):
        self.connection = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )
        self.cursor = self.connection.cursor()

        self.cursor.execute("DROP TABLE IF EXISTS keys")
        self.cursor.execute("CREATE TABLE keys (key VARCHAR(255), used BOOLEAN, expiration_date DATETIME)")

    def insert(self, key):
        sql = "INSERT INTO keys (key, used, expiration_date) VALUES (%s, %s, %s)"
        values = (key, False, datetime.now() + timedelta(days=APIKEY_EXPIRATION_DAYS))
        self.cursor.execute(sql, values)
        self.connection.commit()

    def get_unused(self):
        sql = "SELECT * FROM keys WHERE used = False"
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def mark_as_used(self, api_key):
        sql = "UPDATE keys SET used = True WHERE key = %s"
        values = (api_key['key'],)
        self.cursor.execute(sql, values)
        self.connection.commit()

    def validate(self, api_key):
        sql = "SELECT * FROM keys WHERE key = %s"
        values = (api_key,)
        self.cursor.execute(sql, values)
        return self.cursor.fetchone()

    def revoke(self, api_key):
        sql = "DELETE FROM keys WHERE key = %s"
        values = (api_key,)
        self.cursor.execute(sql, values)
        self.connection.commit()

    def check_expiration(self, api_key):
        sql = "SELECT expiration_date FROM keys WHERE key = %s"
        values = (api_key,)
        self.cursor.execute(sql, values)
        expiration_date = self.cursor.fetchone()[0]
        return expiration_date < datetime.now()


class APIKeyGenerator(object):
    def __init__(self):
        self.api_key_db = APIKeyDatabase()

    def create_pool(self, size):
        for _ in range(size):
            key = self.generate()
            self.api_key_db.insert(key)

    def refill_pool(self, size):
        unused_keys = self.api_key_db.get_unused()
        current_pool_size = len(unused_keys)
        if current_pool_size < size:
            for _ in range(size - current_pool_size):
                key = self.generate()
                self.api_key_db.insert(key)

    def get_key(self):
        keys = self.api_key_db.get_unused()
        for key in keys:
            self.api_key_db.mark_as_used(key)
            return key[0]

    def generate(self):
        # generate 256-bit number
        num_256bit = str(random.getrandbits(256))

        # cryptographically hash this number using SHA 256
        # the result is base64 encoded
        hashed_num = hashlib.sha256(num_256bit.encode()).digest()

        # select random character pair
        char_pair = random.choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])

        # encode in base64
        b64encoded_str = base64.b64encode(hashed_num, char_pair.encode())

        # get api key
        api_key = b64encoded_str.rstrip(b'=')
        return api_key

    def get_keys(self):
        return self.api_key_db.get_unused()


def main():
    api_key_gen = APIKeyGenerator()
    api_key_gen.create_pool(APIKEY_POOL_SIZE)

    for _ in range(APIKEY_POOL_SIZE):
        print(api_key_gen.get_key())

    for key in api_key_gen.get_keys():
        print(key[0])

    # Validate an API key
    api_key = "your_api_key_here"
    if api_key_gen.api_key_db.validate(api_key):
        print("API Key is valid.")
    else:
        print("API Key is not valid.")

    # Check API key expiration
    if api_key_gen.api_key_db.check_expiration(api_key):
        print("API Key has expired.")
    else:
        print("API Key is still valid.")

    # Refill the key pool
    api_key_gen.refill_pool(20)
    for key in api_key_gen.get_keys():
        print(key[0])


if __name__ == '__main__':
    main()