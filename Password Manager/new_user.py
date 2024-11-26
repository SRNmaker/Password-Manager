import os
from dataBase import Database

def create_database_file(name_of_file:str):
    h = os.getcwd()
    hr = fr"{h}"

    full_file_name = fr"{hr}\{name_of_file}.db"
    with open(f"{name_of_file}.db", "wb") as file:
        file.close()

    return full_file_name

def signUp(raw_master_password):
    # intialize database
    db_path = create_database_file("userdata")

    global db
    db = Database(db_path=db_path)
    db.connect()
    db.create_tables()

    db.sign_up(raw_master_password=raw_master_password)
    return db.get_user_id()
