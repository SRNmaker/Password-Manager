from dataBase import Database
import new_user

def signUp(raw_master_password):
    # intialize database
    db_path = new_user.create_database_file("userdata")

    global db
    db = Database(db_path=db_path)
    db.connect()
    db.create_tables()

    db.sign_up(raw_master_password=raw_master_password)
    return db.get_user_id()