import datetime
from pymongo import MongoClient

class MongoDB:
    client = MongoClient("mongodb://mongo:27017/")
    db = client.HospitalDB

class Doctor:
    collection = MongoDB.db.doctors


    def __init__(self, first_name, last_name, email, username, password, appointment_cost, specialization):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.username = username
        self.password = password
        self.appointment_cost = appointment_cost
        self.specialization = specialization

    def login(self, username, password):
        # Validate credentials (you'll need to implement this logic)
        if self.username == username and self.password == password:
            return True
        else:
            return False

    def save(self):
        Doctor.collection.insert_one({
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'username': self.username,
            'password': self.password,
            'appointment_cost': self.appointment_cost,
            'specialization': self.specialization
        })


    def check_password(self, password):
        return self.password == password

    @staticmethod
    def get_future_appointments(doctor_username):
        current_datetime = datetime.utcnow()
        return MongoDB.db.appointments.find({
            'doctor_username': doctor_username,
            'appointment_date': {'$gte': current_datetime}
        })


    @staticmethod
    def change_password(username, new_password):
        Doctor.collection.update_one({'username': username}, {'$set': {'password': new_password}})

    @staticmethod
    def delete(username):
        Doctor.collection.delete_one({'username': username})

    @staticmethod
    def find_by_username(username):
        return Doctor.collection.find_one({'username': username})

    @staticmethod
    def get_appointments(username):
        return MongoDB.db.appointments.find({'doctor_username': username})

    @staticmethod
    def update_appointment_cost(username, new_cost):
        Doctor.collection.update_one({'username': username}, {'$set': {'appointment_cost': new_cost}})


class Patient:
    collection = MongoDB.db.patients

    def __init__(self, first_name, last_name, email, amka, birth_date, username, password):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.amka = amka
        self.birth_date = birth_date  # Assuming birth_date is a datetime object
        self.username = username
        self.password = password
        self.logged_in = False

    def register(self):
        if not self.find_by_username(self.username):
            if not self.find_by_email(self.email):
                Patient.collection.insert_one({
                    'first_name': self.first_name,
                    'last_name': self.last_name,
                    'email': self.email,
                    'amka': self.amka,
                    'birth_date': self.birth_date,
                    'username': self.username,
                    'password': self.password
                })
                return True, "Registration successful"
            else:
                return False, "Email already exists"
        else:
            return False, "Username already exists"

    def login(self, username, password):
        patient = self.find_by_username(username)
        if patient and patient['password'] == password:
            self.logged_in = True
            return True, "Login successful"
        else:
            return False, "Invalid username or password"

    def logout(self):
        self.logged_in = False

    @staticmethod
    def find_by_username(username):
        return Patient.collection.find_one({'username': username})

    @staticmethod
    def find_by_email(email):
        return Patient.collection.find_one({'email': email})

    def make_appointment(self, appointment_date, doctor_specialization, reason, appointment_time):
        if not self.logged_in:
            return False, "Patient must be logged in to make an appointment"

        # Additional checks and logic for appointment scheduling would go here
        # For simplicity, we're not implementing the entire scheduling logic

        # Example logic for scheduling appointment
        appointment_datetime = datetime.combine(appointment_date, appointment_time)
        appointment_details = {
            'patient_username': self.username,
            'appointment_date': appointment_datetime,
            'doctor_specialization': doctor_specialization,
            'reason': reason,
            # Add more fields as required
        }
        # Example of saving appointment to a separate collection
        MongoDB.db.appointments.insert_one(appointment_details)

        return True, "Appointment scheduled successfully"
