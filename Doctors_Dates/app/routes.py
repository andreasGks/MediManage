from flask  import Blueprint, render_template, request, session,render_template,redirect,url_for,session,flash
from pymongo import MongoClient
from .models import Doctor 
from bson.objectid import ObjectId
import os
from .models import Doctor,Patient

from werkzeug.security import generate_password_hash, check_password_hash

main = Blueprint('main', __name__)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "@dm1n"

mongo_host = os.getenv('MONGO_HOST', 'localhost')
mongo_port = int(os.getenv('MONGO_PORT', 27017))
client = MongoClient(f'mongodb://{mongo_host}:{mongo_port}/')
db = client['HospitalDB']  # Replace with your MongoDB database name



patients_collection = db['Patients']
doctors_collection = db['Doctors']
settings_collection = db['Settings']
appointments_collection = db['Appointments']


# # Retrieve or set the secret key
secret_key_document = doctors_collection.find_one({'key_name': 'flask_secret_key'})
if not secret_key_document:
    secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')  # Use env var or default
    settings_collection.insert_one({'key_name': 'flask_secret_key', 'value': secret_key})
else:
    secret_key = secret_key_document['value']





# Define some sample doctors
doctors = [
    Doctor('John', 'Doe', 'john.doe@example.com', 'john_doe', 'password1', 100, 'Cardiology'),
    Doctor('Jane', 'Smith', 'jane.smith@example.com', 'jane_smith', 'password2', 150, 'Dermatology')
]




                            ######  BASE  ######





@main.route('/')
def index():
    return render_template('base.html')









                                    ######  ADMIN  ######
                                    ######  ADMIN  ######










# Hardcoded administrator credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = '@dm1n'

# ADMIN BASE
@main.route('/admin/admin_base')
def admin_base():
    # Authentication check
    if not session.get('logged_in'):
        return redirect(url_for('main.login'))

    return render_template('admin/admin_base.html')


#LOGIN_ADMIN
@main.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('main.admin_base'))
        else:
            return render_template('admin/login.html', error=True)

    return render_template('admin/login.html', error=False)

# ADMIN LOGOUT
@main.route('/admin/logout')
def logout():
    print(f"Session before logout: {session}")
    session.pop('logged_in', None)
    print(f"Session after logout: {session}")
    return redirect(url_for('main.login'))



# CREATE DOCTOR
@main.route('/admin/create_doctor', methods=['GET', 'POST'])
def create_doctor():
    if not session.get('logged_in'):
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        # Fetch form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        appointment_cost = request.form.get('appointment_cost')
        specialization = request.form.get('specialization')

        # Validate specialization
        valid_specializations = ['Ακτινολόγος', 'Αιματολόγος', 'Αλλεργιολόγος', 'Παθολόγος', 'Καρδιολόγος']
        if specialization not in valid_specializations:
            flash('Invalid specialization selected.')
            return redirect(url_for('main.create_doctor'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Insert into database
        doctor = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'username': username,
            'password': hashed_password,
            'appointment_cost': appointment_cost,
            'specialization': specialization
        }
        doctors_collection.insert_one(doctor)

        flash('Doctor created successfully!', 'success')
        return redirect(url_for('main.create_doctor'))

    return render_template('admin/create_doctor.html')






# CHANGE DOCTOR PASSWORD
@main.route('/admin/change_doctor_password', methods=['GET', 'POST'])
def change_doctor_password():
    if not session.get('logged_in'):
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        doctor_username = request.form.get('doctor_username')
        new_password = request.form.get('new_password')

        # Update the doctor's password in the database
        result = doctors_collection.update_one(
            {'username': doctor_username},
            {'$set': {'password': generate_password_hash(new_password, method='pbkdf2:sha256')}}
        )

        if result.modified_count > 0:
            flash('Password updated successfully for doctor: {}'.format(doctor_username), 'success')
        else:
            flash('Doctor with username: {} not found or password unchanged'.format(doctor_username), 'error')

        # Redirect to the same page to show the result and clear the form
        return redirect(url_for('main.change_doctor_password'))

    return render_template('admin/change_doctor_password.html')






# DELETE DOCTOR
@main.route('/admin/delete_doctor', methods=['GET', 'POST'])
def delete_doctor():
    if not session.get('logged_in'):
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        doctor_username = request.form.get('doctor_username')

        if doctor_username:
            doctor = doctors_collection.find_one({'username': doctor_username})

            if doctor:
                # Delete the doctor's appointments
                appointments_result = appointments_collection.delete_many({'doctor_username': doctor_username})
                print(f"Appointments deleted count: {appointments_result.deleted_count}")

                # Delete the doctor from the database
                doctor_result = doctors_collection.delete_one({'username': doctor_username})
                print(f"Doctor deleted count: {doctor_result.deleted_count}")

                if doctor_result.deleted_count > 0:
                    flash(f'Doctor {doctor_username} and their appointments deleted successfully!', 'success')
                else:
                    flash(f'Error deleting doctor with username: {doctor_username}', 'error')
            else:
                flash(f'Doctor with username: {doctor_username} not found', 'error')
        else:
            flash('Doctor username not provided', 'error')

        return redirect(url_for('main.delete_doctor'))

    return render_template('admin/delete_doctor.html')





# DELETE PATIENT
@main.route('/admin/delete_patient')
def delete_patient():
    if not session.get('logged_in'):
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        patient_username = request.form.get('patient_username')

        # Delete the patient's appointments
        appointments_result = appointments_collection.delete_many({'patient_username': patient_username})

        # Delete the patient from the database
        patient_result = patients_collection.delete_one({'username': patient_username})

        if patient_result.deleted_count > 0:
            flash('Patient and their appointments deleted successfully: {}'.format(patient_username))
        else:
            flash('Patient with username: {} not found'.format(patient_username))

        return redirect(url_for('main.admin_base'))

    return render_template('admin/delete_patient.html')














                        #######  DOCTOR  #######
                        #######  DOCTOR  #######
                        #######  DOCTOR  #######
                        #######  DOCTOR  #######
















# DOCTOR BASE
@main.route('/doctor/doctor_base')
def doctor_base():
    if not session.get('doctor_logged_in'):
        return redirect(url_for('main.login_doctor'))
    return render_template('doctor/doctor_base.html')




# DOCTOR LOGIN
@main.route('/doctor/login_doctor', methods=['GET', 'POST'])
def login_doctor():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username exists and passwords match
        for doctor in doctors:
            if doctor.username == username and doctor.check_password(password):
                session['doctor_logged_in'] = True
                session['doctor_username'] = username
                return redirect(url_for('main.doctor_base'))

        # If credentials are invalid, show an error message or redirect back to login page
        return render_template('doctor/doctor_login.html', error='Invalid credentials')

    # For GET requests, render the login form
    return render_template('doctor/doctor_login.html')

# DOCTOR LOGOUT
@main.route('/doctor/logout')
def logout_doctor():
    session.pop('doctor_logged_in', None)
    session.pop('doctor_username', None)
    return redirect(url_for('main.login_doctor'))









@main.route('/doctor/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('doctor_logged_in'):
        return redirect(url_for('main.login_doctor'))

    if request.method == 'POST':
        doctor_username = session['doctor_username']
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        # Validate input
        if not (current_password and new_password):
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('main.change_password'))

        # Retrieve doctor from database
        doctor = Doctor.find_by_username(doctor_username)

        if not doctor:
            flash('Doctor not found.', 'error')
            return redirect(url_for('main.change_password'))

        # Verify current password
        if not check_password_hash(doctor['password'], current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('main.change_password'))

        # Update password
        result = Doctor.change_password(doctor_username, new_password)

        if result:
            flash('Password changed successfully.', 'success')
            return redirect(url_for('main.change_password', success=True))
        else:
            flash('Failed to change password.', 'error')
            return redirect(url_for('main.change_password'))

    return render_template('doctor/change_password.html')









# # DOCTOR CHANGE PASSWORD
# @main.route('/doctor/change_password', methods=['GET', 'POST'])
# def change_password():
#     if not session.get('doctor_logged_in'):
#         return redirect(url_for('main.login_doctor'))

#     if request.method == 'POST':
#         current_password = request.form['current_password']
#         new_password = request.form['new_password']
#         confirm_password = request.form['confirm_password']

#         doctor_username = session['doctor_username']
#         doctor = Doctor.find_by_username(doctor_username)

#         if not doctor:
#             flash('Doctor not found.', 'error')
#             return redirect(url_for('main.change_password'))

#         if doctor['password'] != current_password:
#             flash('Current password is incorrect.', 'error')
#             return redirect(url_for('main.change_password'))

#         if new_password != confirm_password:
#             flash('New passwords do not match.', 'error')
#             return redirect(url_for('main.change_password'))

#         # Update the doctor's password
#         Doctor.change_password(doctor_username, new_password)
#         flash('Password changed successfully.', 'success')
#         return redirect(url_for('main.doctor_base'))

#     return render_template('doctor/change_password.html')













@main.route('/doctor/change_appointment_cost', methods=['GET', 'POST'])
def change_appointment_cost():
    if request.method == 'POST':
        doctor_username = request.form.get('doctor_username')
        new_cost = request.form.get('new_cost')

        # Validate the new cost
        try:
            new_cost = float(new_cost)
            if new_cost < 0:
                raise ValueError("Cost cannot be negative")
        except ValueError as e:
            flash('Invalid cost value.', 'error')
            return redirect(url_for('main.change_appointment_cost'))

        # Check if the doctor exists
        doctor = Doctor.find_by_username(doctor_username)
        if not doctor:
            flash(f"Doctor with username '{doctor_username}' does not exist.", 'error')
            return redirect(url_for('main.change_appointment_cost'))

        # Update the appointment cost
        result = Doctor.update_appointment_cost(doctor_username, new_cost)
        if result > 0:
            flash('Appointment cost updated successfully.', 'success')
        else:
            flash('Failed to update appointment cost.', 'error')

        return redirect(url_for('main.doctor_base'))

    # For GET requests or when there's an error, render the form
    return render_template('doctor/change_appointment_cost.html')



















# # CHANGE APPOINTMENT COST
# @main.route('/doctor/change_appointment_cost', methods=['GET', 'POST'])
# def change_appointment_cost():
#     if request.method == 'POST':
#         new_cost = request.form.get('new_cost')
        
#         # Ensure the user is logged in and get the doctor's username from the session
#         if 'doctor_username' not in session:
#             flash('You need to log in first.', 'error')
#             return redirect(url_for('main.login_doctor'))

#         # Validate the new cost
#         try:
#             new_cost = float(new_cost)
#             if new_cost < 0:
#                 raise ValueError("Cost cannot be negative")
#         except ValueError as e:
#             flash('Invalid cost value.', 'error')
#             return redirect(url_for('main.change_appointment_cost'))

#         # Get the doctor's username from the session
#         doctor_username = session.get('doctor_username')

#         # Update the doctor's appointment cost in the database
#         Doctor.update_appointment_cost(doctor_username, new_cost)
        
#         flash('Appointment cost updated successfully.', 'success')
#         return redirect(url_for('main.doctor_base'))

#     return render_template('doctor/change_appointment_cost.html')




# VIEW FUTURE APPOINTMENT

@main.route('/doctor/future_appointments')
def view_future_appointments():
    if not session.get('doctor_logged_in'):
        return redirect(url_for('main.login_doctor'))

    doctor_username = session.get('doctor_username')
    future_appointments = list(Doctor.get_future_appointments(doctor_username))

    return render_template('doctor/future_appointments.html', appointments=future_appointments)










                                ######PATIENT######
                                ######PATIENT######










@main.route('/patient/patient_options')
def patient_options():
    return render_template('/patient/patient_options.html')






@main.route('/patient/register_patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        amka = request.form.get('amka')
        birth_date = request.form.get('birth_date')
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate form data (add more validation as per your requirements)
        if not all([first_name, last_name, email, amka, birth_date, username, password]):
            flash('All fields are required.', 'error')
            return redirect(url_for('main.register_patient'))

        # Check if username already exists
        if patients_collection.find_one({'username': username}):
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('main.register_patient'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Insert into database
        new_patient = {
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'amka': amka,
            'birth_date': birth_date,
            'username': username,
            'password': hashed_password
        }
        patients_collection.insert_one(new_patient)

        flash('Registration successful. You can now login.', 'success')
    
        
        return redirect(url_for('main.login_patient'))

    return render_template('patient/patient_register.html')







# LOGIN PATIENT
@main.route('/patient/login_patient', methods=['GET', 'POST'])
def login_patient():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate credentials
        patient = Patient.find_by_username(username)

        if patient and check_password_hash(patient['password'], password):
            session['patient_logged_in'] = True
            session['patient_username'] = username
            return redirect(url_for('main.patient_base'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('patient/patient_login.html')








# # LOGIN PATIENT
# @main.route('/patient/login_patient', methods=['GET', 'POST'])
# def login_patient():
#     if request.method == 'POST':
#         # Get form data
#         username = request.form['username']
#         password = request.form['password']

#         # Validate credentials
#         patient = Patient()
#         login_successful, message = patient.login(username, password)

#         if login_successful:
#             session['patient_logged_in'] = True
#             session['patient_username'] = username
#             flash(message, 'success')

#             return redirect(url_for('main.patient_base'))
#         else:
#             flash(message, 'error')

#     return render_template('patient/patient_login.html')




# PATIENT BASE
@main.route('/patient/patient_base')
def patient_base():
    if not session.get('patient_logged_in'):
        flash('You must be logged in to access the patient base.', 'error')
        return redirect(url_for('main.login_patient'))

    patient_username = session['patient_username']
    patient = Patient.find_by_username(patient_username)

    return render_template('patient_base.html', patient=patient)




# # PATIENT BASE
# @main.route('/patient/patient_base')
# def patient_base():
#     if not session.get('patient_logged_in'):
#         return redirect(url_for('main.login_patient'))

#     patient_username = session['patient_username']
#     patient = Patient.find_by_username(patient_username)

#     return render_template('patient_base.html', patient=patient)

# PATIENT LOGOUT
@main.route('/patient/logout')
def logout_patient():
    session.pop('patient_logged_in', None)
    session.pop('patient_username', None)
    return redirect(url_for('main.login_patient'))



