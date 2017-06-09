#importing libraries
from flask import Flask, render_template, request, redirect, url_for, make_response, session #import all flask functions needed
from flask.ext.sqlalchemy import SQLAlchemy #import database
from flask_sslify import SSLify #import HTTPS:// enforcing
from flask_mail import Mail, Message #import mailing system
import hashlib #import encryption
import ast #import string to list evaluation
import csv #import csv file generator and reader
import datetime #import timestamp generator

#setting up website
app = Flask(__name__) #configure flask
app.secret_key = "ITSASECRET" #secret key for username session
sslify = SSLify(app) #include HTTPS:// enforcing
mail = Mail(app) #include mailing system

#setting up mail
app.config['MAIL_SERVER']='smtp.gmail.com' #use gmail
app.config['MAIL_PORT'] = 465 #mail port
app.config['MAIL_USERNAME'] = 'eventmanagementproj@gmail.com' #email
app.config['MAIL_PASSWORD'] = 'ITSASECRET' #password
app.config['MAIL_USE_TLS'] = False #security type
app.config['MAIL_USE_SSL'] = True #security type
mail = Mail(app) #include mailing system, we don't know why this has to be done twice

#setting up database
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format( #database host address
    username="EventManagement", #account username
    password="ITSASECRET", #account password
    hostname="EventManagement.mysql.pythonanywhere-services.com", #host address
    databasename="EventManagement$users", #table name
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI #configure URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299 #recycle connection
db = SQLAlchemy(app) #include database

#setting up database tables
class User(db.Model): #user accounts

    __tablename__ = "users" #user table

    id = db.Column(db.Integer, primary_key=True) #unique user ID
    username = db.Column(db.String(4096)) #unique username
    password = db.Column(db.String(4096)) #hashed password
    email= db.Column(db.String(4096)) #email
    confirmed = db.Column(db.String(4096)) #account status

class Event(db.Model): #events

    __tablename__ = "events" #events table

    id = db.Column(db.Integer, primary_key=True) #unique event ID
    name = db.Column(db.String(4096)) #uinque name
    user = db.Column(db.String(4096)) #owner
    description = db.Column(db.String(4096)) #description

class Form(db.Model): #forms

    __tablename__ = "forms" #forms table

    id = db.Column(db.Integer, primary_key=True) #unique form ID
    name = db.Column(db.String(4096)) #unique name
    user = db.Column(db.String(4096)) #owner
    event = db.Column(db.String(4096)) #owner
    description = db.Column(db.String(4096)) #description
    questions = db.Column(db.Text(4096)) #question data
    answers = db.Column(db.String(4096)) #answer csv file

#error handling
@app.errorhandler(400) #handle 400 error
def bad_request(e): #error handling function
    return render_template('400.html'), 400 #show error page

@app.errorhandler(401) #handle 401 error
def unauthorised(e): #error handling function
    return render_template('401.html'), 401 #show error page

@app.errorhandler(404) #handle 404 error
def page_not_found(e): #error handling function
    return render_template('404.html'), 404 #show error page

@app.errorhandler(405) #handle 405 error
def method_not_allowed(e): #error handling function
    return render_template('405.html'), 405 #show error page

@app.errorhandler(500) #handle 500 error
def internal_server_error(e): #error handling function
    return render_template('500.html'), 500 #show error page

def getUsername(): #function to get username as it is repeatedly used
    if "username" in session: #if user is logged in
        username = session['username'] #get username
    else: #if user is not logged in
        username = None #no username
    return username #give back username

def getHashed(text): #function to get hashed username/password as it is reapeatedly used
    salt = "ITSASECRET" #salt for password security
    hashed = text + salt #salting password
    hashed = hashlib.md5(hashed.encode()) #encrypting with md5 hash
    hashed = hashed.hexdigest() #converting to string
    return hashed #give hashed text back

#main website code
#home page for everybody
@app.route('/', methods=["GET"]) #default URL
def home(): #home page function
    username = getUsername() #get username
    return render_template("home.html", username=username, success=request.args.get("success"), info = "You can look around the website from here.") #load home page with information

#login page for existing users
@app.route('/login', methods=["GET","POST"]) #URL for login
def login(): #login function
    if request.method == "GET": #if user loads the page
        username = getUsername() #get username
        if username != None: #user is logged in
            return render_template("login.html", username=username, info="Log into another account here. You will be logged out of your current account.") #load login page with information
        else: #if not logged in
            return render_template("login.html",info = "Log in to the website here. Make sure you have an account!") #load login page with information
    elif request.method == "POST": #if user submits login form
        username = request.form["username"] #entered username
        password = request.form["password"] #entered password
        hashedPassword = getHashed(password) #get hashed version
        userDetails = User.query.filter_by(username=username).first() #check if user exists and get account information
        if userDetails is None: #no user found
            return render_template("login.html", error="Invalid username or password.", username=username) #return to same page with error message
        elif hashedPassword != userDetails.password: #wrong password
            return render_template("login.html", error="Invalid username or password.", username=username) #return to same page with error message
        elif userDetails.confirmed == "N": #user account not verified
            return render_template("login.html", error="Account not verified.", username=username) #return to same page with error message
        else: #user account exists, is verified, and password is correct
            session["username"] = username #set username session
            return redirect(url_for("home", success="You are now logged in!")) #redirect to homepage with success message

#allows user to request to reset their password if they lose it
@app.route("/account/forgot_password", methods=["GET", "POST"]) #URL to allow user to change password when they forget it
def forgotPassword(): #function to reset password
    if request.method=="GET": #user loads page
        username = getUsername() #get username
        if username != None: #logged in
            return render_template("forgot_password.html", username=username, info = "If you forgot your password, type in your username so we can send you a link to reset your password. But this is unlikely as you are currently logged in.")
        else: #not logged in
            return render_template("forgot_password.html", username=username, info = "If you forgot your password, type in your username so we can send you a link to reset your password.") #render page with info
    elif request.method == "POST": #user submits form
        username = request.form['username'] #get username from form
        user = User.query.filter_by(username=username).first() #get user
        email = user.email #get user email
        msg = Message('Password reset for Event Management Account ' + str(username), sender = 'eventmanagementproj@gmail.com', recipients = [email]) #prepare email to be sent to user
        msg.html = '<h1 style="text-align: center;">Hey ' + str(username) + "!</h1></br>" + "<h2 style='text-align: center;'>We have received your request to reset your password.</h2></br>" + '<h3 style="text-align: center;">Reset your password <a href=' + "https://eventmanagement.pythonanywhere.com/reset_password/" + getHashed(username) + ">here</a>!</h3>" + '</br><h3 style="text-align: center;">If this was not you, kindly ignore it.' '</br><h4 style="text-align: center;">If you have any queries you may send an email to us at eventmanagementproj@gmail.com!</h4>' #code for body of email
        mail.send(msg) #send message to user
        return redirect(url_for("home", success="An email has been sent to the email linked to that username. Please click on the link in the email to reset your password.")) #return to homepage with success message

#confirmation to reset password
@app.route("/reset_password/<userHash>", methods=["GET", "POST"]) #allows user to reset password when they forget it
def resetPassword(userHash): #reset password function
    if request.method == "GET": #user loads page
        return render_template("reset_password.html", info = "Please enter a new password for your account. ") #load reset password page
    elif request.method == "POST": #user submits form
        username = request.form["username"] #get username
        password = request.form["password"] #get password
        confirmPassword = request.form['confirmPassword'] #get confirm password
        if getHashed(username) == userHash: #if confirmation link matches with username provided
            hashedPassword = getHashed(password) #get hashed version
            user = User.query.filter_by(username=username).first() #get account with username
            if user is None: #account doesn't exist
                return render_template("reset_password.html", info = "Please enter a new password for your account.", error = "Invalid username or password.") #return with error
            elif password != confirmPassword: #passwords don't match
                return render_template("reset_password.html", info = "Please enter a new password for your account.", error="Invaalid username or password")
            else: #everything correct
                user.password = hashedPassword #change password
                db.session.commit() #save changes
                return redirect(url_for("home", success="Your password has been reset! Please proceed to login now.")) #go to homepage with message
        else: #username doesn't match
            return render_template("confirmation.html", error = "Invalid username or password.") #return with error

#allows user to get their username(s)
@app.route("/account/forgot_username", methods=["GET", "POST"]) #URL to allow user to recall list of username(s)
def forgotUsername(): #function to get username(s)
    if request.method=="GET": #user loads page
        username = getUsername() #get username
        if username != None: #user is logged in
            return render_template("forgot_username.html", username=username, info = "If you forgot your username, type in your email so we can send you a list of all your previous usernames. But this is unlikely as you are currently logged in.")
        else: #not logged in
            return render_template("forgot_username.html", username=username, info = "If you forgot your username, type in your email so we can send you a list of all your previous usernames.") #render page with info
    elif request.method == "POST": #user submits form
        email = request.form['email'] #get email
        usernames = [] #empty list for usernames
        users = User.query.filter_by(email=email).all() #get usernames linked to email
        for user in users: #for every user found
            usernames.append(user.username) #add username to list
        msg = Message('Event Management Account Usernames associated with ' + str(email), sender = 'eventmanagementproj@gmail.com', recipients = [email]) #prepare message to be sent to user
        msg.html = '<h1 style="text-align: center;">Hey ' + str(email) + "!</h1></br>" + "<h2 style='text-align: center;'>We have received your application to get your usernames.</h2></br>" + '<h3 style="text-align: center;">Here is a list of your usernames:</h3></br><h3 style="text-align: center;">' + "</br>".join(usernames) + "</h3>" + '</br><h4 style="text-align: center;">If you have any queries you may send an email to us at eventmanagementproj@gmail.com!</h4>' #code for body of email
        mail.send(msg) #send message to user
        return redirect(url_for("home", success="We have sent an email with a list of your usernames.")) #return with success message

#logs user out of account
@app.route('/logout', methods=["GET"]) #URL for logout
def logout(): #logout function
    username = getUsername() #get username
    if username != None: #user logged in
        session.pop('username', None) #remove user session
        return redirect(url_for("home", success="You have logged out successfully.")) #redirect to home page with message
    else: #user not even logged in
        return redirect(url_for("home", success="You have logged out successfully, even though you weren't logged in in the first place.")) #redirect to home page with message

#signup page for new users
@app.route('/signup', methods=["GET","POST"]) #URL for signups
def signup(): #signup function
    if request.method  == "GET": #if page is loaded bu user
        username = getUsername() #get username
        if username != None: #user logged in
            return render_template("signup.html", username=username, info = "You can sign up for another account here! You will still be logged into your first account. Note that you need a valid email to create your account.")
        else: #user not logged in
            return render_template("signup.html", username=username, info = "You can sign up for an account here! Note that you need a valid email to create your account.")
    elif request.method == "POST": #user submits form
        username = request.form["username"] #username field
        password = request.form["password"] #password field
        confirm = request.form["confirm"] #password confirmation field
        email = request.form["email"] #user email
        if password != "": #if user keyed in a password
            if password == confirm: #if both password fields match
                hashedPassword = getHashed(password) #get hashed version
                user = User(username=username,password=hashedPassword,email=email,confirmed="N") #create new user entry
                check = User.query.filter_by(username=username).first() #check if username is taken
                if check is None: #username is not taken
                    db.session.add(user) #add new user
                    db.session.commit() #save changes
                    msg = Message('Event Management Account Details for ' + str(username), sender = 'eventmanagementproj@gmail.com', recipients = [email]) #prepare message to be sent to user
                    msg.html = '<h1 style="text-align: center;">Hey ' + str(username) + "!</h1></br>" + "<h2 style='text-align: center;'>We have received your application for an account.</h2></br>" + '<h3 style="text-align: center;">Verify your account <a href=' + "https://eventmanagement.pythonanywhere.com/confirmation/" + getHashed(username) + ">here</a>!</h3>" + '</br><h4 style="text-align: center;">If you have any queries you may send an email to us at eventmanagementproj@gmail.com!</h4>' #code for body of email
                    mail.send(msg) #send message to user
                    return redirect(url_for("home", success="You have signed up for an account! Please check your email for a confirmation email."))
                else: #username not available
                    username = getUsername() #get username
                    return render_template("signup.html", error = "Username already exists. Please pick another username.", username=username) #return to same page with error message
            else: #passwords do not match
                username = getUsername() #get username
                return render_template("signup.html", error = "Your passwords do not match.", username=username) #return to same page with error message
        else: #no password entered
            username = getUsername() #get username
            return render_template("signup.html", error = "You need to enter a password.", username=username) #return to same page with error message

#confirmation for accounts so they can be used
@app.route("/confirmation/<userHash>", methods=["GET","POST"]) #URL for confirmation given in email
def confirmation(userHash): #confirmation function
    if request.method == "GET": #user loads page
        return render_template("confirmation.html", info = "Please enter your username and password to confirm your account.") #load confirmation page
    elif request.method == "POST": #user submits form
        username = request.form["username"] #get username
        password = request.form["password"] #get password
        if getHashed(username) == userHash: #if confirmation link matches with username provided
            hashedPassword = getHashed(password) #get hashed version
            user = User.query.filter_by(username=username).first() #get account with username
            if user is None: #account doesn't exist
                return render_template("confirmation.html", error = "Invalid username or password.") #return with error
            elif hashedPassword != user.password: #wrong password
                return render_template("confirmation.html", error = "Invalid username or password.") #return with error
            elif user.confirmed == "Y": #account already confirmed
                return redirect(url_for("home", success="Your account has been confirmed, though not the first time. Please proceed to login now.")) #go to homepage with message
            else: #account not confirmed and everything correct
                user.confirmed = "Y" #change status to confirmed
                db.session.commit() #save changes
                return redirect(url_for("home", success="Your account has been confirmed! Please proceed to login now.")) #go to homepage with message
        else: #username doesn't match
            return render_template("confirmation.html", error = "Invalid username.") #return with error

#timeline page, just for fun, and users to read
@app.route('/timeline', methods=["GET"]) #URL for timeline page
def timeline(): #timeline function
    username = getUsername() #get username
    return render_template("timeline.html",username=username, info="Read about the development of this website here.") #load timeline with information

#contact page for users to message us
@app.route('/contact', methods=["GET", "POST"]) #URL for contact page
def contact(): #contact function
    if request.method == "GET": #user loads the page
        username = getUsername() #get username
        return render_template("contact.html", username=username, info="Contact the developers through this webpage. You do not have to give your real name.") #load contact page with info
    elif request.method == "POST": #user sends query
        username = request.form["username"] #get username/name
        email = request.form["email"] #get email
        query = request.form["query"] #get query
        msg = Message('Query from ' + str(username), sender = 'eventmanagementproj@gmail.com', recipients = ['eventmanagementproj@gmail.com']) #prepare email
        msg.body = "Reply to: " + str(email) + "\n\n" + str(query) #email to our email so we can read it
        mail.send(msg) #send query
        return redirect(url_for("home", success="Your query has been sent.")) #return to home with notification

#features page which allows user to understand features of website
@app.route("/features", methods = ["GET"]) #URL to view features
def features(): #function to view features
    username = getUsername() #get username
    return render_template("features.html", username=username, info="You can understand the features of this website here! Scroll down for more information!") #render page

#events page which branches out into event creation, event management, and event finding
@app.route("/events", methods=["GET"]) #URL for events page
def events(): #events function
    username = getUsername() #get username
    return render_template("events.html", username=username, success=request.args.get("success"), info="You can create new events or access and manage previous events from here and discover events. You need to be logged in to create and manage events.")

#event creation page where users can make new events
@app.route("/events/create_event", methods=["GET", "POST"]) #URL for event creation
def createEvent(): #function to create event
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        if username != None: #user logged in
            return render_template("create_event.html", username=username, info="Create a new event here.") #render page with information
        else: #not logged in
            return render_template("create_event.html", username=username, error="You aren't logged in. Any events you try to create will not be saved.") #render page with error message
    elif request.method == "POST": #user submits form
        name = request.form['name'] #get name of event
        username = getUsername() #get username
        description = request.form['description'] #get event description
        event = Event(name=name,user=username,description=description) #prepare event
        check = Event.query.filter_by(name=name).first() #check if event with similar name exists
        if check is None: #no event with same name
            if username != None:
                db.session.add(event) #add event
                db.session.commit() #save changes
                return redirect(url_for("events", success="Event successfully created! It can be found under find events.")) #return to events page with message
            else: #user not logged in
                return render_template("create_event.html", username=username, error="I told you that it would not work.") #render page with error message
        else: #name already used
            return render_template("create_event.html", error="Invalid name.", username=username) #return and get user to use another name

#allows user to see all their events
@app.route("/events/manage_events", methods=["GET", "POST"]) #URL to see all events
def manageEvents(): #function to see all events
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        success = request.args.get("success") #success message if redirected from another page
        error = request.args.get("error") #error message if redirected from another page
        if success is None: #not redirected
            events = Event.query.filter_by(user=username).all() #get all events belonging to user
            if username is None: #user not signed in
                return render_template("manage_events.html", error=error, success="Found all events. However, you aren't logged in, so there isn't anything.", username=username, events=events, info="View all your events here.") #return page and message
            elif events is None: #no events
                return render_template("manage_events.html", error=error, success="You have not created any events yet, so we can't show anything. Head over to the create events page to create a new one!", info="View all your events here.") #return page and message
            else: #signed in and has events
                return render_template("manage_events.html", error=error, success="Found all of your events!", username=username, events=events, info="View all your events here.") #return page and message
        else: #redirected
            events = Event.query.filter_by(user=username).all() #get all events belonging to user
            return render_template("manage_events.html", error=error, success=success, username=username, events=events, info="View all your events here.") #return page and message

#event searching which works even if user is not signed in
@app.route("/events/find_events", methods=["GET", "POST"]) #URL to search for events
def findEvents(): #function to find events
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        events = Event.query.all() #lists all events
        success = request.args.get("success") #success message if redirected from another page
        error = request.args.get("error") #error message if redirected from another page
        if success != None:
            return render_template("find_events.html", username=username, events=events, success=success, error=error, info="Find events here.") #render page
        else:
            return render_template("find_events.html", username=username, events=events, success="Found all events!", error=error, info="Find events here.") #render page
    elif request.method == "POST": #user submits form to change search scope
        username = getUsername() #get username
        search = request.form["search"] #search query
        searchType = request.form["type"] #search type
        if searchType == "user": #search for user
            events = Event.query.filter_by(user=search).all() #get events
        elif searchType == "id": #search for ID
            events = Event.query.filter_by(id=search).all() #get events
        elif searchType == "name": #search by name
            events = Event.query.filter_by(name=search).all() #get events #Please fix the in statement so it works if "He" in "Hello"
        elif searchType == "description": #search by description
            events = Event.query.filter_by(description=search).all() #get events #Please fix the in statement so it works if "He" in "Hello"
        return render_template("find_events.html", username=username, events=events, info="Find events here.", success="Search sucessful!") #return with results

#allows user to edit details for a specific event
@app.route("/events/edit/<id>", methods=["GET", "POST"]) #URL for event editing
def editEvent(id): #function to edit event
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        event = Event.query.filter_by(id=id).first() #get event based on variable in URL
        if event != None: #event exists
            if username == event.user: #if user is the creator of the event
                return render_template("edit_event.html", username=username, event=event, info="Edit details for this event here.") #load page
            else: #user did not create this event
                event = Event(id=id,name="HEY!",user="Somebody Else",description="This isn't your event, so don't touch it.") #Troll event
                return render_template("edit_event.html", username=username, event=event, info="This form is useless since the event doesn't belong to you.") #load page
        else: #no such event
            event = Event(id=id,name="HEY!",user="To be discovered",description="This event doesn't even exist yet. Or it has been deleted.") #Troll event
            return render_template("edit_event.html", username=username, event=event, info="This form is useless since the event doesn't exist.") #load page
    elif request.method == "POST": #user sends form over
        name = request.form["name"] #new name
        description = request.form["description"] #new description
        password = request.form["password"] #to delete event
        event = Event.query.filter_by(id=id).first() #get event based on id passed in
        username = getUsername() #get username
        if event != None: #event exists
            if event.user == username: #user is creator of event
                if name != "": #user wants to change name
                    checkEvent = Event.query.filter_by(name=name).first() #check if name is used
                    if checkEvent is None: #name not used
                        forms = Form.query.filter_by(event=event.name).all() #get all forms
                        for form in forms: #loop over forms
                            form.event = name #change event name linked to form
                        event.name = name #change name
                if description != "": #user wants to change description
                    event.description = description #change description
                if password != "": #user wants to delete event
                    hashedPassword = getHashed(password) #get hashed version
                    user = User.query.filter_by(username=username).first() #get user account based on session
                    if user.password == hashedPassword: #correctpassword
                        db.session.delete(event) #delete event
                db.session.commit() #save changes
                return redirect(url_for('manageEvents', success="Event successfully edited.")) #return to manage events with success message
            else: #not authorised
                return redirect(url_for('manageEvents', error="You aren't authorised to edit this event")) #return to manage events with error message
        else: #no such event
            return redirect(url_for('manageEvents', error="No such event.")) #return to manage events with error message

#lets users see the form menu for an event
@app.route("/events/forms/<id>", methods=["GET", "POST"]) #URL forr forms menu for a event
def forms(id): #function to open form menu for event
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        event = Event.query.filter_by(id=id).first() #find event
        if event != None: #event exists
            if username == event.user: #user authorised
                return render_template("forms.html", username=username, event=event, info="Create or manage forms for this event here.", success="Found your event!") #render page
            else: #user not authorised
                event = Event(id=id,name="HEY!",user="Somebody Else",description="This isn't your event, so don't touch it.") #Troll event
                return render_template("forms.html", username=username, event=event, info="Create or manage forms for this event here, but nothing will happen since it isn't yours", success="Found a event!") #render page
        else: #no such event
            event = Event(id=id,name="HEY!",user="To be discovered",description="This event doesn't even exist yet. Or it has been deleted.") #Troll event
            return render_template("forms.html", username=username, event=event, info="Create or manage forms for this event here, but we can't do anything since the event doesn't exist.", success="Found a event!") #render page

#allows users to create a new form
@app.route("/events/forms/create_form/<id>", methods=["GET", "POST"]) #URL to create a new form
def createForm(id): #function to create a form
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        return render_template("create_form.html", username=username, info="Create a new form here.") #load page
    elif request.method == "POST": #user submitted form
        name = request.form['name'] #name of form
        username = getUsername() #get username
        description = request.form['description'] #description of form
        event = Event.query.filter_by(id=id).first() #get event
        if event != None: #if event exists
            if event.user == username: #if user is authorised
                check = Form.query.filter_by(name=name).first() #check if name is used
                if check is None: #name not used
                    lastForm = Form.query.order_by(Form.id.desc()).first() #get last form
                    form = Form(name=name,user=username,event=event.name,description=description,questions="[]",answers="/home/EventManagement/mysite/csv/" + str(lastForm.id+1) +".csv") #prepare form
                    db.session.add(form) #add form
                    db.session.commit() #save changes
                    return redirect(url_for("manageEvents", success="Form successfully created!"))
                else: #name is used
                    return render_template("create_form.html", username=username, error="Invalid name.", info="Create a new form here.") #get user to change the name
            return render_template("create_form.html", username=username, error="You aren't authorised to create a form for this event.", info="Create a new form here.") #return and tell user error message
        return render_template("create_form.html", username=username, error="Event does't even exist.", info="Create a new form here.") #return and tell user error message

#allows users to see a forms and manage each one of them
@app.route("/events/forms/manage_forms/<id>", methods=["GET", "POST"]) #URL to manage all forms
def manageForms(id): #function to see all forms
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        event = Event.query.filter_by(id=id).first() #get event
        forms = Form.query.filter_by(event=event.name).all() #get all forms
        if event != None: #event exists
            if username == event.user: #user is authorised
                return render_template("manage_forms.html", username=username, forms=forms, success="Found all your forms!", info="Manage all your forms here.") #render page with success message
            else: #not authorised
                forms = [Form(id=id,name="HEY!",user="Somebody Else",event="Unknown",description="This isn't your event, so don't touch it.",questions=[],answers="")] #troll form
                return render_template("manage_forms.html", username=username, forms=forms, success="Found a form!", info="Manage all your forms here.") #render troll page
        else: #no such event
            forms = [Form(id=id,name="HEY!",user="To be discovered",event="Unknown", description="The event doesn't even exist yet. Or it has been deleted.",questions=[],answers="")] #troll form
            return render_template("manage_forms.html", username=username, forms=forms, success="Found a form!", info="Manage all your forms here.") #render troll page

#lets users edit form details
@app.route("/events/forms/edit/<id>", methods=["GET", "POST"]) #URL to edit forms
def editForm(id): #function to edit form
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        form = Form.query.filter_by(id=id).first() #get form
        if form != None: #if form exists
            if username == form.user: #user authorised
                return render_template("forms_edit.html", username=username, form=form, success="Found your form.", info="Edit your form here!") #render page with information
            else: #user not authorised
                form = Form(id=id,name="HEY!",user="Somebody Else",event="Unknown",description="This isn't your form, so don't touch it.",questions=[],answers="") #troll form
                return render_template("forms_edit.html", username=username, form=form, success="Found a form.", info="Edit your form here. There won't be any changes because you aren't authorised.") #load troll page
        else: #no such form
            form = Form(id=id,name="HEY!",user="To be discovered",event="Unknown",description="The form doesn't even exist yet. Or it has been deleted.",questions=[],answers="") #troll form
            return render_template("forms_edit.html", username=username, form=form, success="Found a form.", info="Edit your form here. But nothing will happen since the form doesn't exist.") #load troll page
    elif request.method == "POST": #user submits form
        name = request.form["name"] #get new name
        description = request.form["description"] #get new description
        password = request.form["password"] #get password
        form = Form.query.filter_by(id=id).first()
        username = getUsername() #get username
        if form != None: #form exists
            if form.user == username: #user authorised
                if name != "": #user wants to change name
                    checkForm = Form.query.filter_by(name=name).first() #check if name is used
                    if checkForm is None: #name is open
                        form.name = name #change name
                if description != "": #user wants to change description
                    form.description = description #change description
                if password != "": #user wants to delete form
                    hashedPassword = getHashed(password) #get hashed version
                    user = User.query.filter_by(username=username).first() #check user account
                    if user.password == hashedPassword: #password is correct
                        db.session.delete(form) #delete form
                db.session.commit() #save changes
                return redirect(url_for('manageEvents', success="Form successfully edited.")) #return with success message
            else: #user not authorised
                return redirect(url_for('manageEvents', error="You aren't authorised to edit this form.")) #return with error message
        else: #no such form
            return redirect(url_for('manageEvents', error="The form doesn't exist.")) #return with error message

#function to allow people to edit form questions
@app.route("/events/forms/questions/<id>", methods=["GET", "POST"]) #URL to edit form questions
def editFormsQuestions(id): #function to edit form questions
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        form = Form.query.filter_by(id=id).first() #get form
        if form != None: #form exists
            if username == form.user: #user is authorised
                questions = ast.literal_eval(form.questions) #get questions
                return render_template("forms_questions.html", username=username, form=form, questions=questions, info="You can edit and add questions to your form here.") #render page with info
            else: #user not authorised
                form = Form(id=id,name="HEY!",user="Somebody Else",event="Unknown",description="This isn't your form, so don't touch it.",questions=[[1,"Are you dumb?","This is not a test.","radio",["YES","NO"]],[2, "Should you be here?","Is this your event?","radio",["YES","NO"]]],answers="") #troll form
                questions = form.questions #get questions
                return render_template("forms_questions.html", username=username, form=form, questions=questions, info="You can edit and add questions to your form here.") #load troll page
        else: #no such form
            form = Form(id=id,name="HEY!",user="To be discovered",event="Unknown", description="The form doesn't even exist yet. Or it has been deleted.",questions=[],answers="") #troll form
            questions = form.questions #get questions
            return render_template("forms_questions.html", username=username, form=form, questions=questions, info="You can edit and add questions to your form here.") #load troll page
    elif request.method == "POST": #userr submits form
        username = getUsername() #get username
        if "addField" in request.form: #user wants to add a field
            name = request.form["name"] #get field name
            description = request.form["description"] #get field description
            type = request.form["type"] #get field type
            options = request.form["options"] #get field options (if any)
            form = Form.query.filter_by(id=id).first() #get form
            if form != None: #form exists
                if form.user == username: #user is authorised
                    questions = ast.literal_eval(form.questions) #get questions
                    try: #expect a possible error
                        lastID = questions[-1][0] #get ID of the last question
                    except: #eror in getting last ID
                        lastID = 0 #0 since there are no past questions
                    if options == "": #no options
                        questions.append([(lastID + 1),name,description,type]) #add question to question list
                    else: #options given
                        questions.append([(lastID + 1),name,description,type,ast.literal_eval(options)]) #add question to question list
                    form.questions = str(questions) #edit questions in form
                    db.session.commit() #save changes
                    row = [] #prepare blank row
                    row.append("Timestamp") #add default timestamp header
                    for i in range(len(questions)): #loop over questions
                        row.append(questions[i][1]) #add question name to row
                    with open(form.answers, 'a') as csvFile: #open CSV file
                        csvWriter = csv.writer(csvFile, lineterminator="\n") #CSV writer
                        csvWriter.writerow(row) #write row in CSV file
                        csvFile.close() #close CSV file
                    return redirect(url_for("manageEvents", success="Question successfully added."))
                else: #user not authorised
                    form = Form(id=id,name="HEY!",user="Somebody Else",event="Unknown",description="This isn't your form, so don't touch it.",questions=[[1,"Are you dumb?","This is not a test.","radio",["YES","NO"]],[2, "Should you be here?","Is this your event?","radio",["YES","NO"]]],answers="") #troll form
                    questions = form.questions #get questions
                    return render_template("forms_questions.html", username=username, form=form, questions=questions, error="You aren't allowed to edit this form.", info="You can edit and add questions to your form here.") #load troll page
            else: #no such form
                form = Form(id=id,name="HEY!",user="To be discovered",event="Unknown", description="The form doesn't even exist yet. Or it has been deleted.",questions=[],answers="") #troll form
                questions = form.questions #get questions
                return render_template("forms_questions.html", username=username, form=form, questions=questions, error="No form found.", info="You can edit and add questions to your form here.") #load troll page
        if "editField" in request.form: #user wants to edit field
            name = request.form["name"] #get field name
            newName = request.form["newName"] #get new field name
            description = request.form["description"] #get new field description
            password = request.form["password"] #get user password
            form = Form.query.filter_by(id=id).first() # get form
            if form != None: #form exists
                if form.user == username: #user authorised
                    questions = ast.literal_eval(form.questions) #get form questions
                    for i in range(len(questions)): #loop over questions
                        if questions[i][1] == name: #if question is the question to be edited
                            if newName != "": #user wants to change name
                                questions[i][1] = newName #change name
                            if description != "": #user wants to change description
                                questions[i][2] = description #change description
                            if password != None: #user wants to delete field
                                salt = "ITSASECRET" #salt for password
                                hashedPassword = password + salt #salt password
                                hashedPassword  = hashlib.md5(hashedPassword .encode()) #encrypt password with md5 hash
                                hashedPassword  = hashedPassword.hexdigest() #convert to string
                                user = User.query.filter_by(username=username).first() #get user
                                if user.password == hashedPassword : #user password is correct
                                    questions.pop(i) #remove question
                                    try: #expect a possible error
                                        for j in range(len(questions)): #loop over questions
                                            questions[j+i][0] -= 1 #change IDs of questions after that
                                    except IndexError: #out of list
                                        break #get out of loop
                    form.questions = str(questions) #change questions
                    db.session.commit() #save changes
                    row = [] #prepare blank row
                    row.append("Timestamp") #add timestamp field
                    for i in range(len(questions)): #loop over questions
                        row.append(questions[i][1]) #add question name to row
                    with open(form.answers, 'a') as csvFile: #open CSV file
                        csvWriter = csv.writer(csvFile, lineterminator="\n") #prepare CSV writer
                        csvWriter.writerow(row) #write out CSV row
                        csvFile.close() #close CSV file
                    return redirect(url_for("manageEvents", success="Question successfully edited.")) #return with success message
                else: #user not authorised
                    form = Form(id=id,name="HEY!",user="Somebody Else",event="Unknown",description="This isn't your form, so don't touch it.",questions=[[1,"Are you dumb?","This is not a test.","radio",["YES","NO"]],[2, "Should you be here?","Is this your event?","radio",["YES","NO"]]],answers="") #troll form
                    questions = form.questions #get questions
                    return render_template("forms_questions.html", username=username, form=form, questions=questions, error="You aren't allowed to edit this form.", info="You can edit and add questions to your form here.") #load troll page
            else: #no such form
                form = Form(id=id,name="HEY!",user="To be discovered",event="Unknown", description="The form doesn't even exist yet. Or it has been deleted.",questions=[],answers="") #troll form
                questions = form.questions #get questions
                return render_template("forms_questions.html", username=username, form=form, questions=questions, error="No form found.", info="You can edit and add questions to your form here.") #load troll page

#allows users to view answers to their forms
@app.route("/events/forms/answers/<id>", methods=["GET"]) #URL to view form answers
def formsAnswers(id): #function to display answers
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        form = Form.query.filter_by(id=id).first() #get form
        if form != None: #form exists
            if username == form.user: #user is authorised
                with open(form.answers, 'r') as csvFile: #open csv file
                        csvReader = csv.reader(csvFile, lineterminator="\n") #read in csv file
                        csvData = list(csvReader) #create a list from data
                        csvFile.close() #close csv file
                answers = csvData #get csv data
                return render_template("forms_answers.html", username=username, answers=answers, id=id, success="Got your form data.", info="View your form data here.") #return with data
            else: #user not authorised
                answers = [["Timestamp","Are you dumb?","Should you be here?"],["A few years ago.","Yes you are.","Obviously not."]] #troll answers
                return render_template("forms_answers.html", username=username, answers=answers, id=id, success="Got a form's data.", info="View your form data here. It's pointless as you aren't authorised to see the data.") #return troll page
        else: #no such form
            answers = [["Timestamp","Are you dumb?","Should you be here?"],["A few years ago.","Yes you are.","Obviously not."]] #troll answers
            return render_template("forms_answers.html", username=username, answers=answers, id=id, success="Got a form's data.", info="View your form data here. There's no data as there isn't a form in the first place.") #return troll page

#allows users to download answers to their forms
@app.route("/events/forms/answers/download/<id>", methods=["GET"]) #URL to download answer data
def formsAnswersDownload(id): #function to download form answer data
    if request.method == "GET": #user accesses the download page
        username = getUsername() #get username
        form = Form.query.filter_by(id=id).first() #get form
        if form != None: #if form exists
            if username == form.user: #user is authorised
                with open(form.answers, 'r') as csvFile: #open csv file
                        csvReader = csv.reader(csvFile, lineterminator="\n") #read csv file
                        csvData = list(csvReader) #convert data to a list
                        csvFile.close() #close csv file
                answers = [] #empty list for converted data
                answersF = "" #empty string for converted data
                for i in range(len(csvData)): #loop over each row in csv data
                    answers.append(",".join(csvData[i])) #put each row in a list element
                answersF = "\n".join(answers) #compact all rows into one string
                response = make_response(answersF) #make response with final data
                response.headers['Content-Disposition'] = "attachment; filename=" + str(form.name) + ".csv" #download csv file
                response.mimetype='text/csv' #type of download
                return response #return download
            else: #user not authorised
                csvData = [["Timestamp","Are you dumb?","Should you be here?"],["A few years ago.","Yes you are.","Obviously not."]] #troll data
                answers = [] #empty list for converted data
                answersF = "" #empty string for converted data
                for i in range(len(csvData)): #loop over each row in csv data
                    answers.append(",".join(csvData[i])) #put each row in a list element
                answersF = "\n".join(answers) #compact all rows into one string
                response = make_response(answersF) #make response with final data
                response.headers['Content-Disposition'] = "attachment; filename=Data.csv" #download csv file
                response.mimetype='text/csv' #type of download
                return response #return troll download
        else: #no such form
            csvData = [["Are you dumb?","Should you be here?"],["Yes you are.","Obviously not."]] #troll data
            answers = [] #empty list for converted data
            answersF = "" #empty string for converted data
            for i in range(len(csvData)): #loop over each row in csv data
                answers.append(",".join(csvData[i])) #put each row in a list element
            answersF = "\n".join(answers) #compact all rows into one string
            response = make_response(answersF) #make response with final data
            response.headers['Content-Disposition'] = "attachment; filename=Data.csv" #download csv file
            response.mimetype='text/csv' #type of download
            return response #return troll download

#allows users to view details for an event
@app.route("/events/view/<id>", methods=["GET"]) #URL to view an event
def viewEvent(id): #function to view an event
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        event = Event.query.filter_by(id=id).first() #get event
        if event != None: #event exists
            return render_template("view_event.html", username=username, event=event, success="Found the event.", info="View details for an event here.") #render page with message
        else: #no such event
            return render_template("view_event.html", username=username, event=event, info="View details for an event here. But there's nothing as the event doesn't exist.") #render page with message

#allows user to view forms linked to an event
@app.route("/events/view/forms/<id>", methods=["GET"]) #URL to view all forms
def viewForms(id): #function to show all forms
    if request.method == "GET": #user accesses page
        username = getUsername() #get username
        event = Event.query.filter_by(id=id).first() #get event
        forms = Form.query.filter_by(event=event.name).all() #get all forms linked to event
        if forms != None: #has forms linked to event
            return render_template("view_forms.html", username=username, forms=forms, success="Found all forms.", info="View all forms for an event here.") #render page with message
        else: #if no forms linked to event
            return render_template("view_forms.html", info="View all forms for an event here. This event does not contain any forms, so there isn't anything.") #render page with message

#allows user to fill in a form
@app.route("/events/view/forms/fill_form/<id>", methods=["GET","POST"]) #URL to fill in a form
def fillForm(id): #function to fill in a form
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        form = Form.query.filter_by(id=id).first() #get form
        if form != None: #formm exists
            questions = ast.literal_eval(form.questions) #parse form questions
            return render_template("fill_form.html", username=username, form=form, questions=questions, success="Got form data.", info="Fill in a form here.") #render page with questions and messages
        else: #no such form
            form = Form(id=id,name="HEY!",user="To be discovered",event="Unknown", description="The event doesn't even exist yet. Or it has been deleted.",questions=[],answers="")
            questions = form.questions #load troll questions
            return render_template("fill_form.html", username=username, form=form, questions=questions, info="Fill in a form here. There aren't any questions because there isn't a form") #render page with messages
    elif request.method == "POST": #user submits form
        form = Form.query.filter_by(id=id).first() #get form
        if form != None: #form exists
            questions = ast.literal_eval(form.questions) #parse questions
            if questions != []: #form has questions
                row = [] #create blank CSV row
                date = datetime.datetime.now() #get current date and time
                date = date.strftime('%Y-%m-%d %H:%M:%S') #format date and time so there are no miliseconds
                row.append(date) #push date into CSV row
                for i in range(len(questions)): #loop over questions in form
                    row.append(request.form["q"+str(i+1)]) #get value of appropriate field
                with open(form.answers, 'a') as csvFile: #open CSV data file
                    csvWriter = csv.writer(csvFile, lineterminator="\n") #create CSV writer
                    csvWriter.writerow(row) #write out CSV row
                    csvFile.close() #close CSV file
                return redirect(url_for("findEvents", success="Your response has been recorded.")) #return to find events page
            else: #form doesn't have questions
                return redirect(url_for("findEvents", error="Form doesn't have any questions.")) #return to find events page with message
        else: #form doesn't exist
            return redirect(url_for("findEvents", error="Form doesn't exist.")) #return to find events page with message

#page to direct people to manage their account
@app.route("/account", methods=["GET", "POST"]) #URL to allow user to edit account details
def account(): #function to edit account details
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        return render_template("account.html", username=username, success=request.args.get("success"), info="You can edit your account details here.") #render page with info

#allows users to change their username
@app.route("/account/change_username", methods=["GET", "POST"]) #URL to allow user to change username
def changeUsername(): #function to change username
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        return render_template("change_username.html", username=username, info="You can change your username here.") #render page with info
    elif request.method == "POST": #user submits form
        username = getUsername() #get username
        oldUsername = request.form['oldname'] #get old username
        newUsername = request.form['newname'] #get new username
        user = User.query.filter_by(username=username).first() #get user details
        if username == None: #if not logged in
            return render_template("change_username.html", username=username, error="You are not logged in.", info="You can change your username here.") #render page with messages
        else: #user is logged in
            if username != oldUsername: #username doesn't match
                return render_template("change_username.html", username=username, error="Your username does not match with your old username.", info="You can change your username here.") #render page with messages
            else: #username matches
                check = User.query.filter_by(username=newUsername).first() #get user details
                if check != None: #new username already exists
                    return render_template("change_username.html", username=username, error="The new username is already in use.", info="You can change your username here.") #render page with messages
                else: #username is available and user is logged in
                    user.username = newUsername #change username
                    db.session.commit() #save changes
                    session.pop('username', None) #remove user session
                    session["username"] = username #set username session
                    return redirect(url_for("account", success="Your username has been successfully changed.")) #return with success message

#allows users to change their email
@app.route("/account/change_email", methods=["GET", "POST"]) #URL to allow user to change email
def changeEmail(): #function to change email
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        return render_template("change_email.html", username=username, info="You can change your email here.") #render page with info
    elif request.method == "POST": #user submits form
        username = getUsername() #get username
        oldEmail = request.form['oldemail'] #get old email
        newEmail = request.form['newemail'] #get new email
        user = User.query.filter_by(username=username).first() #get user details
        if username == None: #if not logged in
            return render_template("change_email.html", username=username, error="You are not logged in.", info="You can change your email here.") #render page with messages
        else: #user is logged in
            if user.email != oldEmail: #email doesn't match
                return render_template("change_email.html", username=username, error="Your email does not match with your old email.", info="You can change your email here.") #render page with messagess
            else: #user is logged in
                user.email = newEmail #change email
                db.session.commit() #save changes
                return redirect(url_for("account", success="Your email has been successfully changed.")) #return with success message

#allows users to change their passwords
@app.route("/account/change_password", methods=["GET", "POST"]) #URL to allow user to change password
def changePassword(): #function to change password
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        return render_template("change_password.html", username=username, info="You can change your password here.") #render page with info here
    elif request.method == "POST": #user changes password
        username = getUsername() #get username
        oldpass = request.form["oldpass"] #old password
        newpass = request.form["newpass"] #new password
        confirmpass = request.form["confirmpass"] #confirmation password
        user = User.query.filter_by(username=username).first() #get user
        hashedPassword = getHashed(oldpass) #get hashed version
        if username != None: #user is logged in
            if hashedPassword != user.password: #wrong password
                return render_template("change_password.html", username=username, error="The old password is incorrect.", info = "You can change your password here.") #return with error message
            elif newpass != confirmpass: #passwords dont match
                return render_template("change_password.html", username=username, error="The new password and confirmation password do not match.", info = "You can change your password here.") #return with error message
            else: #passwords match
                hashedPassword = getHashed(newpass) #get hashed version
                user.password = hashedPassword
                db.session.commit() #save changes
                return redirect(url_for("account", success="Password successfully changed!")) #return with success message
        else: #not logged in
            return render_template("change_password.html", username=username, error="You are not logged in.", info = "You can change your password here.") #return with error message

#allows users to delete (unconfirm their account)
@app.route("/account/delete_account", methods=["GET", "POST"]) #URL to allow user to delete their account
def deleteAccount(): #function to delete account
    if request.method == "GET": #user loads page
        username = getUsername() #get username
        return render_template("delete_account.html", username=username, info="You can delete your account here.") #render page with info here
    elif request.method == "POST": #user changes password
        username = getUsername() #get username
        password = request.form["password"] # password
        confirmpass = request.form["confirmPassword"] #confirmation password
        user = User.query.filter_by(username=username).first() #get user
        hashedPassword = getHashed(password) #get hashed version
        if username != None: #user is logged in
            if hashedPassword != user.password: #wrong password
                return render_template("delete_account.html", username=username, error="The password is incorrect.", info = "You can change your password here.") #return with error message
            elif password != confirmpass: #passwords dont match
                return render_template("delete_account.html", username=username, error="The password and confirmation password do not match.", info = "You can change your password here.") #return with error message
            else: #passwords match
                user.confirmed = "N" #change account status
                email = user.email #get user's email
                msg = Message('Event Management Account Details for ' + str(username), sender = 'eventmanagementproj@gmail.com', recipients = [email]) #prepare message to be sent to user
                msg.html = '<h1 style="text-align: center;">Hey ' + str(username) + "!</h1></br>" + "<h2 style='text-align: center;'>We have received your request to delete your account.</h2></br>" + '<h3 style="text-align: center;">Re-verify your account <a href=' + "https://eventmanagement.pythonanywhere.com/confirmation/" + getHashed(username) + ">here</a>!</h3>" + '</br><h4 style="text-align: center;">If you have any queries you may send an email to us at eventmanagementproj@gmail.com!</h4>' #code for body of email
                mail.send(msg) #send message to user
                db.session.commit() #save changes
                session.pop('username', None) #remove user session
                return redirect(url_for("home", success="Account successfully deleted! You can restore your account by re-confirming your account again.")) #return with success message
        else: #not logged in
            return render_template("delete_account.html", username=username, error="You are not logged in.", info = "You can change your password here.") #return with error message