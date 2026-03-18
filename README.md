rcubepos

Django Admin Panel Bootstrap 4 Template
Clone the project
Create the virtual env -> python3 -m venv venv
Install the requirements.txt file ->
pip freeze > requirements.txt
pip install -r requirements.txt
Collect all the static files -> python3 manage.py collectstatic
Migrate all the basic tables -> python3 manage.py migrate
Run the server -> python3 manage.py runserver
Open any browser and visit the localhost:8000/

env activate
1.pip install virtualenv
2.python -m venv env-rcube
3.env-rcube\Scripts\activate

.gitignore
echo > .gitignore
#DEACTIVATE

1. from decouple import config
2. config("SECRET_KEY")
