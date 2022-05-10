## How to install project
- Create an empty folder on your local machine
- Open CMD in that empty folder and create a virtual environment by running: py -3 -m venv venv
- Activate the virtual environment by running: venv\Scripts\Activate
- Run: 
    set FLASK_APP=app.py 
    set FLASK_ENV=development
- Clone the project from Github
- Change the db_config.py file to your personal MySQL information
- Download all the required dependencies by running: pip install -r requirements.txt
- Run the project: flask run 

## Project structure
The project is divided into several files:
- db_config.py: holds the personal information of each user's database
- model folder: holds a file for each database table, defines how each tables data is structured
- app.py: the main API file that holds all the functions and API request functionalities