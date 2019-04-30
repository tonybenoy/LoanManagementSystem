## The app
As per the requiremts the web app is built using flask.
ORM used to define the models is SQLAlchemy.
Database used is postgresql.
Marshmallow is used to serialize the models for API.
Authentication for the API endpoint is done using JWT.
The passwords are hashed using pbkdf2:sha256 and with a salt of lenght 8.
Flask_tests is used for unit testing the flask application.
In the webapp timezones are managed by moment library through flask-moments .
The the api the timezone is passed in the header. If it is not passed then it defaults to India.
An alternative to this approach would be to save them in the Database for each user.
docker-compose used to run the app with nginx as a reverse proxy,gunicorn as wsgi, and postgres as the datbase.
An alternatibe to this would be to take a linux base image and built all of this in a dockerfile.
flaskapp contains docker-entrypoint.sh to perform all the required migrations for the webapp to work.
docker-entrypoint-initdb.d in postgres contains a shell script to create multiple databases for both the app and the testing.


## Usage
```
$ docker-compose build
$ docker-compose up -d
$ docker-compose run web python tests.py
```
