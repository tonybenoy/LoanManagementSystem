# this is an official Python runtime, used as the parent image
FROM python:3.7.3-slim

# set the working directory in the container to /app
WORKDIR /app

# add the current directory to the container as /app
ADD . /app
RUN pip install --trusted-host pypi.python.org -r requirements.txt

EXPOSE 5000

# execute the Flask app
CMD ["flask", "run","--host=0.0.0.0"]
