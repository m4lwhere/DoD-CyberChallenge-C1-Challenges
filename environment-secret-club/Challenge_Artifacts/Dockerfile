# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install the dependencies
# Ensure pip is up to date for security fixes and improvements
RUN pip install --upgrade pip &&\
    pip install flask gunicorn python-dotenv Flask-SQLAlchemy flask_jwt_extended

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=/app/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_DEBUG=1
ENV JWT_SECRET_KEY=thisISmySECRETkeyTHATnobodySTEALS

# Run app.py when the container launches
CMD ["flask", "run", "--host=0.0.0.0"]
