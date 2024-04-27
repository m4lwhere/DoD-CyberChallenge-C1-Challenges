# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

RUN chmod -R 755 /app/.git
# Install the dependencies
# Ensure pip is up to date for security fixes and improvements
RUN pip install --upgrade pip &&\
    pip install flask gunicorn python-dotenv Flask-SQLAlchemy flask_jwt_extended

RUN apt-get update && apt-get install -y nginx
RUN rm /etc/nginx/sites-enabled/default
COPY nginx.conf /etc/nginx/sites-available/
RUN ln -s /etc/nginx/sites-available/nginx.conf /etc/nginx/sites-enabled/

# Make port 5000 available to the world outside this container
EXPOSE 5001

# Define environment variable
ENV FLASK_APP=/app/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_DEBUG=1
ENV JWT_SECRET_KEY=thisISmySECRETkeyTHATnobodySTEALS
ENV FLAG=C1{oops_I_l34k3d_my_k3ys!}

# Run app.py when the container launches
CMD service nginx start && flask run --host=0.0.0.0
