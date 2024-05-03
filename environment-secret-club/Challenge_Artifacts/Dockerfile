FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache git

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install gunicorn flask python-dotenv Flask-SQLAlchemy flask_jwt_extended bcrypt

# Copy flag
COPY flag.txt /flag.txt

# Set up fake git
RUN mkdir /tmp/repo

WORKDIR /tmp/repo

COPY ./git .

RUN git init
RUN git config --global user.email "m4lwhere@c1.local" && git config --global user.name "m4lwhere"
RUN git add -A && git commit -m "Initial commit"

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

RUN chmod +x /app/entrypoint.sh
RUN mv /tmp/repo/.git /app/application/git

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Run supervisord
CMD ["./entrypoint.sh"]