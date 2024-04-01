FROM debian:buster-slim

# Set environment variables
ENV DEBIAN_FRONTEND noninteractive

# Update system and install some essential tools
RUN apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade && \
    apt-get install ssh python3-pip supervisor netcat-traditional nmap curl -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir /var/run/sshd
RUN echo 'root:d0n0tgu3ssM3' | chpasswd 

# Create a user and set up env for the challenge
RUN useradd -m -d /home/ctfuser ctfuser
RUN echo 'ctfuser:ctfpassword' | chpasswd
RUN chsh -s /bin/rbash ctfuser
# RUN touch /home/ctfuser/.hushlogin

# Start isolating the user env, since it's a shared account
# RUN mkdir -p /home/ctfuser/bin
# RUN ln -s /usr/bin/nmap /home/ctfuser/bin/
# RUN ln -s /usr/bin/curl /home/ctfuser/bin/
# RUN ln -s /usr/bin/nc /home/ctfuser/bin/
# RUN ln -s /usr/bin/date /home/ctfuser/bin/
# RUN ln -s /usr/bin/mkdir /home/ctfuser/bin/
# RUN ln -s /usr/bin/chmod /home/ctfuser/bin/
# RUN ln -s /usr/bin/ls /home/ctfuser/bin/
# RUN ln -s /usr/bin/cat /home/ctfuser/bin/

# Setup .bash_profile to restrict environment
# RUN echo "export PATH=/home/ctfuser/bin" |  tee /home/ctfuser/.bash_profile
RUN echo "unset HISTFILE" |  tee -a /home/ctfuser/.bash_profile


# Disable command history
RUN touch /home/ctfuser/.bash_history
RUN chmod 444 /home/ctfuser/.bash_history

# Set permissions
# RUN chown -R ctfuser:ctfuser /home/ctfuser
# RUN chmod -R 755 /home/ctfuser
# RUN chmod 700 /home/ctfuser/bin

# Ensure the user cannot modify .bash_profile or .bash_history
RUN chown root:root /home/ctfuser/.bash_history
RUN chmod 444 /home/ctfuser/.bash_history


# Set the working directory in the container
WORKDIR /usr/src/app
RUN chmod 0700 /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .
COPY README /home/ctfuser/

# Install any needed packages specified in requirements.txt
RUN pip3 install --no-cache-dir flask
# RUN service ssh start

EXPOSE 22
RUN  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
CMD /usr/bin/supervisord -c /usr/src/app/supervisord.conf