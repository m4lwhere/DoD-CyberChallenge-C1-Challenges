FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND noninteractive

# Update system and install some essential tools
RUN apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade && \
    apt-get install ssh python3-pip supervisor netcat-traditional nmap curl ffuf wfuzz seclists nano vim gobuster -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


# Setup SSH
RUN mkdir /var/run/sshd
RUN echo 'root:d0n0tgu3ssM3' | chpasswd 

# Create a user and set up env for the challenge
RUN useradd -m -d /home/ctfuser ctfuser
RUN touch /home/ctfuser/.hushlogin
RUN echo 'ctfuser:ctfpassword' | chpasswd
RUN echo "unset HISTFILE" |  tee -a /home/ctfuser/.bashrc
RUN touch /home/ctfuser/.bash_history
RUN chown root:root /home/ctfuser/.bash_history
RUN chown root:root /home/ctfuser
RUN chmod 755 /home/ctfuser
RUN chmod 444 /home/ctfuser/.bash_history

# Add symbolic links to homedir
RUN ln -s /usr/share/seclists /home/ctfuser/seclists
RUN ln -s /usr/bin/curl /home/ctfuser/curl
RUN ln -s /usr/bin/ffuf /home/ctfuser/ffuf
RUN ln -s /usr/bin/wfuzz /home/ctfuser/wfuzz
RUN ln -s /usr/bin/gobuster /home/ctfuser/gobuster


# Install flask for services
RUN pip install --no-cache-dir flask Flask-HTTPAuth

# Copy readme into competitor's home directory
COPY README /home/ctfuser/

# Start supervisor
COPY conf/supervisord.conf /etc/supervisord.conf

# Copy services
COPY services /app/services

RUN chmod -R 0700 /app

# SSH configuration steps here (e.g., keys, security settings)
# ...

RUN service ssh start

EXPOSE 22
CMD /usr/bin/supervisord -c /etc/supervisord.conf