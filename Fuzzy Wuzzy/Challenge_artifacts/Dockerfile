FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND noninteractive

# Update system and install some essential tools
RUN apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade && \
    apt-get install ssh python3-pip supervisor netcat-traditional nmap curl ffuf wfuzz seclists nano -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


# Setup SSH
RUN mkdir /var/run/sshd
RUN echo 'd0n0tgu3ssM3:d0n0tgu3ssM3' | chpasswd # It's better to use SSH keys in real-world scenarios

# Create a user and set up env for the challenge
RUN useradd -m -d /home/ctfuser ctfuser
RUN chsh -s /usr/bin/bash ctfuser
RUN touch /home/ctfuser/.hushlogin
RUN echo 'ctfuser:ctfpassword' | chpasswd
RUN ln -s /usr/share/seclists /home/ctfuser/seclists



# Install flask for services
RUN pip install flask Flask-HTTPAuth

# Copy readme into competitor's home directory
COPY README.md /home/ctfuser/

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