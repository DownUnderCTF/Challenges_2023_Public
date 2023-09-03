FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    python3 \
    python3-pip \
    less \
&& rm -rf /var/lib/apt/lists/*

COPY ./flag.txt ./helpless.py /home/ductf/
RUN chmod +x /home/ductf/helpless.py
RUN useradd -ms /home/ductf/helpless.py ductf
RUN echo "ductf:ductf" | chpasswd

RUN mkdir /var/run/sshd /run/sshd
RUN sed -i 's/#PasswordAuthentication/PasswordAuthentication/g' /etc/ssh/sshd_config
RUN sed -i 's/#Port 22/Port 1337/g' /etc/ssh/sshd_config
RUN chmod -x /etc/update-motd.d/*

EXPOSE 1337
CMD ["/usr/sbin/sshd", "-D", "-e"]