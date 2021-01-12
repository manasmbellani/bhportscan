FROM kalilinux/kali-rolling
LABEL maintainer="manasbellani"

RUN apt-get -y update

RUN apt-get -y install \
    bash \
    python3 \
    python3-pip \
    sed \
    jq \
    grep \
    curl \
    golang \
    nmap \
    wget

# Install python3 dependencies
RUN python3 -m pip install yq

# Install anew
RUN go get -u github.com/tomnomnom/anew

# Install gargs
RUN wget "https://github.com/brentp/gargs/releases/download/v0.3.9/gargs_linux" -O "/usr/bin/gargs" && \
    chmod +x "/usr/bin/gargs"

# Install GoBin path $PATH
ENV GOBIN=/root/go/bin PATH=/root/go/bin:$PATH


COPY . /app
WORKDIR /app

ENTRYPOINT [ "/bin/bash" ]
