## Image Golang pour les modules du code
FROM golang:1.18.1-bullseye as go-build
       
# Install packages
RUN go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/tomnomnom/waybackurls@latest\
    && go install github.com/tomnomnom/qsreplace@latest\
    && go install github.com/takshal/freq@latest\
    && cp $GOPATH/bin/* /usr/local/bin/
 

## Image python pour les script de la toolbox
FROM python:3.10-slim-bullseye

# Variables d'environements python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Installation des paquets nécessaire au fonctionnement de la toolbox
RUN apt update \
    && apt -y install software-properties-common libpq5 libc6 python3-dev musl-dev git\
    netcat-traditional golang nmap openvpn freerdp2-x11 tigervnc-viewer apt-utils ca-certificates vim build-essential\
    && rm -rf /var/lib/apt/lists/*

# Repertoire de travail
WORKDIR /usr/src/projet/

# Installation des dépendences python
RUN pip install --upgrade pip
COPY ./requirements.txt .
RUN pip install -r requirements.txt

# Copie du entrypoint.sh
COPY ./entrypoint.sh .
RUN sed -i 's/\r$//g' /usr/src/projet/entrypoint.sh
RUN chmod +x /usr/src/projet/entrypoint.sh

# Copie du projet
COPY . .
COPY --from=go-build /usr/local/bin/gau /usr/local/bin/ /usr/local/bin/waybackurls /usr/local/bin/qsreplace /usr/local/bin/freq\
 /usr/src/projet/toolbox/scripts/webapp/

# Exécution du entrypoint.sh
RUN chmod +x /usr/src/projet/entrypoint.sh
ENTRYPOINT ["/usr/src/projet/entrypoint.sh"]
