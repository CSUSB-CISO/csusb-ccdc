FROM ubuntu:latest

RUN apt update 
RUN apt install nftables iproute2 vim python3 pip -y
RUN apt upgrade -y
RUN mkdir KeyboardKowboys
# RUN mkdir KeyboardKowboys/Rules
COPY . /KeyboardKowboys
# RUN mv nftables.conf /KeyboardKowboys/Rules
# RUN mv freshnftables.conf /KeyboardKowboys/Rules
WORKDIR /KeyboardKowboys
# WORKDIR /KeyboardKowboys/Rules
RUN pip install -r requirements.txt
RUN chmod +x start.sh
ENTRYPOINT [ "./start.sh"]