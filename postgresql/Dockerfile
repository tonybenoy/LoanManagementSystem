FROM postgres:latest

#ENV POSTGRES_DB loanmanagement
ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD postgres
ENV POSTGRES_MULTIPLE_DATABASES=loanmanagement,loanmanagementtest
COPY create-multiple-postgresql-databases.sh /docker-entrypoint-initdb.d/